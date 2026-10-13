"""Unified private, stdlib-only Huawei health program.

Commands: sync, status, capabilities, latest, report [--limit 1..100].
Shared --state-dir/--auth-file options work before or after the command.
Only sync loads auth (via app.load_auth) or uses networking. It collects bounded
activity summaries, sleep, daily resting-HR/HRV, heart-rate and SpO2 stats.
status/sync are operational-only; latest/report disclose normalized saved
summaries with source freshness and stale-auth markers, not medical analysis.

The official auth coordinator is invoked before collection and once after a
rejected token. Only server-verified changed tokens permit that retry; editing
a JSON marker never makes authentication verified. Existing
v1 data and schemas are preserved; no history is deleted or claimed complete.
Exit codes: 0 successful read/sync (including partial/cap-limited), 1 operational
failure, 2 invalid arguments, 3 reauthorization/verification required.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import app
import health_sources as sources
import sleep_collector as sleep
import auth_session
import health_points as points
import health_history as history
import health_storage as storage
import health_analysis as analysis
import health_recovery as recovery

SOURCE_NAMES = ("activities", "sleep", "resting_hr", "hrv", "all_day_heart_rate", "spo2", "vo2max")
FRESH_SECONDS = 36 * 3600
SYNC_KEYS = ("last_status", "checked_at_utc", "last_success_time_utc", "last_verified_time_utc",
             "verified_auth_mtime_ns", "blocked_auth_fingerprint", "authentication_required")
STATE_KEYS = ("last_status", "checked_at_utc", "last_success_time_utc", "received_records",
              "stored_records", "coverage", "quality", "lookback_days", "query_limit")
COVERAGES = {"bounded_window", "coverage_limited", "legacy_latest_only", "not_collected", "not_assessed", "latest_measurement"}


def utc_now():
    return datetime.now(timezone.utc)


def _exists(db, table):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def ensure_schema(db):
    sleep.ensure_schema(db)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS metric_stats (
            metric TEXT NOT NULL CHECK(metric IN ('resting_hr','hrv','all_day_heart_rate','spo2')),
            day TEXT NOT NULL,
            time_zone TEXT NOT NULL CHECK(time_zone='+0800'),
            field_name TEXT NOT NULL,
            unit TEXT,
            avg, min, max, sum, count,
            source TEXT NOT NULL CHECK(source='huawei_training_camp'),
            PRIMARY KEY(metric,day,time_zone),
            CHECK((metric='resting_hr' AND field_name='restBpm' AND unit='bpm')
               OR (metric='hrv' AND field_name='avgHrv' AND unit IS NULL)
               OR (metric='all_day_heart_rate' AND field_name='bpm' AND unit='bpm')
               OR (metric='spo2' AND field_name='spO2' AND unit='percent'))
        );
        CREATE TABLE IF NOT EXISTS health_source_state (
            name TEXT PRIMARY KEY CHECK(name IN ('activities','sleep','resting_hr','hrv','all_day_heart_rate','spo2','vo2max')),
            last_status TEXT NOT NULL, checked_at_utc TEXT NOT NULL,
            last_success_time_utc TEXT, received_records INTEGER NOT NULL,
            stored_records INTEGER NOT NULL, coverage TEXT NOT NULL, quality TEXT,
            lookback_days INTEGER NOT NULL, query_limit INTEGER
        );
        CREATE TABLE IF NOT EXISTS health_sync_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            last_status TEXT NOT NULL, checked_at_utc TEXT NOT NULL,
            last_success_time_utc TEXT, last_verified_time_utc TEXT,
            verified_auth_mtime_ns INTEGER, blocked_auth_fingerprint TEXT,
            authentication_required INTEGER NOT NULL CHECK(authentication_required IN (0,1))
        );
    """)
    points.ensure_schema(db)
    storage.ensure_schema(db)
    history.ensure_schema(db)
    _extend_source_state_for_points(db)


def _extend_source_state_for_points(db):
    """Atomically widen only the existing source-name CHECK, preserving rows."""
    ddl=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='health_source_state'").fetchone()[0]
    if "'vo2max'" in ddl:
        return
    token="'spo2'))"
    if token not in ddl or 'health_source_state_before_points' in ddl:
        raise app.StorageError()
    expanded=ddl.replace(token,"'spo2','vo2max'))",1)
    columns=['name',*STATE_KEYS]
    if [x[1] for x in db.execute('PRAGMA table_info(health_source_state)')]!=columns:
        raise app.StorageError()
    db.execute('SAVEPOINT add_point_sources')
    try:
        db.execute('ALTER TABLE health_source_state RENAME TO health_source_state_before_points')
        db.execute(expanded)
        names=','.join(columns)
        db.execute(f'INSERT INTO health_source_state ({names}) SELECT {names} FROM health_source_state_before_points')
        db.execute('DROP TABLE health_source_state_before_points')
        db.execute('RELEASE SAVEPOINT add_point_sources')
    except Exception:
        db.execute('ROLLBACK TO SAVEPOINT add_point_sources')
        db.execute('RELEASE SAVEPOINT add_point_sources')
        raise


def _auth_mtime(path):
    # Metadata only. Read commands never read credential contents.
    try:
        info = Path(path).lstat()
        return info.st_mtime_ns if app._private_file(info, 0o600) and info.st_size <= app.MAX_AUTH_BYTES else None
    except OSError:
        return None


def _fingerprint(headers):
    # An internal private rejection key, never emitted. Touching unchanged
    # rejected credentials or clearing sync-status.json cannot unblock them.
    if headers is None:
        return None
    return hashlib.sha256(json.dumps(headers, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _legacy_marker(store):
    fd = None
    try:
        fd = os.open("sync-status.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=store.directory_fd)
        with os.fdopen(fd, "rb") as handle:
            fd = None
            info = os.fstat(handle.fileno())
            if not app._private_file(info, 0o600) or info.st_nlink != 1 or info.st_size > 32768:
                return {}
            raw = handle.read(32769)
            if len(raw) > 32768:
                return {}
        data = json.loads(raw, object_pairs_hook=app._unique_object)
        if not isinstance(data, dict):
            return {}
        # Do not propagate arbitrary marker fields or v1 nested payloads.
        return {k: data.get(k) for k in ("authentication_required", "auth_mtime_ns", "checked_at_utc")}
    except (OSError, ValueError, UnicodeError, RecursionError):
        return {}
    finally:
        if fd is not None:
            os.close(fd)


def _sync_state(db):
    if not _exists(db, "health_sync_state"):
        return {}
    row = db.execute("SELECT " + ",".join(SYNC_KEYS) + " FROM health_sync_state WHERE singleton=1").fetchone()
    return dict(zip(SYNC_KEYS, row)) if row else {}


def _legacy_failure(store, previous):
    """Honor the deployed v1 pause, including its database failure markers.

    Ignore an older v1 failure only after a newer unified cycle has actually
    run. The auth mtime can permit a probe, never certify successful renewal.
    """
    checked = app._utc_timestamp(previous.get("checked_at_utc"))
    failures = []
    marker = _legacy_marker(store)
    stamp = app._utc_timestamp(marker.get("checked_at_utc"))
    if marker.get("authentication_required") is True and (not checked or not stamp or stamp > checked):
        mtime = marker.get("auth_mtime_ns")
        failures.append((stamp, mtime if type(mtime) is int else None))
    for table in ("collection_state", "sleep_collection_state"):
        if not _exists(store.connection, table):
            continue
        row = store.connection.execute(f"SELECT last_status,collected_at_utc FROM {table} WHERE singleton=1").fetchone()
        stamp = app._utc_timestamp(row[1]) if row else None
        if row and row[0] == "reauth_required" and (not checked or not stamp or stamp > checked):
            failures.append((stamp, None))
    return max(failures, key=lambda item: item[0] or "") if failures else None


def _unchanged_legacy_failure(failure, mtime):
    if failure is None:
        return False
    stamp, rejected_mtime = failure
    if rejected_mtime is not None:
        return mtime == rejected_mtime
    if mtime is None or stamp is None:
        return True
    return mtime <= int(datetime.fromisoformat(stamp).timestamp() * 1000000000)


def _source_state(db, name):
    if _exists(db, "health_source_state"):
        row = db.execute("SELECT " + ",".join(STATE_KEYS) + " FROM health_source_state WHERE name=?", (name,)).fetchone()
        if row:
            return dict(zip(STATE_KEYS, row))
    table = {"activities": "collection_state", "sleep": "sleep_collection_state"}.get(name)
    if table and _exists(db, table):
        row = db.execute(f"SELECT last_status,collected_at_utc FROM {table} WHERE singleton=1").fetchone()
        if row:
            return dict(last_status=row[0], checked_at_utc=row[1],
                        last_success_time_utc=row[1] if row[0] in sources.SUCCESS else None,
                        coverage="legacy_latest_only" if name == "activities" else "bounded_window")
    return {}


def _count(db, name):
    if name == points.METRIC:
        return db.execute('SELECT count(*) FROM point_measurements WHERE metric=? AND source=?',(name,app.SOURCE)).fetchone()[0] if _exists(db,'point_measurements') else 0
    if name in sources.METRICS:
        return db.execute("SELECT count(*) FROM metric_stats WHERE metric=? AND source=?", (name, app.SOURCE)).fetchone()[0] if _exists(db, "metric_stats") else 0
    table = "activities" if name == "activities" else "sleep_records"
    return db.execute(f"SELECT count(*) FROM {table} WHERE source=?", (app.SOURCE,)).fetchone()[0] if _exists(db, table) else 0


def _data_freshness(db, name, count, now):
    if count == 0:
        return "empty"
    if name == points.METRIC:
        stamp=db.execute('SELECT max(measured_at_ns) FROM point_measurements WHERE metric=? AND source=?',(name,app.SOURCE)).fetchone()[0]
        if type(stamp) is not int:return 'unknown'
        age_ns=int(now.timestamp()*points.NS_PER_SECOND)-stamp
        return 'recent' if 0<=age_ns<=FRESH_SECONDS*points.NS_PER_SECOND else 'stale'
    if name in sources.METRICS:
        # A row containing only missing/retained fields is not a new measured
        # day. Never promote freshness because an empty placeholder is recent.
        fields = ('avg',) if name in ('resting_hr','hrv') else ('min','max') if name == 'all_day_heart_rate' else ('avg','min','max')
        rows = db.execute('SELECT day,avg,min,max FROM metric_stats WHERE metric=? AND source=? ORDER BY day DESC',(name,app.SOURCE))
        has_retained = False
        for row in rows:
            record = dict(zip(('day','avg','min','max'),row))
            retained = storage.quality(db,name,record)['retained_fields']
            has_retained |= any(record[k] is not None and k in retained for k in fields)
            if not any(record[k] is not None and k not in retained for k in fields):
                continue
            latest = record['day']
            day = sources.day_string(latest.replace('-','')) if type(latest) is str and len(latest)==10 else None
            if day is None:continue
            delta = (now.astimezone(sources.LOCAL_ZONE).date() - datetime.fromisoformat(day).date()).days
            return 'recent' if 0 <= delta <= 1 else 'stale'
        return 'retained' if has_retained else 'unknown'
    table, key = ("activities", "start_time_utc") if name == "activities" else ("sleep_records", "end_time_utc")
    value = db.execute(f"SELECT max({key}) FROM {table} WHERE source=?", (app.SOURCE,)).fetchone()[0]
    stamp = app._utc_timestamp(value)
    if stamp is None:
        return "unknown"
    age = (now - datetime.fromisoformat(stamp)).total_seconds()
    return "recent" if 0 <= age <= FRESH_SECONDS else "stale"


def _operational(store, auth_path, now):
    previous = _sync_state(store.connection) if store else {}
    failure = _legacy_failure(store, previous) if store else None
    mtime = _auth_mtime(auth_path) if store else None
    verified_at = app._utc_timestamp(previous.get("last_verified_time_utc"))
    if (failure is not None or previous.get("authentication_required") == 1
            or previous.get("blocked_auth_fingerprint") is not None):
        auth_state = "reauth_required"
    elif previous.get('last_status') == 'auth_check_error':
        auth_state = 'check_failed'
    elif verified_at:
        auth_state = "verified" if mtime is not None and mtime == previous.get("verified_auth_mtime_ns") else "verification_required"
    else:
        auth_state = "unverified"
    required = auth_state in ("reauth_required", "verification_required")
    payload = dict(source=app.SOURCE, status="not_initialized" if store is None else "ready",
                   checked_at_utc=app._utc_timestamp(previous.get("checked_at_utc")),
                   last_sync_status=previous.get("last_status") if previous.get("last_status") in sources.STATUSES | {"collection_error", "auth_check_error"} else None,
                   last_success_time_utc=app._utc_timestamp(previous.get("last_success_time_utc")),
                   authentication_required=required,
                   authentication=dict(state=auth_state, last_verified_time_utc=verified_at,
                       requires_user=required and previous.get('last_status') != 'auth_check_error',
                       temporary_check_failure=previous.get('last_status') == 'auth_check_error'), sources={})
    if store:
        payload["status"] = 'auth_check_error' if previous.get('last_status') == 'auth_check_error' else "reauth_required" if required else payload["last_sync_status"] or "ready"
    for name in SOURCE_NAMES:
        saved = _source_state(store.connection, name) if store else {}
        last = saved.get("last_status")
        last = last if last in sources.STATUSES else "invalid_response" if last is not None else None
        successful_at = app._utc_timestamp(saved.get("last_success_time_utc"))
        if required:
            freshness = "stale_auth"
        elif not successful_at:
            freshness = "never"
        elif auth_state != "verified":
            freshness = "unverified_auth"
        elif last not in sources.SUCCESS:
            freshness = "collection_failed"
        else:
            age = (now - datetime.fromisoformat(successful_at)).total_seconds()
            freshness = "fresh" if 0 <= age <= FRESH_SECONDS else "stale"
        count = _count(store.connection, name) if store else 0
        coverage = saved.get("coverage")
        payload["sources"][name] = dict(status="reauth_required" if required else last or "not_collected",
            count=count, last_collection_status=last,
            last_collection_time_utc=app._utc_timestamp(saved.get("checked_at_utc")),
            last_success_time_utc=successful_at, freshness=freshness,
            data_freshness="stale_auth" if required and count else _data_freshness(store.connection, name, count, now) if store else "empty",
            received_records=sleep.integer(saved.get("received_records")),
            stored_records=sleep.integer(saved.get("stored_records")),
            coverage=coverage if coverage in COVERAGES else "not_collected",
            quality=saved.get("quality") if saved.get("quality") in ("ok", "partial", "empty") else None,
            lookback_days=None if name==points.METRIC else sleep.integer(saved.get("lookback_days"), 30),
            query_limit=sleep.integer(saved.get("query_limit"), 100),
            retained_fields=storage.retained_count(store.connection,name) if store else 0,
            complete_history=False)
    return payload


def capabilities():
    """Evidence is deliberately not upgraded by the presence of saved rows."""
    items = {
        "sleep": dict(integrated=True, evidence_state="account_verified_v1", coverage="bounded_window", time_units="top_level_ns_nested_ms_durations_minutes"),
        "activities": dict(integrated=True, evidence_state="single_record_account_verified_list_reference_verified",
                           coverage="bounded_window_max_100_cap_may_limit", duration_unit="ms", distance_unit="m"),
        "resting_hr": dict(integrated=True, evidence_state="account_verified", field_name="restBpm", unit="bpm", granularity="daily_statistics"),
        "hrv": dict(integrated=True, evidence_state="account_verified", field_name="avgHrv", unit=None, unit_evidence="unverified", granularity="daily_statistics"),
        "all_day_heart_rate": dict(integrated=True, evidence_state="account_verified", field_name="bpm", unit="bpm", granularity="daily_min_max", average_available=False, raw_time_series_verified=False),
        "spo2": dict(integrated=True, evidence_state="account_verified", field_name="spO2", unit="percent", granularity="daily_statistics", raw_time_series_verified=False),
        "vo2max": dict(integrated=True,evidence_state="account_route_verified",field_name="vo2max",unit=None,unit_evidence="unverified",granularity="single_measurement",coverage="latest_measurement",measurement_time_preserved=True),
    }
    items["steps"] = dict(integrated=False, evidence_state="endpoint_probe_inconclusive", availability="not_verified", reason="official_delta_and_total_types_returned_empty_or_business_error_on_checked_routes")
    return dict(source=app.SOURCE, status="ok", capabilities=items, complete_history=False,
                medical_analysis=False, auth_renewal="official_authInfo_and_private_local_browser", expired_token_recovery_acceptance="verified_in_actual_service_2026_10_12", evidence_scope="this_authorized_account", all_huawei_health_metrics_integrated=False)


def _store_result(store, name, result, at, days, limit):
    db = store.connection
    valid_records = []
    if result.status in sources.SUCCESS:
        for record in result.records:
            if name == "activities":
                out = app.normalize_summary(record)
                if out["start_time_utc"] is not None and out["activity_type"] is not None:
                    valid_records.append(out)
            elif name == "sleep":
                out = _sleep_summary(record)
                if out is not None:
                    valid_records.append(out)
            elif name == points.METRIC:
                out=points.normalize_point(record,name)
                if out is not None:valid_records.append(out)
            else:
                out = sources.normalize_metric(record, name)
                if out is not None:
                    valid_records.append(out)
    with db:
        storage.store_records(db,name,valid_records,at)
        if name in history.SOURCE_NAMES and result.status in ('ok','partial','empty') and len(valid_records)==len(result.records):
            # Only the adapter knows the actual request window. A cycle clock
            # or legacy/mock result without this metadata cannot certify dates.
            first=getattr(result,'queried_start_day',None)
            last=getattr(result,'queried_end_day',None)
            checked=getattr(result,'queried_at_utc',None)
            if first is not None and last is not None and checked is not None:
                history.record_queried_window(db,name,first,last,checked,result.status)
        if name == "activities":
            db.execute("""INSERT INTO collection_state VALUES (1,?,?)
                ON CONFLICT(singleton) DO UPDATE SET last_status=excluded.last_status,
                collected_at_utc=excluded.collected_at_utc""", (result.status, at))
        elif name == "sleep":
            db.execute("""INSERT INTO sleep_collection_state VALUES (1,?,?,?)
                ON CONFLICT(singleton) DO UPDATE SET last_status=excluded.last_status,
                collected_at_utc=excluded.collected_at_utc,fetched_records=excluded.fetched_records""",
                (result.status, at, len(valid_records)))

        db.execute("""INSERT INTO health_source_state
            (name,last_status,checked_at_utc,last_success_time_utc,received_records,
             stored_records,coverage,quality,lookback_days,query_limit)
            VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET
            last_status=excluded.last_status,checked_at_utc=excluded.checked_at_utc,
            last_success_time_utc=COALESCE(excluded.last_success_time_utc,health_source_state.last_success_time_utc),
            received_records=excluded.received_records,stored_records=excluded.stored_records,
            coverage=excluded.coverage,quality=excluded.quality,
            lookback_days=excluded.lookback_days,query_limit=excluded.query_limit""",
            (name, result.status, at, at if result.status in sources.SUCCESS else None,
             result.received_count, len(valid_records), result.coverage if result.status in sources.SUCCESS else "not_assessed",
             result.quality, days, limit))
    return len(valid_records)


def _record_cycle(db, previous, status, at, *, required, mtime, fingerprint, verified=False):
    with db:
        db.execute("""INSERT INTO health_sync_state VALUES (1,?,?,?,?,?,?,?)
            ON CONFLICT(singleton) DO UPDATE SET last_status=excluded.last_status,
            checked_at_utc=excluded.checked_at_utc,last_success_time_utc=excluded.last_success_time_utc,
            last_verified_time_utc=excluded.last_verified_time_utc,
            verified_auth_mtime_ns=excluded.verified_auth_mtime_ns,
            blocked_auth_fingerprint=excluded.blocked_auth_fingerprint,
            authentication_required=excluded.authentication_required""",
            (status, at, at if status in sources.SUCCESS else previous.get("last_success_time_utc"),
             at if verified else previous.get("last_verified_time_utc"),
             mtime if verified else previous.get("verified_auth_mtime_ns"),
             fingerprint if required else None, int(required)))


def _fetch_source(name, headers, days, limit):
    try:
        if name == 'activities':
            result = sources.fetch_activities(headers,days=days,limit=limit)
        elif name == 'sleep':
            old = sleep.fetch(headers,days=days)
            result = sources.Result(old.status,old.records,len(old.records),quality=old.status if old.status in ('ok','partial','empty') else None,
                queried_start_day=getattr(old,'queried_start_day',None),
                queried_end_day=getattr(old,'queried_end_day',None),
                queried_at_utc=getattr(old,'queried_at_utc',None))
        elif name == points.METRIC:
            result=points.fetch(headers,name)
        else:
            result = sources.fetch_metric(headers,name,days=days)
        return result if result.status in sources.STATUSES else sources.Result('invalid_response')
    except Exception:
        return sources.Result('transport_error')


def run_once(state_dir=app.DEFAULT_STATE_DIR, auth_file=None, *, activity_days=30,
             sleep_days=7, metric_days=7, activity_limit=100):
    # Validate every option before any store, credential or network access.
    for days in (activity_days, sleep_days, metric_days):
        sources.bounded_int(days)
    sources.bounded_int(activity_limit, 100)
    state_dir = Path(state_dir)
    auth_path = Path(auth_file) if auth_file is not None else state_dir / "auth.json"
    now = utc_now()
    at = now.isoformat()
    with app.Store(state_dir, create=True) as store:
        fd = os.open("sync.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     0o600, dir_fd=store.directory_fd)
        try:
            info = os.fstat(fd)
            if not app._private_file(info, 0o600) or info.st_nlink != 1:
                raise app.StorageError()
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return dict(source=app.SOURCE, status="already_running", network_attempted=False)
            ensure_schema(store.connection)
            previous = _sync_state(store.connection)
            mtime = _auth_mtime(auth_path)
            headers = app.load_auth(auth_path)
            fingerprint = _fingerprint(headers)
            rejected = previous.get("blocked_auth_fingerprint")
            known_block = (rejected is not None and fingerprint == rejected) or _unchanged_legacy_failure(_legacy_failure(store, previous), mtime)
            production = state_dir == app.DEFAULT_STATE_DIR and auth_path == state_dir / "auth.json"
            auth_proven = False
            recovered = {}
            if production:
                recovered = auth_session.ensure_auth(state_dir, force=known_block)
                if recovered.get("status") == "ok" and recovered.get("vps_auth_verified") is True:
                    headers = app.load_auth(auth_path)
                    mtime = _auth_mtime(auth_path)
                    fingerprint = _fingerprint(headers)
                    auth_proven = known_block and bool(recovered.get("revalidated") or recovered.get("session_restored"))
                else:
                    headers = None
                    if recovered.get('status') != 'reauth_required' and recovered.get('requires_user') is not True:
                        # Network/browser trouble is not evidence that the
                        # user must log in again. Keep any genuine old block.
                        blocked = bool(known_block or previous.get('authentication_required'))
                        _record_cycle(store.connection,previous,'auth_check_error',at,
                            required=blocked,mtime=mtime,fingerprint=rejected if blocked else None)
                        payload=_operational(store,auth_path,now)
                        payload.update(network_attempted=False,
                            attempted_sources={name:False for name in SOURCE_NAMES})
                        return payload
            paused = headers is None or (known_block and not auth_proven and fingerprint == rejected) or (not auth_proven and _unchanged_legacy_failure(_legacy_failure(store,previous),mtime))
            attempted = {name: False for name in SOURCE_NAMES}
            if paused:
                _record_cycle(store.connection, previous, "reauth_required", at,
                              required=True, mtime=mtime, fingerprint=fingerprint)
            else:
                results = {}
                days_by_source = {"activities": activity_days, "sleep": sleep_days,
                                  **{name:metric_days for name in sources.METRICS},points.METRIC:0}
                recovery_attempted = False
                recovery_temporary_failure = False
                for name in SOURCE_NAMES:
                    attempted[name] = True
                    result = _fetch_source(name,headers,days_by_source[name],activity_limit)
                    if result.status == 'reauth_required' and production and not recovery_attempted:
                        recovery_attempted = True
                        before = headers.get('Authorization') if headers else None
                        refreshed = auth_session.ensure_auth(state_dir,force=True)
                        recovery_temporary_failure = (refreshed.get('status') not in ('ok','reauth_required') and refreshed.get('requires_user') is not True)
                        updated = app.load_auth(auth_path)
                        # Retry only with a server-verified, actually changed
                        # token; never repeat a rejected token blindly.
                        if refreshed.get('status') == 'ok' and refreshed.get('vps_auth_verified') is True and updated and updated.get('Authorization') != before:
                            headers=updated;mtime=_auth_mtime(auth_path);fingerprint=_fingerprint(headers)
                            result=_fetch_source(name,headers,days_by_source[name],activity_limit)
                    _store_result(store, name, result, at, days_by_source[name], activity_limit if name == "activities" else None)
                    results[name] = result.status
                    if result.status == "reauth_required":
                        break  # Never make another request with failed authentication.
                required = "reauth_required" in results.values()
                all_success = len(results) == len(SOURCE_NAMES) and all(s in sources.SUCCESS for s in results.values())
                if required:
                    status = 'auth_check_error' if recovery_temporary_failure else "reauth_required"
                elif not all_success:
                    status = "collection_error"
                elif "coverage_limited" in results.values():
                    status = "coverage_limited"
                elif "partial" in results.values():
                    status = "partial"
                elif all(s == "empty" for s in results.values()):
                    status = "empty"
                else:
                    status = "ok"
                verified = not required and any(s in sources.SUCCESS for s in results.values())
                # A marker or credential-file update by itself cannot verify auth.
                required = required or (not verified and previous.get("authentication_required") == 1)
                _record_cycle(store.connection, previous, status, at, required=required,
                              mtime=mtime, fingerprint=fingerprint if 'reauth_required' in results.values() else previous.get("blocked_auth_fingerprint"),
                              verified=verified)
            payload = _operational(store, auth_path, now)
            payload["network_attempted"] = any(attempted.values())
            if production:
                payload['auth_control'] = {k:v for k,v in recovered.items() if k in ('status','error_type','method','requires_user','vps_auth_verified','renewed','session_restored','process_exit','pam_related','permission_related','readonly_related','python_error_names','missing_modules','trace_files','launcher_errors','stderr_length')}
            for name, was_attempted in attempted.items():
                payload["sources"][name]["network_attempted"] = was_attempted
            return payload
        finally:
            os.close(fd)


def _sleep_summary(record):
    if not isinstance(record, dict):
        return None
    out = {}
    for key in sleep.KEYS:
        if key.endswith("_utc"):
            out[key] = app._utc_timestamp(record.get(key))
        else:
            maximum = 1440 if key in sleep.MINUTE_FIELDS.values() else 100 if key in ("sleep_score", "sleep_efficiency_percent") else app.SQLITE_MAX_INT
            out[key] = sleep.integer(record.get(key), maximum)
    if (any(out[k] is None for k in ("start_time_utc", "end_time_utc", "sleep_type"))
            or out["end_time_utc"] < out["start_time_utc"]):
        return None
    return out


def _summaries(db, name, limit):
    if name==points.METRIC:
        if not _exists(db,'point_measurements'):return []
        rows=db.execute('SELECT '+','.join(points.POINT_KEYS)+' FROM point_measurements WHERE metric=? AND source=? ORDER BY measured_at_ns DESC LIMIT ?',(name,app.SOURCE,limit)).fetchall()
        return [out for row in rows if (out:=points.normalize_point(dict(zip(points.POINT_KEYS,row)),name)) is not None]
    if name == "activities":
        rows = db.execute("SELECT " + ",".join(app.SUMMARY_KEYS) +
            " FROM activities WHERE source=? ORDER BY start_time_utc DESC,activity_type DESC LIMIT ?", (app.SOURCE, limit)).fetchall()
        records = [app.normalize_summary(dict(zip(app.SUMMARY_KEYS, row))) for row in rows]
        return [r for r in records if r["start_time_utc"] is not None and r["activity_type"] is not None]
    if name == "sleep":
        if not _exists(db, "sleep_records"):
            return []
        rows = db.execute("SELECT " + ",".join(sleep.KEYS) +
            " FROM sleep_records WHERE source=? ORDER BY end_time_utc DESC LIMIT ?", (app.SOURCE, limit)).fetchall()
        return [out for row in rows if (out := _sleep_summary(dict(zip(sleep.KEYS, row)))) is not None]
    if not _exists(db, "metric_stats"):
        return []
    rows = db.execute("SELECT " + ",".join(sources.METRIC_KEYS) +
        " FROM metric_stats WHERE metric=? AND source=? ORDER BY day DESC LIMIT ?", (name, app.SOURCE, limit)).fetchall()
    return [out for row in rows if (out := sources.normalize_metric(dict(zip(sources.METRIC_KEYS, row)), name)) is not None]


def read_view(state_dir=app.DEFAULT_STATE_DIR, auth_file=None, *, mode="status", limit=14):
    if mode not in ("status", "latest", "report"):
        raise app.InvalidArguments()
    sources.bounded_int(limit, 100)
    auth_path = Path(auth_file) if auth_file is not None else Path(state_dir) / "auth.json"
    now = utc_now()
    try:
        with app.Store(state_dir) as store:
            payload = _operational(store, auth_path, now)
            if mode != "status":
                payload["saved_data_only"] = True
                for name, entry in payload["sources"].items():
                    records = _summaries(store.connection, name, 1 if mode == "latest" else limit)
                    for record in records:
                        record['field_quality']=storage.quality(store.connection,name,record)
                    if mode == "latest":
                        entry["summary"] = records[0] if records else None
                    else:
                        entry.update(records=records, returned_records=len(records))
            return payload
    except app.NotInitialized:
        payload = _operational(None, auth_path, now)
        if mode != "status":
            payload["saved_data_only"] = True
            for entry in payload["sources"].values():
                entry.update(summary=None) if mode == "latest" else entry.update(records=[], returned_records=0)
        return payload


def _history_auth_providers(state_dir,auth_path):
    production=Path(state_dir)==app.DEFAULT_STATE_DIR and Path(auth_path)==Path(state_dir)/'auth.json'
    def check(control):
        if control.get('status')=='ok' and control.get('vps_auth_verified') is True:return True
        if control.get('status')=='reauth_required' or control.get('requires_user') is True:return False
        raise history.HeadersUnavailable()
    def provide():
        if production:
            current=app.load_auth(auth_path)
            blocked=False
            try:
                with app.Store(state_dir) as store:
                    blocked=bool(current and _exists(store.connection,'health_history_auth_block') and history._blocked(store.connection,current))
            except app.NotInitialized:pass
            if not check(auth_session.ensure_auth(state_dir,force=blocked)):return None
        return app.load_auth(auth_path)
    def recover(rejected):
        control=auth_session.ensure_auth(state_dir,force=True)
        check(control)
        return {'status':control.get('status'),'headers':app.load_auth(auth_path),'vps_auth_verified':control.get('vps_auth_verified') is True}
    return provide,recover if production else None


def history_command(state_dir=app.DEFAULT_STATE_DIR,auth_file=None,*,mode='backfill',days=365,start=None,end=None,source_names=None,window_days=30,resume=True):
    plan=history.plan_coverage_windows(days,start=start,end=end,window_days=window_days)
    names=history._scope(source_names)
    state_dir=Path(state_dir)
    auth_path=Path(auth_file) if auth_file is not None else state_dir/'auth.json'
    if mode=='history-status':
        payload=history.read_coverage(state_dir,start=plan[0][0],end=plan[-1][1],source_names=names,window_days=window_days)
    elif mode=='backfill':
        provide,recover=_history_auth_providers(state_dir,auth_path)
        payload=history.run_backfill(state_dir,provide,start=plan[0][0],end=plan[-1][1],source_names=names,window_days=window_days,
            recover_headers=recover,resume=resume)
    else:raise app.InvalidArguments()
    payload.update(source=app.SOURCE,command=mode,scope_start=plan[0][0],scope_end=plan[-1][1],source_names=list(names),
        requested_scope_queried=payload.get('pending_windows')==0 and payload.get('coverage_limited_windows')==0)
    return payload


def recovery_command(state_dir,auth_file=None,*,plan=None,max_calls=2,now=None):
    state_dir=Path(state_dir)
    auth_path=Path(auth_file) if auth_file is not None else state_dir/'auth.json'
    provide,recover=_history_auth_providers(state_dir,auth_path)
    return recovery.run_recovery(state_dir,provide,plan=plan,max_calls=max_calls,
                                 recover_headers=recover,now=now)


def build_parser():
    common = app.SafeArgumentParser(add_help=False)
    # SUPPRESS is essential: a subparser must not reset a pre-command path to
    # production. Defaults are supplied only once, in main's namespace.
    common.add_argument("--state-dir", default=argparse.SUPPRESS, help="private state directory")
    common.add_argument("--auth-file", default=argparse.SUPPRESS, help="private auth file; only sync/backfill reads its contents")
    parser = app.SafeArgumentParser(description=__doc__, parents=[common])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("sync", "status", "capabilities", "latest", "report", "backfill", "history-status", 'analyze', 'recovery-status', 'catchup'):
        command = commands.add_parser(name, parents=[common])
        if name == "sync":
            for option, default in (("activity-days", 30), ("sleep-days", 7), ("metric-days", 7)):
                command.add_argument("--" + option, type=app._lookback, default=default)
            command.add_argument("--activity-limit", type=_limit, default=100)
            command.add_argument('--catch-up',action='store_true',default=False)
            command.add_argument('--catch-up-max-calls',type=int,default=2)
        if name=='analyze':
            command.add_argument('--days',type=int,default=7)
            command.add_argument('--start');command.add_argument('--end')
            command.add_argument('--baseline-days',type=int,default=28)
            command.add_argument('--include-today',action='store_true',default=False)
        if name=='catchup':command.add_argument('--max-calls',type=int,default=2)
        if name == "report":
            command.add_argument("--limit", type=_limit, default=14)
        if name in ('backfill','history-status'):
            command.add_argument('--days',type=int,default=365)
            command.add_argument('--start');command.add_argument('--end')
            command.add_argument('--window-days',type=int,default=30)
            command.add_argument('--source',action='append',choices=history.SOURCE_NAMES)
            command.add_argument('--no-resume',action='store_true',default=False)
    return parser


def _limit(value):
    try:
        return sources.bounded_int(int(value), 100)
    except (ValueError, app.InvalidArguments):
        raise argparse.ArgumentTypeError("invalid_limit") from None


def main(argv=None):
    try:
        args = build_parser().parse_args(argv, namespace=argparse.Namespace(
            state_dir=str(app.DEFAULT_STATE_DIR), auth_file=None))
        if args.command == "sync":
            if not 1<=args.catch_up_max_calls<=24:raise app.InvalidArguments()
            gap_plan=None
            if args.catch_up:
                gap_plan=recovery.plan_recovery(args.state_dir,now=utc_now(),activity_days=args.activity_days,
                    sleep_days=args.sleep_days,metric_days=args.metric_days)
                recovery.enqueue(args.state_dir,gap_plan,now=utc_now())
            payload = run_once(args.state_dir, args.auth_file, activity_days=args.activity_days,
                               sleep_days=args.sleep_days, metric_days=args.metric_days,
                               activity_limit=args.activity_limit)
            if args.catch_up and payload['status'] in sources.SUCCESS:
                gap_plan=recovery.plan_recovery(args.state_dir,now=utc_now())
                payload['catch_up']=recovery_command(args.state_dir,args.auth_file,plan=gap_plan,
                    max_calls=args.catch_up_max_calls,now=utc_now())
                if payload['catch_up']['status'] in ('reauth_required','auth_check_error','storage_error'):
                    payload['status']=payload['catch_up']['status']
            elif args.catch_up:payload['catch_up']={'status':'skipped_due_to_collection_state','network_calls':0}
        elif args.command=='analyze':
            payload=analysis.build_analysis(args.state_dir,days=args.days,start=args.start,end=args.end,
                baseline_days=args.baseline_days,include_today=args.include_today,now=utc_now())
        elif args.command=='recovery-status':
            payload=recovery.plan_recovery(args.state_dir,now=utc_now())
        elif args.command=='catchup':
            payload=recovery_command(args.state_dir,args.auth_file,max_calls=args.max_calls,now=utc_now())
        elif args.command in ('backfill','history-status'):
            payload=history_command(args.state_dir,args.auth_file,mode=args.command,days=args.days,start=args.start,end=args.end,
                source_names=args.source,window_days=args.window_days,resume=not args.no_resume)
        elif args.command == "capabilities":
            payload = capabilities()
        else:
            payload = read_view(args.state_dir, args.auth_file, mode=args.command, limit=getattr(args, "limit", 14))
    except app.InvalidArguments:
        payload = dict(status="invalid_arguments")
    except (app.StorageError, OSError, sqlite3.Error):
        payload = dict(source=app.SOURCE, status="storage_error")
    except Exception:
        payload = dict(source=app.SOURCE, status="internal_error")
    print(json.dumps(payload, sort_keys=True, allow_nan=False))
    status = payload["status"]
    if status == "invalid_arguments":
        return 2
    if status == "reauth_required":
        return 3
    return 0 if status in sources.SUCCESS | {"ready", "already_running", "not_complete", "not_initialized",'up_to_date','pending','outside_supported_range'} else 1


if __name__ == "__main__":
    raise SystemExit(main())
