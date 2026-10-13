"""Read-only sleep summaries from the already-verified Huawei web endpoint.

Only authorized sleep summary fields are retained. Raw responses, record IDs,
fragment timelines, coordinates, HRV and unrelated metrics are never persisted.
Top-level times are nanoseconds; time fields in value are milliseconds;
duration fields are minutes. Missing/invalid values remain None.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib import error, parse, request

import app
import collector

URL = "https://hihealthbase-drcn.things.dbankcloud.cn/healthrunninggroup/v1/healthRecords"
DATA_TYPE = "com.huawei.health.record.sleep"
SUB_DATA_TYPE = "com.huawei.continuous.sleep.fragment"
TIME_FIELDS = {"go_bed_time": "go_bed_time_utc", "fall_asleep_time": "fall_asleep_time_utc",
               "wakeup_time": "wakeup_time_utc"}
MINUTE_FIELDS = {"all_sleep_time": "total_sleep_minutes", "light_sleep_time": "light_sleep_minutes",
                 "deep_sleep_time": "deep_sleep_minutes", "dream_time": "rem_sleep_minutes",
                 "awake_time": "awake_minutes", "sleep_latency": "sleep_latency_minutes"}
INT_FIELDS = {"wakeup_count": "wakeup_count", "sleep_score": "sleep_score",
              "sleep_efficiency": "sleep_efficiency_percent", "sleep_type": "sleep_type"}
KEYS = ("start_time_utc", "end_time_utc", *TIME_FIELDS.values(), *MINUTE_FIELDS.values(), *INT_FIELDS.values())
VALUE_KEYS = ("longValue", "integerValue", "floatValue", "doubleValue")


@dataclass
class Result:
    status: str
    records: list[dict] = field(default_factory=list, repr=False)
    # Inclusive full +0800 dates proven by a rolling request, if any.
    queried_start_day: str | None = field(default=None, repr=False)
    queried_end_day: str | None = field(default=None, repr=False)
    queried_at_utc: str | None = field(default=None, repr=False)


def integer(value, maximum=app.SQLITE_MAX_INT):
    if type(value) is int and 0 <= value <= maximum:
        return value
    if type(value) is float and value.is_integer() and 0 <= value <= maximum:
        return int(value)
    return None


def stamp(value, divisor):
    value = integer(value)
    if value is None:
        return None
    try:
        seconds, remainder = divmod(value, divisor)
        return datetime.fromtimestamp(seconds, timezone.utc).replace(
            microsecond=remainder * 1000000 // divisor).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def rolling_query_window(start, end, divisor):
    """Full elapsed +0800 dates inside actual integer wire bounds, plus UTC at.

    Round a partial starting date up and exclude the ongoing ending date. Use
    integer wire units so even one nanosecond past midnight cannot certify the
    whole first day. A short rolling query may contain no full calendar dates.
    """
    day_units, offset = 86400 * divisor, 8 * 3600 * divisor
    first, remainder = divmod(start + offset, day_units)
    first += bool(remainder)
    last = (end + offset) // day_units - 1
    epoch = date(1970, 1, 1)
    return ((epoch + timedelta(days=first)).isoformat() if first <= last else None,
            (epoch + timedelta(days=last)).isoformat() if first <= last else None,
            stamp(end, divisor))


def normalize(item):
    values = {}
    allowed = set(TIME_FIELDS) | set(MINUTE_FIELDS) | set(INT_FIELDS)
    raw_values = item.get("value")
    if isinstance(raw_values, list):
        for entry in raw_values:
            if not isinstance(entry, dict) or not isinstance(entry.get("fieldName"), str) or entry.get("fieldName") not in allowed:
                continue
            for key in VALUE_KEYS:
                if key in entry:
                    values[entry["fieldName"]] = entry[key]
                    break
    out = dict(start_time_utc=stamp(item.get("startTime"), 1000000000),
               end_time_utc=stamp(item.get("endTime"), 1000000000))
    for source, target in TIME_FIELDS.items():
        out[target] = stamp(values.get(source), 1000)
    for source, target in MINUTE_FIELDS.items():
        out[target] = integer(values.get(source), 1440)
    for source, target in INT_FIELDS.items():
        out[target] = integer(values.get(source), 100 if source in ("sleep_score", "sleep_efficiency") else app.SQLITE_MAX_INT)
    if out["start_time_utc"] and out["end_time_utc"] and out["end_time_utc"] < out["start_time_utc"]:
        out["end_time_utc"] = None
    return out


def analyse(response):
    code = response.status
    if code in (401, 403, 301, 302, 303, 307, 308):
        return Result("reauth_required")
    if code == 429:
        return Result("rate_limited")
    if 500 <= code <= 599:
        return Result("service_error")
    if not 200 <= code <= 299:
        return Result("http_error")
    if "html" in response.content_type.lower() or response.body.lstrip().startswith((b"<html", b"<!DOCTYPE")):
        return Result("reauth_required")
    if len(response.body) > collector.MAX_BODY:
        return Result("invalid_response")
    try:
        raw = json.loads(response.body)
    except (ValueError, UnicodeDecodeError):
        return Result("invalid_response")
    # The successful real response has exactly this envelope. Unknown JSON
    # business-error shapes must not be reported as an empty health history.
    items = raw.get("healthRecords") if isinstance(raw, dict) and set(raw) == {"healthRecords"} else raw if isinstance(raw, list) else None
    if not isinstance(items, list) or len(items) > 1000 or any(not isinstance(x, dict) for x in items):
        return Result("invalid_response")
    if not items:
        return Result("empty")
    records = []
    partial = False
    for item in items:
        out = normalize(item)
        if any(out[key] is None for key in ("start_time_utc", "end_time_utc", "sleep_type")):
            partial = True
            continue
        partial = partial or any(value is None for value in out.values())
        records.append(out)
    records.sort(key=lambda x: x["end_time_utc"])
    return Result("partial" if partial else "ok", records)


def fetch(headers, *, days=7):
    if type(days) is not int or not 1 <= days <= 30:
        raise app.InvalidArguments()
    end_ns = time.time_ns()
    params = {"startTime": end_ns - days * 86400 * 1000000000, "endTime": end_ns,
              "dataType": DATA_TYPE}
    url = URL + "?" + parse.urlencode(params)
    opener = request.build_opener(request.ProxyHandler({}),
        request.HTTPSHandler(context=ssl.create_default_context()), collector.NoRedirect())
    try:
        with opener.open(request.Request(url, headers=headers, method="GET"), timeout=10) as r:
            response = collector.Response(r.status, r.read(collector.MAX_BODY + 1), r.headers.get("Content-Type", ""))
    except error.HTTPError as exc:
        code = exc.code
        exc.close()
        return analyse(collector.Response(code, b""))
    except Exception:
        return Result("transport_error")
    result = analyse(response)
    if result.status in ('ok', 'partial', 'empty'):
        result.queried_start_day, result.queried_end_day, result.queried_at_utc = rolling_query_window(params['startTime'], end_ns, 1000000000)
    return result


def ensure_schema(db):
    columns = ",\n".join(name + (" TEXT" if name.endswith("_utc") else " INTEGER") for name in KEYS)
    db.execute("CREATE TABLE IF NOT EXISTS sleep_records (" + columns +
        ", source TEXT NOT NULL CHECK(source='huawei_training_camp'), UNIQUE(start_time_utc,sleep_type))")
    db.execute("""CREATE TABLE IF NOT EXISTS sleep_collection_state (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), last_status TEXT NOT NULL,
        collected_at_utc TEXT NOT NULL, fetched_records INTEGER NOT NULL)""")


def collect_once(state_dir=app.DEFAULT_STATE_DIR, auth_file=None, *, days=7):
    if type(days) is not int or not 1 <= days <= 30:
        raise app.InvalidArguments()
    now = datetime.now(timezone.utc).isoformat()
    headers = app.load_auth(auth_file if auth_file is not None else Path(state_dir) / "auth.json")
    payload = dict(source=app.SOURCE, status="reauth_required", collected_at_utc=now, stored_records=0)
    try:
        with app.Store(state_dir, create=True) as store:
            ensure_schema(store.connection)
            result = fetch(headers, days=days) if headers is not None else Result("reauth_required")
            names = ",".join(KEYS)
            marks = ",".join("?" for _ in KEYS)
            updates = ",".join(f"{k}=excluded.{k}" for k in KEYS if k not in ("start_time_utc", "sleep_type"))
            with store.connection:
                for record in result.records:
                    store.connection.execute(f"INSERT INTO sleep_records ({names},source) VALUES ({marks},?) "
                        f"ON CONFLICT(start_time_utc,sleep_type) DO UPDATE SET {updates}",
                        tuple(record[k] for k in KEYS) + (app.SOURCE,))
                store.connection.execute("""INSERT INTO sleep_collection_state VALUES (1,?,?,?)
                    ON CONFLICT(singleton) DO UPDATE SET last_status=excluded.last_status,
                    collected_at_utc=excluded.collected_at_utc, fetched_records=excluded.fetched_records""",
                    (result.status, now, len(result.records)))
            payload.update(status=result.status, stored_records=len(result.records))
    except Exception:
        payload.update(status="storage_error", stored_records=0)
    return payload


def read(state_dir=app.DEFAULT_STATE_DIR, *, latest=False, limit=14):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise app.InvalidArguments()
    try:
        with app.Store(state_dir) as store:
            exists = store.connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='sleep_records'").fetchone()
            if not exists:
                return dict(source=app.SOURCE, status="not_initialized", count=0)
            count = store.connection.execute("SELECT count(*) FROM sleep_records").fetchone()[0]
            row = store.connection.execute("SELECT last_status,collected_at_utc,fetched_records FROM sleep_collection_state WHERE singleton=1").fetchone()
            payload = dict(source=app.SOURCE, status=row[0] if row else "ready", count=count,
                last_collection_status=row[0] if row else None,
                last_collection_time_utc=row[1] if row else None)
            if latest:
                row = store.connection.execute("SELECT " + ",".join(KEYS) +
                    " FROM sleep_records ORDER BY end_time_utc DESC LIMIT 1").fetchone()
                payload["summary"] = dict(zip(KEYS, row)) if row else None
            else:
                rows = store.connection.execute("SELECT " + ",".join(KEYS) +
                    " FROM sleep_records ORDER BY end_time_utc DESC LIMIT ?", (limit,)).fetchall()
                payload["records"] = [dict(zip(KEYS, x)) for x in rows]
            return payload
    except app.NotInitialized:
        return dict(source=app.SOURCE, status="not_initialized", count=0)


def main(argv=None):
    try:
        parser = app.SafeArgumentParser(description=__doc__)
        parser.add_argument("command", choices=("collect", "status", "latest", "list"))
        parser.add_argument("--state-dir", default=str(app.DEFAULT_STATE_DIR))
        parser.add_argument("--auth-file")
        parser.add_argument("--days", type=app._lookback, default=7)
        parser.add_argument("--limit", type=int, default=14)
        args = parser.parse_args(argv)
        if args.command == "collect":
            payload = collect_once(args.state_dir, args.auth_file, days=args.days)
        elif args.command == "status":
            payload = read(args.state_dir, latest=True)
            payload.pop("summary", None)
        else:
            payload = read(args.state_dir, latest=args.command == "latest", limit=args.limit)
    except app.InvalidArguments:
        payload = dict(status="invalid_arguments")
    except Exception:
        payload = dict(source=app.SOURCE, status="storage_error")
    print(json.dumps(payload, allow_nan=False, sort_keys=True))
    return 3 if payload["status"] == "reauth_required" else 0 if payload["status"] in ("ok", "partial", "empty", "ready") else 1


if __name__ == "__main__":
    raise SystemExit(main())
