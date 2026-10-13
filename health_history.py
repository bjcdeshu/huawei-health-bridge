"""Bounded historical Huawei queries and private, resumable window coverage.

No credentials are loaded here. The CLI/auth coordinator supplies a zero-argument
headers_provider. An optional recover_headers(rejected_headers) callback is called
at most once, only after an actual HTTP 401, and must return
{"headers": <changed headers>, "vps_auth_verified": True}. A marker or changed
Cookie/client ID is not a changed, verified access token. Previously rejected
tokens are blocked across runs, independently of live collection state.

Dates are inclusive Asia/Shanghai calendar dates (date or strict YYYY-MM-DD).
HTTP is authorized only for the last 365 calendar days, including today; each
query covers at most 30 days. Offline views also accept old scopes. Coverage is
a date union, independent of display-window boundaries. Completed days end at
midnight minus one wire unit; today ends at actual UTC now, and its incomplete
tail must be refreshed after midnight. There is no all-time archive discovery.

Storage uses app.Store and the existing summary tables. Historical writes never
update collection_state, sleep_collection_state, health_source_state, or
health_sync_state. storage_callback(db, source, normalized_records), if supplied,
must upsert without committing or updating live state and return its stored row
count. Records and coverage commit together. Stored counts mean accepted/upserted
summaries, not newly inserted rows. Split parent counts summarize child windows;
run network_calls counts attempted requests, including split probes/retries.

Public integration: plan_windows (online), plan_coverage_windows (offline),
fetch_window, ensure_schema, store_records, record_queried_window, run_backfill,
read_coverage. No CLI, browser, auth-file, logging, or scheduler.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import ssl
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from urllib import error, parse, request

import app
import collector
import health_sources as sources
import health_storage as storage
import sleep_collector as sleep

SOURCE_NAMES = ("activities", "sleep", "resting_hr", "hrv", "all_day_heart_rate", "spo2")
MAX_DAYS = 365
MAX_WINDOW_DAYS = 30
MAX_CALLS = 1024
MAX_SPLIT_DEPTH = 5
MAX_REQUEST_BODY = 8192
MAX_BODY = collector.MAX_BODY
STRATEGIES = ("MAX", "MIN", "AVG", "SUM", "COUNT")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
COVERAGE_KEYS = ("source", "start_day", "end_day", "status", "coverage",
                 "received_count", "stored_count", "collected_at_utc", "coverage_limited")
HISTORY_STATUSES = app.COLLECTION_STATUSES | {"coverage_limited", "split"}


class HeadersUnavailable(Exception):
    """Temporary coordinator failure, not evidence of rejected credentials."""


@dataclass
class WindowResult:
    status: str
    records: list[dict] = field(default_factory=list, repr=False)
    received_count: int = 0
    coverage: str = "not_assessed"
    quality: str | None = None
    http_status: int | None = None


def utc_now():
    return datetime.now(timezone.utc)


def _now(value=None):
    value = utc_now() if value is None else value
    if (not isinstance(value, datetime) or value.tzinfo is None
            or value.utcoffset() is None or value < EPOCH):
        raise app.InvalidArguments()
    return value.astimezone(timezone.utc)


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise app.InvalidArguments()
    return value


def _date(value):
    if type(value) is date:
        return value
    if type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        try:
            return date.fromisoformat(value)
        except ValueError:
            pass
    raise app.InvalidArguments()


def _range(start, end, now, maximum=MAX_WINDOW_DAYS):
    start, end = _date(start), _date(end)
    today = now.astimezone(sources.LOCAL_ZONE).date()
    if not today - timedelta(days=MAX_DAYS - 1) <= start <= end <= today:
        raise app.InvalidArguments()
    if (end - start).days >= maximum:
        raise app.InvalidArguments()
    return start, end


def plan_coverage_windows(days=365, *, start=None, end=None, window_days=30, now=None):
    """Partition an offline scope, including old dates, without authorizing HTTP.

    A view is still bounded to 365 days and 1..30-day display windows. Dates must
    be valid, ordered and not in the future; there is no moving lower date bound.
    """
    _integer(days, 1, MAX_DAYS)
    _integer(window_days, 1, MAX_WINDOW_DAYS)
    today = _now(now).astimezone(sources.LOCAL_ZONE).date()
    if start is not None and end is None:
        raise app.InvalidArguments()
    end = today if end is None else _date(end)
    try:
        start = end - timedelta(days=days - 1) if start is None else _date(start)
    except OverflowError:
        raise app.InvalidArguments() from None
    if not start <= end <= today or (end - start).days >= MAX_DAYS:
        raise app.InvalidArguments()
    windows = []
    while start <= end:
        last = start + timedelta(days=min(window_days - 1, (end - start).days))
        windows.append((start.isoformat(), last.isoformat()))
        if last == end:
            break
        start = last + timedelta(days=1)
    return windows


def plan_windows(days=365, *, start=None, end=None, window_days=30, now=None):
    """Plan online queries strictly inside the most recent 365 calendar days.

    Explicit start/end select a range instead of the trailing `days` default.
    An end alone selects `days` ending there, still inside the authorized year.
    """
    now = _now(now)
    windows = plan_coverage_windows(days, start=start, end=end, window_days=window_days, now=now)
    _range(windows[0][0], windows[-1][1], now, MAX_DAYS)
    return windows


def _scope(source_names=None):
    names = SOURCE_NAMES if source_names is None else source_names
    if (not isinstance(names, (tuple, list)) or not names
            or any(type(name) is not str or name not in SOURCE_NAMES for name in names)
            or len(set(names)) != len(names)):
        raise app.InvalidArguments()
    if any(name not in sources.METRICS for name in names if name not in ("activities", "sleep")):
        raise app.InvalidArguments()
    return tuple(names)


def _metric_spec(name):
    if name not in SOURCE_NAMES[2:] or name not in sources.METRICS:
        raise app.InvalidArguments()
    spec = sources.METRICS[name]
    if (not isinstance(spec, (tuple, list)) or len(spec) != 4
            or spec[0] not in (sources.RESTING_HR_URL, sources.HRV_URL)
            or type(spec[1]) is not str or not spec[1].startswith("com.huawei.")
            or type(spec[2]) is not str or not re.fullmatch(r"[A-Za-z0-9_]{1,64}", spec[2])
            or (spec[3] is not None and type(spec[3]) is not str)):
        raise app.InvalidArguments()
    return spec


def _units(stamp, divisor):
    delta = stamp.astimezone(timezone.utc) - EPOCH
    return (delta.days * 86400 + delta.seconds) * divisor + delta.microseconds * divisor // 1000000


def _midnight(day):
    return datetime.combine(day, time.min, tzinfo=sources.LOCAL_ZONE)


def _bounds(start, end, divisor, now):
    return _units(_midnight(start), divisor), min(
        _units(_midnight(end + timedelta(days=1)), divisor) - 1, _units(now, divisor))


def _payload(source, start, end, now, activity_limit):
    if source == "sleep":
        low, high = _bounds(start, end, 1000000000, now)
        params = dict(startTime=low, endTime=high, dataType=sleep.DATA_TYPE)
        return "GET", sleep.URL + "?" + parse.urlencode(params), b""
    if source == "activities":
        low, high = _bounds(start, end, 1000, now)
        payload = dict(startTime=str(low), endTime=str(high), limit=activity_limit,
                       order="endTimeDesc")
        url = sources.ACTIVITIES_URL
    else:
        url, dtype, field_name, _ = _metric_spec(source)
        first, last = start.strftime("%Y%m%d"), end.strftime("%Y%m%d")
        item = dict(dataType=dtype, startDay=first if source == "hrv" else int(first),
                    endDay=last if source == "hrv" else int(last), strategy=list(STRATEGIES),
                    groupOption="day", timeZone=sources.TIME_ZONE)
        if source == "hrv":
            item["fieldNames"] = [field_name]
        payload = dict(reqs=[item], groupReqs=[dict(item)])
    return "POST", url, json.dumps(payload, allow_nan=False, separators=(",", ":")).encode()


def _wire_range(first, last, divisor, now):
    if any(type(t) is not str or not re.fullmatch(r"[0-9]{1,20}", t)
           or str(int(t)) != t for t in (first, last)):
        raise ValueError("invalid_time_range")
    first, last = int(first), int(last)
    if not 0 <= first <= last <= _units(now, divisor):
        raise ValueError("invalid_time_range")
    try:
        start = (EPOCH + timedelta(seconds=first // divisor)).astimezone(sources.LOCAL_ZONE).date()
        end = (EPOCH + timedelta(seconds=last // divisor)).astimezone(sources.LOCAL_ZONE).date()
        start, end = _range(start, end, now)
        if first != _units(_midnight(start), divisor):
            raise ValueError("invalid_time_range")
        if (end < now.astimezone(sources.LOCAL_ZONE).date()
                and last != _units(_midnight(end + timedelta(days=1)), divisor) - 1):
            raise ValueError("invalid_time_range")
    except (app.InvalidArguments, OverflowError):
        raise ValueError("invalid_time_range") from None


def check_request(method, url, body, *, now=None):
    """Allow only the six summary sources and exact historical DTOs."""
    now = _now(now)
    if type(url) is not str or type(body) is not bytes or len(body) > MAX_REQUEST_BODY:
        raise ValueError("request_not_allowed")
    if method == "GET" and url.startswith(sleep.URL + "?"):
        if body or len(url) > MAX_REQUEST_BODY:
            raise ValueError("query_not_allowed")
        pairs = parse.parse_qsl(url[len(sleep.URL) + 1:], keep_blank_values=True, strict_parsing=True)
        params = app._unique_object(pairs)
        if (set(params) != {"startTime", "endTime", "dataType"}
                or params["dataType"] != sleep.DATA_TYPE):
            raise ValueError("query_not_allowed")
        # Reject fragments, alternate encodings, duplicate fields and extra URL components.
        if url != sleep.URL + "?" + parse.urlencode(params):
            raise ValueError("query_not_allowed")
        _wire_range(params["startTime"], params["endTime"], 1000000000, now)
        return
    if method != "POST" or url not in (sources.ACTIVITIES_URL, sources.RESTING_HR_URL, sources.HRV_URL):
        raise ValueError("request_not_allowed")
    data = json.loads(body, object_pairs_hook=app._unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_json")))
    if not isinstance(data, dict):
        raise ValueError("query_not_allowed")
    if url == sources.ACTIVITIES_URL:
        if (set(data) != {"startTime", "endTime", "limit", "order"}
                or type(data["limit"]) is not int or not 1 <= data["limit"] <= 100
                or data["order"] != "endTimeDesc"):
            raise ValueError("query_not_allowed")
        _wire_range(data["startTime"], data["endTime"], 1000, now)
        return
    if (set(data) != {"reqs", "groupReqs"} or type(data["reqs"]) is not list
            or len(data["reqs"]) != 1 or data["groupReqs"] != data["reqs"]
            or type(data["reqs"][0]) is not dict):
        raise ValueError("query_not_allowed")
    item = data["reqs"][0]
    matches = [name for name in SOURCE_NAMES[2:] if name in sources.METRICS
               and _metric_spec(name)[0] == url and _metric_spec(name)[1] == item.get("dataType")]
    if len(matches) != 1:
        raise ValueError("query_not_allowed")
    name = matches[0]
    keys = {"dataType", "startDay", "endDay", "strategy", "groupOption", "timeZone"}
    if name == "hrv":
        keys.add("fieldNames")
    if (set(item) != keys or item["strategy"] != list(STRATEGIES)
            or item["groupOption"] != "day" or item["timeZone"] != sources.TIME_ZONE
            or (name == "hrv" and item["fieldNames"] != [_metric_spec(name)[2]])):
        raise ValueError("query_not_allowed")
    expected_type = str if name == "hrv" else int
    if type(item["startDay"]) is not expected_type or type(item["endDay"]) is not expected_type:
        raise ValueError("invalid_day_type")
    try:
        _range(sources.day_string(item["startDay"]), sources.day_string(item["endDay"]), now)
    except app.InvalidArguments:
        raise ValueError("invalid_time_range") from None


def _headers(headers):
    if (type(headers) is not dict or set(headers) - app.AUTH_KEYS
            or any(type(value) is not str or len(value) > app.MAX_AUTH_BYTES
                   or any(ord(c) < 32 or ord(c) == 127 for c in value) for value in headers.values())
            or any(not headers.get(key, "").strip() for key in ("Authorization", "x-client-id"))):
        return None
    if sum(len(key) + len(value) for key, value in headers.items()) > app.MAX_AUTH_BYTES:
        return None
    return dict(headers)


class OfficialTransport:
    def __init__(self, *, network_authorized=False, now=None):
        if network_authorized is not True:
            raise ValueError("network_not_authorized")
        self._now = now
        self._opener = request.build_opener(request.ProxyHandler({}), collector.NoRedirect(),
            request.HTTPSHandler(context=ssl.create_default_context()))

    def send(self, method, url, headers, body):
        check_request(method, url, body, now=self._now)
        supplied = dict(headers)
        content_type = supplied.pop("Content-Type", None)
        if _headers(supplied) is None or (method == "POST" and content_type != "application/json"):
            raise ValueError("headers_not_allowed")
        if method == "GET" and content_type is not None:
            raise ValueError("headers_not_allowed")
        req = request.Request(url, data=body if method == "POST" else None, headers=headers, method=method)
        try:
            response = self._opener.open(req, timeout=10)
        except error.HTTPError as exc:
            response = exc
        with response:
            kind = response.headers.get("Content-Type", "")
            if not 200 <= response.code <= 299 or "html" in kind.lower():
                return collector.Response(response.code, b"", kind)
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise sources.ResponseTooLarge("response_too_large")
            return collector.Response(response.code, data, kind)


def _result(parsed, received=None, http_status=None):
    if parsed.status not in sources.STATUSES:
        return WindowResult("invalid_response", http_status=http_status)
    success = parsed.status in sources.SUCCESS
    limited = parsed.status == "coverage_limited"
    return WindowResult(parsed.status, parsed.records if success else [],
        parsed.received_count if received is None else received,
        "coverage_limited" if limited else "queried" if success else "not_assessed",
        parsed.quality if hasattr(parsed, "quality") else parsed.status if success else None, http_status)


def _analyse(response, source, start, end, now, activity_limit):
    if (type(getattr(response, "status", None)) is not int
            or type(getattr(response, "body", None)) is not bytes
            or type(getattr(response, "content_type", None)) is not str):
        return WindowResult("invalid_response")
    failure, raw = sources._decode(response)
    if failure:
        return WindowResult(failure, http_status=response.status)
    if source in ("activities", "sleep"):
        if source == "sleep" and type(raw) is dict and set(raw) == {"healthRecords"}:
            raw = raw["healthRecords"]
        maximum = activity_limit if source == "activities" else 1000
        if type(raw) is not list or len(raw) > maximum or any(type(item) is not dict for item in raw):
            return WindowResult("invalid_response", http_status=response.status)
        divisor = 1000 if source == "activities" else 1000000000
        low, high = _bounds(start, end, divisor, now)
        valid, skipped = [], False
        for item in raw:
            keys = ("startTime", "endTime") if source == "sleep" or "endTime" in item else ("startTime",)
            if any(type(item.get(key)) is not int for key in keys):
                skipped = True
                continue
            if source=='sleep':
                # The API returns overlapping sessions on either boundary.
                # Storage bins by start date; do not reject a valid prior night.
                if item['startTime']>high or item['endTime']<low or item['endTime']>_units(now,10**9) or item['endTime']-item['startTime']>86400*10**9:
                    return WindowResult('invalid_response',received_count=len(raw),http_status=response.status)
            elif any(not low <= item[key] <= high for key in keys):
                return WindowResult("invalid_response", received_count=len(raw), http_status=response.status)
            if "endTime" in keys and item["endTime"] < item["startTime"]:
                skipped = True
                continue
            valid.append(item)
        clean = collector.Response(200, json.dumps(valid, allow_nan=False,separators=(',',':'),ensure_ascii=False).encode(), response.content_type)
        if source == "activities":
            parsed = sources.analyse_activities(clean, limit=activity_limit, start_ms=low, end_ms=high)
        else:
            old = sleep.analyse(clean)
            parsed = sources.Result(old.status, old.records, quality=old.status)
        if skipped:
            parsed.status, parsed.quality = "partial", "partial"
        if len(raw) == maximum:
            parsed.status = "coverage_limited"
        return _result(parsed, len(raw), response.status)
    # The shared analyser owns COUNT=0 semantics, missing values and first-day wins.
    parsed = sources.analyse_metric(response, source, start_day=start.strftime("%Y%m%d"),
                                    end_day=end.strftime("%Y%m%d"))
    if parsed.status in sources.SUCCESS:
        # Reject ignored/out-of-window data rather than certify a misapplied query.
        expected = _metric_spec(source)[2]
        for group in raw["groupResults"]:
            for entry in group["groupStatistics"]:
                if entry.get("fieldName") == expected:
                    day = sources.day_string(entry.get("startDay"))
                    if day is not None and not start.isoformat() <= day <= end.isoformat():
                        return WindowResult("invalid_response", http_status=response.status)
    return _result(parsed, http_status=response.status)


def fetch_window(headers, source, start, end, transport=None, *, now=None, activity_limit=100):
    """One allowlisted HTTP attempt; return only normalized in-memory summaries."""
    _scope([source])
    _integer(activity_limit, 1, 100)
    now = _now(now)
    start, end = _range(start, end, now)
    method, url, body = _payload(source, start, end, now, activity_limit)
    check_request(method, url, body, now=now)
    headers = _headers(headers)
    if headers is None:
        return WindowResult("reauth_required")
    if method == "POST":
        headers["Content-Type"] = "application/json"
    try:
        transport = transport if transport is not None else OfficialTransport(network_authorized=True, now=now)
        response = transport.send(method, url, headers, body)
    except sources.ResponseTooLarge:
        if source=='sleep':
            # Large fragment payloads are a known volume limit, not a guessed
            # empty/error response. Split dates instead of raising the body cap.
            return WindowResult('coverage_limited',coverage='coverage_limited',http_status=200)
        return WindowResult("invalid_response")
    except Exception:
        return WindowResult("transport_error")
    try:
        return _analyse(response, source, start, end, now, activity_limit)
    except (ValueError, TypeError, OverflowError, RecursionError, AttributeError):
        return WindowResult("invalid_response", http_status=getattr(response, "status", None))


def _quote(value):
    return "'" + value.replace("'", "''") + "'"


def ensure_schema(db):
    """Add only compatible summary tables and separate private history state."""
    sleep.ensure_schema(db)
    names = [name for name in SOURCE_NAMES[2:] if name in sources.METRICS]
    checks = []
    for name in names:
        _, _, field_name, unit = _metric_spec(name)
        checks.append("(metric=" + _quote(name) + " AND field_name=" + _quote(field_name)
                      + " AND unit" + (" IS NULL" if unit is None else "=" + _quote(unit)) + ")")
    # The shared descriptor, not a second metric/dataType catalog, owns the schema.
    types = {"metric": "TEXT NOT NULL", "day": "TEXT NOT NULL", "time_zone": "TEXT NOT NULL",
             "field_name": "TEXT NOT NULL", "unit": "TEXT"}
    if any(not re.fullmatch(r"[a-z_]+", key) for key in sources.METRIC_KEYS):
        raise app.InvalidArguments()
    columns = ",".join(key + " " + types.get(key, "") for key in sources.METRIC_KEYS)
    db.execute("CREATE TABLE IF NOT EXISTS metric_stats (" + columns +
        ",source TEXT NOT NULL CHECK(source='huawei_training_camp'),"
        "PRIMARY KEY(metric,day,time_zone),CHECK(time_zone='+0800'),CHECK(" + " OR ".join(checks) + "))")
    db.execute("""CREATE TABLE IF NOT EXISTS health_history_coverage (
        source TEXT NOT NULL CHECK(source IN ('activities','sleep','resting_hr','hrv','all_day_heart_rate','spo2')),
        start_day TEXT NOT NULL, end_day TEXT NOT NULL, status TEXT NOT NULL,
        coverage TEXT NOT NULL CHECK(coverage IN ('queried','coverage_limited','not_assessed')),
        received_count INTEGER NOT NULL CHECK(received_count>=0),
        stored_count INTEGER NOT NULL CHECK(stored_count>=0), collected_at_utc TEXT NOT NULL,
        coverage_limited INTEGER NOT NULL CHECK(coverage_limited IN (0,1)),
        PRIMARY KEY(source,start_day,end_day), CHECK(start_day<=end_day))""")
    db.execute("""CREATE TABLE IF NOT EXISTS health_history_auth_block (
        token_hash TEXT PRIMARY KEY, rejected_at_utc TEXT NOT NULL)""")
    db.commit()


def _sleep_summary(record):
    out = {}
    for key in sleep.KEYS:
        maximum = 1440 if key in sleep.MINUTE_FIELDS.values() else 100 if key in (
            "sleep_score", "sleep_efficiency_percent") else app.SQLITE_MAX_INT
        out[key] = app._utc_timestamp(record.get(key)) if key.endswith("_utc") else sleep.integer(record.get(key), maximum)
    if (any(out[key] is None for key in ("start_time_utc", "end_time_utc", "sleep_type"))
            or out["end_time_utc"] < out["start_time_utc"]):
        return None
    return out


def _normalized(source, records, start=None, end=None):
    valid, seen = [], set()
    for record in records:
        if type(record) is not dict:
            continue
        if source == "activities":
            out = app.normalize_summary(record)
            if out["start_time_utc"] is None or out["activity_type"] is None:
                continue
            key = (out["start_time_utc"], out["activity_type"])
        elif source == "sleep":
            out = _sleep_summary(record)
            if out is None:
                continue
            key = (out["start_time_utc"], out["sleep_type"])
        else:
            out = sources.normalize_metric(record, source)
            if out is None or out["count"] == 0:
                continue
            key = (out["metric"], out["day"], out["time_zone"])
        if start is not None:
            days = [out["day"]] if source in sources.METRICS else [
                datetime.fromisoformat(out[k]).astimezone(sources.LOCAL_ZONE).date().isoformat()
                for k in ("start_time_utc",)]
            if any(not start <= day <= end for day in days):
                continue
        if key not in seen:
            seen.add(key)
            valid.append(out)
    return valid


def store_records(db, source, records):
    """Idempotent summary-only upserts; deliberately no live-state updates/commit."""
    _scope([source])
    records = _normalized(source, records)
    return storage.store_records(db, source, records, utc_now().isoformat())


def _clean_row(raw):
    row = dict(zip(COVERAGE_KEYS, raw))
    # Do not expose arbitrary persisted strings or trust malformed intervals.
    try:
        first, last = _date(row["start_day"]), _date(row["end_day"])
    except app.InvalidArguments:
        return None
    if row["source"] not in SOURCE_NAMES or not 0 <= (last - first).days < MAX_WINDOW_DAYS:
        return None
    status = row["status"] if row["status"] in HISTORY_STATUSES else "invalid_response"
    received, stored = sleep.integer(row["received_count"]), sleep.integer(row["stored_count"])
    at = app._utc_timestamp(row["collected_at_utc"])
    coverage = row["coverage"] if row["coverage"] in ("queried", "coverage_limited", "not_assessed") else "not_assessed"
    if received is None or stored is None or at is None or row["coverage_limited"] not in (0, 1):
        status = "invalid_response"
    if status == "split" and first == last:
        status = "invalid_response"
    if status not in sources.SUCCESS:
        coverage = "not_assessed"
    elif status == "coverage_limited" or row["coverage_limited"] == 1:
        # A contradictory flag must never promote a capped query to queried.
        status, coverage = "coverage_limited", "coverage_limited"
    return dict(source=row["source"], start_day=first.isoformat(), end_day=last.isoformat(),
                status=status, coverage=coverage, received_count=received or 0,
                stored_count=stored or 0, collected_at_utc=at,
                coverage_limited=status == "split" or coverage == "coverage_limited")


def _row(db, source, start, end):
    raw = db.execute("SELECT " + ",".join(COVERAGE_KEYS) + " FROM health_history_coverage "
        "WHERE source=? AND start_day=? AND end_day=?", (source, start, end)).fetchone()
    return _clean_row(raw) if raw is not None else None


def _rows(db, source, start, end):
    if db is None:
        return []
    raw = db.execute("SELECT " + ",".join(COVERAGE_KEYS) + " FROM health_history_coverage "
        "WHERE source=? AND start_day<=? AND end_day>=? ORDER BY start_day,end_day",
        (source, end, start))
    return [row for item in raw if (row := _clean_row(item)) is not None]


def _completed(row):
    return bool(row and row["status"] in sources.SUCCESS and row["coverage"] in ("queried", "coverage_limited"))


def _coverage(db, source, start, end, result, at, stored=0):
    db.execute("""INSERT INTO health_history_coverage VALUES (?,?,?,?,?,?,?,?,?)
        ON CONFLICT(source,start_day,end_day) DO UPDATE SET
        status=excluded.status,coverage=excluded.coverage,received_count=excluded.received_count,
        stored_count=excluded.stored_count,collected_at_utc=excluded.collected_at_utc,
        coverage_limited=excluded.coverage_limited""", (source, start, end, result.status, result.coverage,
        result.received_count, stored, at, int(result.coverage == "coverage_limited" or result.status == "split")))


def record_queried_window(db, source, start, end, checked_at, status="ok"):
    """Record a successful sync query for FULL past days; return days recorded.

    The caller owns the existing schema, lock and transaction. No commit, schema
    creation, record storage or live-state changes occur here. checked_at is an
    aware datetime or UTC ISO timestamp. Only ok/partial/empty certify a query;
    capped/errors are rejected. The validated query is at most 30 days within
    checked_at's recent year, and its current-day tail is always excluded.
    """
    _scope([source])
    if status not in ("ok", "partial", "empty") or checked_at is None:
        raise app.InvalidArguments()
    if isinstance(checked_at, str):
        at = app._utc_timestamp(checked_at)
        if at is None:
            raise app.InvalidArguments()
        checked_at = datetime.fromisoformat(at)
    checked_at = _now(checked_at)
    first, last = _range(start, end, checked_at)
    last = min(last, checked_at.astimezone(sources.LOCAL_ZONE).date() - timedelta(days=1))
    if last < first:
        return 0
    previous = _row(db, source, first.isoformat(), last.isoformat())
    # Do not erase an existing history query's received/stored counters.
    if not (previous and previous["coverage"] == "queried"
            and _covered_days(previous, checked_at) == _days(first, last)):
        _coverage(db, source, first.isoformat(), last.isoformat(),
                  WindowResult(status, coverage="queried", received_count=previous["received_count"] if previous else 0),
                  checked_at.isoformat(), previous["stored_count"] if previous else 0)
    return (last - first).days + 1


def _token_hash(headers):
    # Token identity only: modifying cookies/client/version cannot unblock it.
    return hashlib.sha256(headers["Authorization"].encode()).hexdigest()


def _blocked(db, headers):
    return db.execute("SELECT 1 FROM health_history_auth_block WHERE token_hash=?", (_token_hash(headers),)).fetchone() is not None


def _days(first, last):
    return set(range(_date(first).toordinal(), _date(last).toordinal() + 1))


def _intervals(days):
    """Maximal inclusive, oldest-first intervals from a bounded day union."""
    intervals = []
    for day in sorted(days):
        if intervals and intervals[-1][1] + 1 == day:
            intervals[-1][1] = day
        else:
            intervals.append([day, day])
    return [dict(start_day=date.fromordinal(first).isoformat(),
                 end_day=date.fromordinal(last).isoformat()) for first, last in intervals]


def _covered_days(row, now):
    if not _completed(row):
        return set()
    checked = datetime.fromisoformat(row["collected_at_utc"])
    if checked > now:
        return set()
    last = _date(row["end_day"])
    checked_day = checked.astimezone(sources.LOCAL_ZONE).date()
    today = now.astimezone(sources.LOCAL_ZONE).date()
    # Keep today's queried snapshot compatible, but never carry an unfinished
    # current-day tail into tomorrow as if it were a full historical day.
    last = min(last, checked_day if checked_day == today else checked_day - timedelta(days=1))
    return _days(row["start_day"], last)


def _sum_known(rows, key):
    values = [row[key] for row in rows]
    return None if any(value is None for value in values) else sum(values)


def _record_counts(rows, start, end):
    # Legacy rows contain window counters, not per-day counts. Never prorate a
    # clipped count or double-count split parents and their children. An exact
    # snapshot remains usable unless crossing overlaps make it ambiguous.
    ordered = sorted(rows, key=lambda row: (row["start_day"], -_date(row["end_day"]).toordinal()))
    for index, left in enumerate(ordered):
        if any(left["start_day"] < right["start_day"] <= left["end_day"] < right["end_day"]
               for right in ordered[index + 1:]):
            return None, None
    selected = []
    for row in ordered:
        if selected and row["end_day"] <= selected[-1]["end_day"]:
            continue
        selected.append(row)
    if any(row["start_day"] < start or row["end_day"] > end for row in selected):
        # A matching child can supply exact counters for a split subwindow.
        exact = next((row for row in rows if (row["start_day"], row["end_day"]) == (start, end)), None)
        return (exact["received_count"], exact["stored_count"]) if exact else (None, None)
    return _sum_known(selected, "received_count"), _sum_known(selected, "stored_count")


def _window_view(rows, source, start, end, now):
    rows = [row for row in rows if row["start_day"] <= end and row["end_day"] >= start]
    scope, completed, queried = _days(start, end), set(), set()
    contributing = []
    for row in rows:
        covered = _covered_days(row, now) & scope
        completed.update(covered)
        if covered and row["coverage"] == "queried":
            queried.update(covered)
            contributing.append(row)
    limited = completed - queried
    previous = next((row for row in rows if (row["start_day"], row["end_day"]) == (start, end)), None)
    status = previous["status"] if previous and not _completed(previous) else "pending"
    coverage = "not_assessed"
    if completed == scope:
        coverage = "coverage_limited" if limited else "queried"
        status = "coverage_limited" if limited else "partial" if any(
            row["status"] == "partial" for row in contributing) else (
            "empty" if all(row["status"] == "empty" for row in contributing) else "ok")
    received, stored = _record_counts(rows, start, end)
    stamps = [row["collected_at_utc"] for row in rows if row["collected_at_utc"] is not None]
    return dict(source=source, start_day=start, end_day=end, status=status, coverage=coverage,
        received_count=received, stored_count=stored, collected_at_utc=max(stamps) if stamps else None,
        coverage_limited=bool(limited) or status == "split", planned_days=len(scope),
        completed_days=len(completed), queried_days=len(queried), coverage_limited_days=len(limited),
        pending_days=len(scope - completed), missing_intervals=_intervals(scope - queried),
        pending_intervals=_intervals(scope - completed))


def _view(db, plan, names, *, status=None, network_calls=0, now=None):
    now = _now(now)
    windows, missing = [], {}
    for source in names:
        rows = _rows(db, source, plan[0][0], plan[-1][1])
        windows.extend(_window_view(rows, source, start, end, now) for start, end in plan)
        missing[source] = _window_view(rows, source, plan[0][0], plan[-1][1], now)["missing_intervals"]
    done = sum(_completed(row) for row in windows)
    limited = sum(row["coverage"] == "coverage_limited" for row in windows)
    if status is None:
        status = "not_complete" if done != len(windows) else "coverage_limited" if limited else (
            "partial" if any(row["status"] == "partial" for row in windows) else
            "empty" if all(row["status"] == "empty" for row in windows) else "ok")
    return dict(status=status, planned_windows=len(windows), completed_windows=done,
        queried_windows=sum(row["coverage"] == "queried" for row in windows),
        coverage_limited_windows=limited, pending_windows=len(windows) - done,
        received_records=_sum_known(windows, "received_count"),
        stored_records=_sum_known(windows, "stored_count"), network_calls=network_calls,
        planned_days=sum(row["planned_days"] for row in windows),
        completed_days=sum(row["completed_days"] for row in windows),
        queried_days=sum(row["queried_days"] for row in windows),
        coverage_limited_days=sum(row["coverage_limited_days"] for row in windows),
        pending_days=sum(row["pending_days"] for row in windows),
        missing_intervals=missing, complete_history=False, windows=windows)


def read_coverage(state_dir, *, days=365, start=None, end=None, source_names=None, window_days=30, now=None):
    """Offline coverage, including old scopes; never create state/read credentials.

    Existing window keys describe the requested display partition; coverage is
    the union of successfully queried dates, not equality with persisted keys.
    Day totals count (source, date) pairs. `missing_intervals` maps each source
    to unqueried or unresolved limited date intervals. Limited dates remain
    terminal for normal resume, but are NOT queried; `complete_history` is false.
    Per-window `pending_intervals` exclude these terminal limited dates.

    Counters describe saved query snapshots, not measurements or unique rows.
    Received/stored counts are None when clipped/crossing legacy windows cannot
    be apportioned exactly. Empty means queried, never physiological zero.
    """
    now = _now(now)
    plan = plan_coverage_windows(days, start=start, end=end, window_days=window_days, now=now)
    names = _scope(source_names)
    try:
        with app.Store(state_dir) as store:
            exists = store.connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='health_history_coverage'").fetchone()
            return _view(store.connection if exists else None, plan, names, now=now,
                         status=None if exists else "not_initialized")
    except app.NotInitialized:
        return _view(None, plan, names, status="not_initialized", now=now)


def run_backfill(state_dir, headers_provider, *, days=365, start=None, end=None,
                 source_names=None, window_days=30, transport=None, storage_callback=None,
                 recover_headers=None, resume=True, max_calls=1024, max_split_depth=5, now=None):
    """Collect/resume an explicit bounded scope; stop globally on auth/error/budget.

    Activity caps split into non-overlapping calendar-day children, at most five
    levels. A capped single day (or depth exhaustion) remains coverage_limited.
    Completed empty windows are merely queried, never proof of an empty archive.
    No implicit non-auth retries. The shared sync.lock excludes live sync races.
    Resume subtracts terminal date coverage before fetching. Old finished scopes
    need neither credentials nor HTTP; any pending out-of-year day is rejected
    before credentials/HTTP. Use resume=False to retry terminal limited dates.
    """
    now = _now(now)
    plan = plan_coverage_windows(days, start=start, end=end, window_days=window_days, now=now)
    names = _scope(source_names)
    _integer(max_calls, 1, MAX_CALLS)
    _integer(max_split_depth, 0, MAX_SPLIT_DEPTH)
    if (type(resume) is not bool or not callable(headers_provider)
            or (storage_callback is not None and not callable(storage_callback))
            or (recover_headers is not None and not callable(recover_headers))):
        raise app.InvalidArguments()
    def validate_pending(view):
        for row in view["windows"]:
            for interval in row["pending_intervals"]:
                _range(interval["start_day"], interval["end_day"], now)

    if resume:
        # Old, finished scopes remain entirely offline. Only dates that still
        # need HTTP must satisfy the moving lower bound; never fetch old holes.
        initial = read_coverage(state_dir, start=plan[0][0], end=plan[-1][1],
                                source_names=names, window_days=window_days, now=now)
        if initial["pending_windows"] == 0:
            return initial
        validate_pending(initial)
    else:
        _range(plan[0][0], plan[-1][1], now, MAX_DAYS)
    writer = store_records if storage_callback is None else storage_callback
    context = dict(headers=None, calls=0, recovered=False, halt=None)
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
                return _view(None, plan, names, status="already_running", now=now)
            db = store.connection
            ensure_schema(db)
            initial = _view(db, plan, names, now=now)
            if resume and initial["pending_windows"] == 0:
                return initial
            if resume:
                validate_pending(initial)
            try:
                context["headers"] = _headers(headers_provider())
            except HeadersUnavailable:
                return _view(db, plan, names, status='auth_check_error', now=now)
            except Exception:
                context["headers"] = None
            if context["headers"] is None or _blocked(db, context["headers"]):
                return _view(db, plan, names, status="reauth_required", now=now)

            def query(source, first, last):
                if context["calls"] >= max_calls:
                    context["halt"] = "call_limit"
                    return None
                context["calls"] += 1
                result = fetch_window(context["headers"], source, first, last, transport, now=now)
                if result.status != "reauth_required":
                    return result
                before = context["headers"]["Authorization"]
                with db:
                    db.execute("INSERT OR IGNORE INTO health_history_auth_block VALUES (?,?)",
                               (_token_hash(context["headers"]), now.isoformat()))
                if (result.http_status == 401 and recover_headers is not None and not context["recovered"]
                        and context["calls"] < max_calls):
                    context["recovered"] = True
                    try:
                        recovered = recover_headers(dict(context["headers"]))
                        new = _headers(recovered.get("headers")) if type(recovered) is dict else None
                        verified = type(recovered) is dict and recovered.get("vps_auth_verified") is True and recovered.get("status", "ok") == "ok"
                    except HeadersUnavailable:
                        context['halt']='auth_check_error'
                        new, verified = None, False
                    except Exception:
                        new, verified = None, False
                    if verified and new and new["Authorization"] != before and not _blocked(db, new):
                        context["headers"] = new
                        return query(source, first, last)
                context["halt"] = context['halt'] or "reauth_required"
                return result

            def collect(source, first, last, depth=0):
                if context["halt"]:
                    return None
                previous = _row(db, source, first, last) if resume else None
                split = bool(previous and previous["status"] == "split")
                if resume:
                    current = _window_view(_rows(db, source, first, last), source, first, last, now)
                    if _completed(current):
                        return current
                    # Preserve persisted split recursion/probe budgets. For
                    # shifted unsplit windows, request only uncovered pieces.
                    if not split and current["completed_days"]:
                        for interval in current["pending_intervals"]:
                            collect(source, interval["start_day"], interval["end_day"], depth)
                            if context["halt"]:
                                break
                        return _window_view(_rows(db, source, first, last), source, first, last, now)
                if not split:
                    result = query(source, first, last)
                    if result is None:
                        return None
                    width = (_date(last) - _date(first)).days + 1
                    split = (source in ("activities","sleep") and result.status == "coverage_limited"
                             and width > 1 and depth < max_split_depth)
                    if split:
                        with db:
                            _coverage(db, source, first, last, WindowResult("split", received_count=result.received_count), now.isoformat())
                    else:
                        records = _normalized(source, result.records, first, last) if result.status in sources.SUCCESS else []
                        with db:
                            stored = writer(db, source, records) if records else 0
                            if type(stored) is not int or not 0 <= stored <= len(records):
                                raise app.StorageError()
                            _coverage(db, source, first, last, result, now.isoformat(), stored)
                        if result.status not in sources.SUCCESS:
                            context["halt"] = context['halt'] or ("reauth_required" if result.status == "reauth_required" else "collection_error")
                        return _row(db, source, first, last)
                # A persisted split is resumed directly: do not repeat its cap probe.
                middle = _date(first) + timedelta(days=(_date(last) - _date(first)).days // 2)
                left = collect(source, first, middle.isoformat(), depth + 1)
                right = collect(source, (middle + timedelta(days=1)).isoformat(), last, depth + 1)
                if not _completed(left) or not _completed(right):
                    # Persist actual child progress rather than the discarded
                    # cap probe's rows; resume/status must count saved records
                    # even when interruption occurs halfway through a split.
                    left = left or _row(db, source, first, middle.isoformat())
                    right = right or _row(db, source, (middle + timedelta(days=1)).isoformat(), last)
                    children = [row for row in (left, right) if row is not None]
                    received, stored = _sum_known(children, "received_count"), _sum_known(children, "stored_count")
                    if received is not None and stored is not None:
                        progress = WindowResult("split", received_count=received)
                        with db:
                            _coverage(db, source, first, last, progress, now.isoformat(), stored)
                    return _window_view(_rows(db, source, first, last), source, first, last, now)
                limited = left["coverage_limited"] or right["coverage_limited"]
                status = "coverage_limited" if limited else "partial" if "partial" in (left["status"], right["status"]) else (
                    "empty" if left["status"] == right["status"] == "empty" else "ok")
                received, stored = _sum_known([left, right], "received_count"), _sum_known([left, right], "stored_count")
                if received is None or stored is None:
                    return _window_view(_rows(db, source, first, last), source, first, last, now)
                aggregate = WindowResult(status, received_count=received,
                    coverage="coverage_limited" if limited else "queried")
                with db:
                    _coverage(db, source, first, last, aggregate, now.isoformat(), stored)
                return _row(db, source, first, last)

            try:
                for source in names:
                    for first, last in plan:
                        collect(source, first, last)
                        if context["halt"]:
                            break
                    if context["halt"]:
                        break
            except (app.StorageError, sqlite3.Error, OSError):
                context["halt"] = "storage_error"
            except Exception:
                context["halt"] = "storage_error"  # Callback errors are never printed or retried.
            return _view(db, plan, names, status=context["halt"], network_calls=context["calls"], now=now)
        finally:
            os.close(fd)
