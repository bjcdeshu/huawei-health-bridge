"""Bounded read-only activity-list and daily resting-HR/HRV adapters.

Only summary whitelists leave this module; raw responses, IDs, names and GPS
are never retained. Request/response contracts were checked against the public
reference at c4b6b5c24ea078e8e17598de732f1ce12bb4a96c; no upstream dependencies
are imported. These contracts do not prove this account's API availability.

Reference attribution (MIT):
Copyright (c) 2026 huawei-health-mcp contributors
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
from __future__ import annotations

import json
import ssl
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from urllib import error, request

import app
import collector
import sleep_collector

BASE_URL = "https://hihealthbase-drcn.things.dbankcloud.cn/healthrunninggroup/v1"
ACTIVITIES_URL = BASE_URL + "/activityRecord:query"
RESTING_HR_URL = BASE_URL + "/sampleSet/periodStatistics:calculate"
HRV_URL = BASE_URL + "/healthRecords/periodStatistics:calculate"
TIME_ZONE = "+0800"
LOCAL_ZONE = timezone(timedelta(hours=8))
STRATEGY = ["MAX", "MIN", "AVG", "SUM", "COUNT"]
METRICS = {
    "resting_hr": (RESTING_HR_URL, "com.huawei.instantaneous.resting_heart_rate", "restBpm", "bpm"),
    "hrv": (HRV_URL, "com.huawei.health.record.sleep", "avgHrv", None),
    "all_day_heart_rate": (RESTING_HR_URL, "com.huawei.instantaneous.heart_rate", "bpm", "bpm"),
    "spo2": (RESTING_HR_URL, "com.huawei.instantaneous.spo2", "spO2", "percent"),
}
REQUIRED_STATS = {"resting_hr": ("avg","min","max"), "hrv": ("avg",),
                  "all_day_heart_rate": ("min","max"), "spo2": ("avg","min","max")}
STAT_KEYS = ("avg", "min", "max", "sum", "count")
METRIC_KEYS = ("metric", "day", "time_zone", "field_name", "unit", *STAT_KEYS)
SUCCESS = frozenset(("ok", "partial", "empty", "coverage_limited"))
STATUSES = app.COLLECTION_STATUSES | {"coverage_limited"}
MAX_BODY = collector.MAX_BODY


@dataclass
class Result:
    status: str
    records: list[dict] = field(default_factory=list, repr=False)
    received_count: int = 0
    coverage: str = "bounded_window"
    quality: str | None = None
    overall: dict | None = field(default=None, repr=False)
    # Inclusive +0800 calendar dates from the actual request, never the cycle
    # clock. Rolling requests exclude partial dates; metric tails are clipped
    # by record_queried_window using queried_at_utc. None certifies no coverage.
    queried_start_day: str | None = field(default=None, repr=False)
    queried_end_day: str | None = field(default=None, repr=False)
    queried_at_utc: str | None = field(default=None, repr=False)


class ResponseTooLarge(ValueError):
    pass


def utc_now():
    return datetime.now(timezone.utc)


def bounded_int(value, maximum=30):
    if type(value) is not int or not 1 <= value <= maximum:
        raise app.InvalidArguments()
    return value


def day_string(value):
    """Only genuine calendar YYYYMMDD values; no bool/Unicode/float coercion."""
    if type(value) not in (int, str):
        return None
    text = str(value)
    if len(text) != 8 or not text.isascii() or not text.isdigit():
        return None
    try:
        return date(int(text[:4]), int(text[4:6]), int(text[6:])).isoformat()
    except ValueError:
        return None


def metric_window(days, now=None):
    bounded_int(days)
    end = (now or utc_now()).astimezone(LOCAL_ZONE).date()
    return (end - timedelta(days=days - 1)).strftime("%Y%m%d"), end.strftime("%Y%m%d")


def activity_request(days=30, limit=100, now=None):
    bounded_int(days)
    bounded_int(limit, 100)
    end = int((now or utc_now()).timestamp() * 1000)
    return dict(startTime=str(end - days * 86400000), endTime=str(end),
                limit=limit, order="endTimeDesc")


def metric_request(metric, days=7, now=None):
    if metric not in METRICS:
        raise app.InvalidArguments()
    start, end = metric_window(days, now)
    item = dict(dataType=METRICS[metric][1], startDay=start if metric == "hrv" else int(start),
                endDay=end if metric == "hrv" else int(end),
                strategy=list(STRATEGY), groupOption="day", timeZone=TIME_ZONE)
    if metric == "hrv":
        item["fieldNames"] = ["avgHrv"]
    return {"reqs": [item], "groupReqs": [dict(item)]}


def check_request(method, url, body, *, now=None):
    """There are exactly three permitted POST shapes, never detail/GPS calls."""
    if method != "POST" or url not in (ACTIVITIES_URL, RESTING_HR_URL, HRV_URL):
        raise ValueError("request_not_allowed")
    data = json.loads(body, object_pairs_hook=app._unique_object)
    if not isinstance(data, dict):
        raise ValueError("query_not_allowed")
    now = now or utc_now()
    if url == ACTIVITIES_URL:
        if (set(data) != {"startTime", "endTime", "limit", "order"}
                or type(data["limit"]) is not int or not 1 <= data["limit"] <= 100
                or data["order"] != "endTimeDesc"):
            raise ValueError("query_not_allowed")
        times = [data["startTime"], data["endTime"]]
        if any(type(t) is not str or not 1 <= len(t) <= 16 or not t.isascii() or not t.isdigit() for t in times):
            raise ValueError("invalid_time_range")
        start, end = map(int, times)
        current = int(now.timestamp() * 1000)
        if not 0 <= start < end or end - start > 30 * 86400000 or not -1000 <= current - end <= 60000:
            raise ValueError("invalid_time_range")
        return
    if (set(data) != {"reqs", "groupReqs"} or not isinstance(data["reqs"], list)
            or len(data["reqs"]) != 1 or data["groupReqs"] != data["reqs"]):
        raise ValueError("query_not_allowed")
    item = data["reqs"][0]
    if not isinstance(item,dict):raise ValueError("query_not_allowed")
    matches = [name for name,spec in METRICS.items() if url == spec[0] and item.get("dataType") == spec[1]]
    if len(matches)!=1:raise ValueError("query_not_allowed")
    metric = matches[0]
    keys = {"dataType", "startDay", "endDay", "strategy", "groupOption", "timeZone"}
    if metric == "hrv":
        keys.add("fieldNames")
    if (not isinstance(item, dict) or set(item) != keys or item["dataType"] != METRICS[metric][1]
            or item["strategy"] != STRATEGY or item["groupOption"] != "day"
            or item["timeZone"] != TIME_ZONE
            or (metric == "hrv" and item["fieldNames"] != ["avgHrv"])):
        raise ValueError("query_not_allowed")
    expected_type = str if metric == "hrv" else int
    start, end = item["startDay"], item["endDay"]
    if type(start) is not expected_type or type(end) is not expected_type:
        raise ValueError("invalid_day_type")
    start_iso, end_iso = day_string(start), day_string(end)
    if (start_iso is None or end_iso is None or end_iso != now.astimezone(LOCAL_ZONE).date().isoformat()
            or not 0 <= (date.fromisoformat(end_iso) - date.fromisoformat(start_iso)).days <= 29):
        raise ValueError("invalid_time_range")


class OfficialTransport:
    def __init__(self, *, network_authorized=False, now=None):
        if network_authorized is not True:
            raise ValueError("network_not_authorized")
        self._now = now
        self._opener = request.build_opener(request.ProxyHandler({}), collector.NoRedirect(),
                                           request.HTTPSHandler(context=ssl.create_default_context()))

    def send(self, method, url, headers, body):
        check_request(method, url, body, now=self._now)
        req = request.Request(url, data=body, headers=dict(headers), method=method)
        try:
            response = self._opener.open(req, timeout=10)
        except error.HTTPError as exc:
            response = exc
        with response:
            content_type = response.headers.get("Content-Type", "")
            # Error status and explicit login HTML already determine the result.
            # Never let an oversized error body hide a known auth failure and
            # cause later sources to send the same rejected credentials.
            if not 200 <= response.code <= 299 or "html" in content_type.lower():
                return collector.Response(response.code, b"", content_type)
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise ResponseTooLarge("response_too_large")
            return collector.Response(response.code, data, content_type)


def _decode(response):
    code = response.status
    if code in (401, 403, 301, 302, 303, 307, 308):
        return "reauth_required", None
    if 300 <= code < 400:
        return "redirect_rejected", None
    if code == 429:
        return "rate_limited", None
    if 500 <= code <= 599:
        return "service_error", None
    if not 200 <= code <= 299:
        return "http_error", None
    if ("html" in response.content_type.lower()
            or response.body.lstrip().lower().startswith((b"<html", b"<!doctype"))):
        return "reauth_required", None
    if len(response.body) > MAX_BODY:
        return "invalid_response", None
    try:
        return None, json.loads(response.body, object_pairs_hook=app._unique_object)
    except (ValueError, UnicodeError, RecursionError):
        return "invalid_response", None


def analyse_activities(response, *, limit=100, start_ms=None, end_ms=None):
    bounded_int(limit, 100)
    status, raw = _decode(response)
    if status:
        return Result(status)
    # The verified activity-list contract is a top-level array, not an error
    # object or an invented envelope. A cap hit is not complete window coverage.
    if not isinstance(raw, list) or len(raw) > limit or any(not isinstance(r, dict) for r in raw):
        return Result("invalid_response")
    if not raw:
        return Result("empty", quality="empty")
    records, partial = [], False
    for item in raw:
        out = app.normalize_summary(collector.summarize(item))
        # Use the integer millisecond timestamp contract (no unit guessing).
        out["start_time_utc"] = sleep_collector.stamp(item.get("startTime"), 1000)
        if (out["start_time_utc"] is None or out["activity_type"] is None
                or (start_ms is not None and not start_ms <= item["startTime"] <= end_ms)):
            partial = True
            continue
        partial = partial or any(value is None for value in out.values())
        records.append(out)
    quality = "partial" if partial else "ok"
    hit = len(raw) == limit
    return Result("coverage_limited" if hit else quality, records, len(raw),
                  "coverage_limited" if hit else "bounded_window", quality)


def stat_block(raw):
    values = raw if isinstance(raw, dict) else {}
    return {key: sleep_collector.integer(values.get(key)) if key == "count"
            else app._number(values.get(key)) for key in STAT_KEYS}


def normalize_metric(record, metric):
    """Apply the same whitelist on parser output and database read-back."""
    if metric not in METRICS or not isinstance(record, dict):
        return None
    day = record.get("day")
    day = day_string(day[:4] + day[5:7] + day[8:]) if (type(day) is str and len(day) == 10
        and day[4] == "-" and day[7] == "-") else None
    if day is None:
        return None
    return dict(metric=metric, day=day, time_zone=TIME_ZONE, field_name=METRICS[metric][2],
                unit=METRICS[metric][3], **stat_block(record))


def analyse_metric(response, metric, *, start_day, end_day):
    if metric not in METRICS or day_string(start_day) is None or day_string(end_day) is None:
        raise app.InvalidArguments()
    status, raw = _decode(response)
    if status:
        return Result(status)
    if (not isinstance(raw, dict) or set(raw) != {"results", "groupResults"}
            or not isinstance(raw["results"], list) or not isinstance(raw["groupResults"], list)
            or len(raw["results"]) > 100 or len(raw["groupResults"]) > 100
            or any(not isinstance(e, dict) for e in raw["results"] + raw["groupResults"])):
        return Result("invalid_response")
    expected = METRICS[metric][2]
    overall, records, seen, partial, matched = None, [], set(), False, False
    for entry in raw["results"]:
        if entry.get("fieldName") == expected and overall is None:
            overall = stat_block(entry.get("statistics"))
            if overall['count'] == 0:
                overall = {key:0 if key=='count' else None for key in STAT_KEYS}
            matched = True
            partial = overall['count'] != 0 and any(overall[k] is None for k in REQUIRED_STATS[metric])
    start_iso, end_iso = day_string(start_day), day_string(end_day)
    pending = []
    nonempty = bool(raw["results"])
    for group in raw["groupResults"]:
        entries = group.get("groupStatistics")
        if not isinstance(entries, list) or len(entries) > 1000 or any(not isinstance(e, dict) for e in entries):
            return Result("invalid_response")
        nonempty = nonempty or bool(entries)
        for entry in entries:
            if entry.get("fieldName") != expected:
                continue
            matched = True
            day = day_string(entry.get("startDay"))
            if day is None or not start_iso <= day <= end_iso:
                partial = True
                continue
            pending.append((day, entry))
    for day, entry in sorted(pending, key=lambda pair: pair[0]):
        if day in seen:
            continue  # Reference rule: first matching entry for a day wins.
        seen.add(day)
        block = stat_block(entry.get("statistics"))
        if block['count'] == 0:
            continue  # Provider zero placeholders are not measured heart/SpO2 values.
        partial = partial or any(block[k] is None for k in REQUIRED_STATS[metric])
        records.append(normalize_metric(dict(day=day, **block), metric))
    if nonempty and not matched:
        return Result("invalid_response")
    quality = "partial" if partial else "ok" if records else "empty"
    return Result(quality, records, len(pending), quality=quality, overall=overall)


def _post(headers, url, payload, transport, *, now):
    if (not isinstance(headers, dict) or set(headers) - app.AUTH_KEYS
            or any(type(v) is not str or "\r" in v or "\n" in v for v in headers.values())
            or any(not headers.get(k, "").strip() for k in ("Authorization", "x-client-id"))):
        return Result("reauth_required"), None
    body = json.dumps(payload, allow_nan=False).encode()
    check_request("POST", url, body, now=now)
    try:
        transport = transport if transport is not None else OfficialTransport(network_authorized=True, now=now)
        response = transport.send("POST", url, {**headers, "Content-Type": "application/json"}, body)
        return None, response
    except ResponseTooLarge:
        return Result("invalid_response"), None
    except Exception:
        return Result("transport_error"), None


def fetch_activities(headers, *, days=30, limit=100, transport=None):
    now = utc_now()
    payload = activity_request(days, limit, now=now)
    failure, response = _post(headers, ACTIVITIES_URL, payload, transport, now=now)
    if failure:
        return failure
    start, end = int(payload["startTime"]), int(payload["endTime"])
    result = analyse_activities(response, limit=limit, start_ms=start, end_ms=end)
    if result.status in SUCCESS:
        result.queried_start_day, result.queried_end_day, result.queried_at_utc = sleep_collector.rolling_query_window(start, end, 1000)
    return result


def fetch_metric(headers, metric, *, days=7, transport=None):
    now = utc_now()
    payload = metric_request(metric, days, now=now)
    failure, response = _post(headers, METRICS[metric][0], payload, transport, now=now)
    if failure:
        return failure
    start, end = payload["reqs"][0]["startDay"], payload["reqs"][0]["endDay"]
    result = analyse_metric(response, metric, start_day=start, end_day=end)
    if result.status in SUCCESS:
        result.queried_start_day, result.queried_end_day = day_string(start), day_string(end)
        result.queried_at_utc = now.isoformat()
    return result
