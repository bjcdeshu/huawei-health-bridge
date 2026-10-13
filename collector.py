"""Read-only Training Camp prototype. CLI is synthetic-only; no credentials loaded."""
from __future__ import annotations

import json
import math
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Mapping, Protocol
from urllib import error, request

URL = "https://hihealthbase-drcn.things.dbankcloud.cn/healthrunninggroup/v1/activityRecord:query"
MAX_BODY = 1_048_576


@dataclass(repr=False)
class Response:
    status: int
    body: bytes = field(repr=False)
    content_type: str = "application/json"


class Transport(Protocol):
    def send(self, method: str, url: str, headers: Mapping[str, str], body: bytes) -> Response: ...


def check_request(method: str, url: str, body: bytes) -> None:
    if method != "POST" or url != URL:
        raise ValueError("request_not_allowed")
    data = json.loads(body)
    if (not isinstance(data, dict) or set(data) != {"startTime", "endTime", "limit", "order"}
            or data["limit"] != 1 or isinstance(data["limit"], bool)
            or data["order"] != "endTimeDesc"):
        raise ValueError("query_not_allowed")
    times = [data["startTime"], data["endTime"]]
    if any(not isinstance(t, str) or not t.isascii() or not t.isdigit() for t in times):
        raise ValueError("invalid_time_range")
    start, end = map(int, times)
    if not 0 <= start < end or end - start > 30 * 86400 * 1000:
        raise ValueError("invalid_time_range")


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Reject every redirect, including same-origin redirects.

    def http_error_302(self, req, fp, code, msg, headers):
        raise error.HTTPError(req.full_url, code, "redirect_rejected", headers, fp)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


class OfficialTransport:
    """Dormant network adapter; construction requires explicit future approval."""
    def __init__(self, *, network_authorized: bool = False):
        if not network_authorized:
            raise ValueError("network_not_authorized")
        self._opener = request.build_opener(
            request.ProxyHandler({}), NoRedirect(),
            request.HTTPSHandler(context=ssl.create_default_context()))

    def send(self, method, url, headers, body):
        check_request(method, url, body)
        req = request.Request(URL, data=body, headers=dict(headers), method="POST")
        try:
            response = self._opener.open(req, timeout=10)
        except error.HTTPError as exc:
            response = exc
        with response:
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise ValueError("response_too_large")
            return Response(response.code, data, response.headers.get("Content-Type", ""))


class MockTransport:
    """No network, no header/body retention; fixtures must be synthetic."""
    def __init__(self, response: Response):
        self._response = response
        self.calls = 0

    def send(self, method, url, headers, body):
        check_request(method, url, body)
        self.calls += 1
        return self._response


@dataclass
class Result:
    status: str
    summary: dict | None = field(default=None, repr=False)


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return value if math.isfinite(value) and value >= 0 else None
    except OverflowError:
        return None


def summarize(record):
    start = number(record.get("startTime"))
    try:
        timestamp = datetime.fromtimestamp(start / 1000, timezone.utc).isoformat() if start is not None else None
    except (ValueError, OverflowError, OSError):
        timestamp = None
    activity = record.get("activitySummary")
    activity = activity if isinstance(activity, dict) else {}
    data = activity.get("dataSummary", {})
    distance = None
    if isinstance(data, dict):
        entry = data.get("com.huawei.continuous.distance.total", {})
    elif isinstance(data, list):
        entry = next((e for e in data if isinstance(e, dict) and e.get("dataTypeName") == "com.huawei.continuous.distance.total"), {})
    else:
        entry = {}
    values = entry.get("value", []) if isinstance(entry, dict) else []
    for value in values if isinstance(values, list) else []:
        if isinstance(value, dict) and value.get("fieldName") == "distance":
            for key in ("floatValue", "integerValue", "longValue", "doubleValue"):
                if key in value:
                    distance = number(value[key])
                    break
    perf = activity.get("performanceSummary", {})
    kind = record.get("activityType")
    return {"start_time_utc": timestamp,
            "activity_type": kind if type(kind) in (int, str) else None,
            "duration_ms": number(record.get("activeTime")),
            "distance_m": distance,
            "training_load": number(perf.get("aerobicTrainingStress")) if isinstance(perf, dict) else None}


def latest(transport: Transport, start_ms: str, end_ms: str,
           auth_provider: Callable[[], Mapping[str, str]] | None = None,
           *, dry_run: bool = True) -> Result:
    """Return an in-memory summary only. No logging, persistence, refresh or retries."""
    body = json.dumps(dict(startTime=start_ms, endTime=end_ms, limit=1, order="endTimeDesc")).encode()
    check_request("POST", URL, body)
    if dry_run and type(transport) is not MockTransport:
        return Result("dry_run_only")
    headers = {"Content-Type": "application/json"}
    if not dry_run:
        if auth_provider is None:
            return Result("reauth_required")
        try:
            supplied = dict(auth_provider())
            if (set(supplied) - {"Authorization", "x-client-id", "x-version", "Cookie"}
                    or not all(supplied.get(k) for k in ("Authorization", "x-client-id"))
                    or any(not isinstance(v, str) or "\r" in v or "\n" in v for v in supplied.values())):
                return Result("reauth_required")
            headers.update(supplied)
        except Exception:
            return Result("reauth_required")
    try:
        response = transport.send("POST", URL, headers, body)
    except Exception:
        return Result("transport_error")  # Never expose exception text/credentials.
    if response.status in (401, 403) or "text/html" in response.content_type.lower():
        return Result("reauth_required")
    if 300 <= response.status < 400:
        return Result("reauth_required" if response.status in (301, 302, 303, 307, 308) else "redirect_rejected")
    if response.status == 429:
        return Result("rate_limited")
    if 500 <= response.status <= 599:
        return Result("service_error")
    if not 200 <= response.status < 300:
        return Result("http_error")
    try:
        if len(response.body) > MAX_BODY:
            return Result("invalid_response")
        records = json.loads(response.body)
    except (ValueError, UnicodeError):
        return Result("invalid_response")
    if not isinstance(records, list) or len(records) > 1 or any(not isinstance(r, dict) for r in records):
        return Result("invalid_response")
    if not records:
        return Result("empty")
    summary = summarize(records[0])
    return Result("partial" if any(v is None for v in summary.values()) else "ok", summary)


def synthetic_response():
    return Response(200, json.dumps([{
        "startTime": 1700000000000, "activityType": 56, "activeTime": 1800000,
        "activitySummary": {
            "dataSummary": {"com.huawei.continuous.distance.total": {
                "value": [{"fieldName": "distance", "floatValue": 5000}]}},
            "performanceSummary": {"aerobicTrainingStress": 30}}}]).encode())


if __name__ == "__main__":
    result = latest(MockTransport(synthetic_response()), "1699000000000", "1700100000000")
    print(json.dumps({"mode": "dry-run", "source": "synthetic", "status": result.status, "summary": result.summary}))
