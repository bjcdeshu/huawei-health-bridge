"""VO2max latestSamplePoint adapter; one measurement, never daily statistics.

The verified envelope is samplePoints["com.huawei.vo2max"] with integer
nanosecond startTime/endTime and value[{fieldName: "vo2max", integerValue: int}].
startTime is the measurement identity; endTime is retained separately. UTC
strings keep all nine fractional digits, without floating-point conversion.
The unit is deliberately None until independently confirmed by the parent.
Result.status == "ok" means a successful query, not a recent measurement. The
parent must assess data age from measured_at_ns/measured_at_utc; old but valid
points retain their original times, and missing times cannot become success.

fetch() uses the existing Result/Response contracts. Only the fixed GET below
is permitted; there is no credential discovery, retry, raw-payload persistence,
CLI, default database path, or source-state migration. ensure_schema()/upsert()
operate on a caller-owned SQLite connection and never commit its transaction.
"""
from __future__ import annotations

import json
import sqlite3
import ssl
import time
from datetime import datetime, timedelta, timezone
from urllib import error, request

from app import AUTH_KEYS, SOURCE, SQLITE_MAX_INT, _unique_object
from collector import MAX_BODY, NoRedirect, Response
from health_sources import Result

METRIC = "vo2max"
DATA_TYPE = "com.huawei.vo2max"
FIELD_NAME = "vo2max"
TIME_ZONE = "+0800"
URL = (
    "https://hihealthbase-drcn.things.dbankcloud.cn/healthrunninggroup/v1/"
    "sampleSets/latestSamplePoint?dataType=com.huawei.vo2max&timeZone=%2B0800"
)
COVERAGE = "latest_measurement"
TIMEOUT_SECONDS = 10
MAX_HEADER_BYTES = 32 * 1024
MAX_VALUE_FIELDS = 32
NS_PER_SECOND = 1_000_000_000
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
POINT_KEYS = (
    "metric", "measured_at_ns", "measured_at_utc", "end_time_ns",
    "end_time_utc", "field_name", "value", "unit", "time_zone",
)
# Keep statuses compatible with health_sources. An unknown business error is
# invalid_response/quality=business_error, never a successful empty result.
BUSINESS_KEYS = frozenset((
    "error", "errors", "errorCode", "errorMsg", "errorMessage", "code",
    "resultCode", "rtnCode", "message", "msg",
))


def _check_metric(metric):
    if type(metric) is not str or metric != METRIC:
        raise ValueError("metric_not_allowed")


def _clock(now_ns):
    value = time.time_ns() if now_ns is None else now_ns
    if type(value) is not int or not 0 < value <= SQLITE_MAX_INT:
        raise ValueError("invalid_clock")
    return value


def _valid_ns(value, now_ns):
    return type(value) is int and 0 < value <= min(now_ns, SQLITE_MAX_INT)


def ns_to_utc(value, *, now_ns=None):
    """Exact integer ns -> canonical UTC; invalid/future values return None."""
    current = _clock(now_ns)
    if not _valid_ns(value, current):
        return None
    seconds, fraction = divmod(value, NS_PER_SECOND)
    stamp = EPOCH + timedelta(seconds=seconds)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}+00:00"


def normalize_point(record, metric=METRIC, *, now_ns=None):
    """Re-whitelist normalized/database records; reject unidentifiable points.

    measured_at_ns is startTime, not collection time or a guessed day. A
    conflicting source/timestamp/field is rejected. Unconfirmed units and all
    private or aggregate fields are discarded, including fields added by callers.
    """
    _check_metric(metric)
    current = _clock(now_ns)
    if not isinstance(record, dict) or record.get("metric") != metric:
        return None
    if ("source" in record and record["source"] != SOURCE
            or record.get("field_name", FIELD_NAME) != FIELD_NAME
            or record.get("time_zone", TIME_ZONE) != TIME_ZONE):
        return None
    start, end, value = (
        record.get("measured_at_ns"), record.get("end_time_ns"), record.get("value")
    )
    if (not _valid_ns(start, current) or not _valid_ns(end, current) or end < start
            or type(value) is not int or not 0 <= value <= SQLITE_MAX_INT):
        return None
    measured = ns_to_utc(start, now_ns=current)
    ended = ns_to_utc(end, now_ns=current)
    if ("measured_at_utc" in record and record["measured_at_utc"] != measured
            or "end_time_utc" in record and record["end_time_utc"] != ended):
        return None
    return dict(
        metric=metric, measured_at_ns=start, measured_at_utc=measured,
        end_time_ns=end, end_time_utc=ended, field_name=FIELD_NAME,
        value=value, unit=None, time_zone=TIME_ZONE,
    )


def normalize_sample_point(sample, metric=METRIC, *, now_ns=None):
    """Normalize the verified wire sample; record IDs are not required."""
    _check_metric(metric)
    if not isinstance(sample, dict) or sample.get("dataTypeName") != DATA_TYPE:
        return None
    entries = sample.get("value")
    if (not isinstance(entries, list) or not 1 <= len(entries) <= MAX_VALUE_FIELDS
            or any(not isinstance(entry, dict) for entry in entries)):
        return None
    matches = [entry for entry in entries if entry.get("fieldName") == FIELD_NAME]
    if len(matches) != 1:
        return None
    entry = matches[0]
    # No guessed conversion from another numeric representation.
    if any(key in entry for key in ("floatValue", "doubleValue", "longValue", "stringValue")):
        return None
    return normalize_point(dict(
        metric=metric, measured_at_ns=sample.get("startTime"),
        end_time_ns=sample.get("endTime"), value=entry.get("integerValue"),
    ), metric, now_ns=now_ns)


def _result(status, *, quality=None, records=None, received_count=0):
    return Result(status, records=[] if records is None else records,
                  received_count=received_count, coverage=COVERAGE, quality=quality)


def _reject_constant(_value):
    raise ValueError("nonfinite_json")


def analyse(response, metric=METRIC, *, now_ns=None):
    """Classify HTTP/JSON and accept only the verified single-point envelope."""
    _check_metric(metric)
    code = getattr(response, "status", None)
    if type(code) is not int or not 100 <= code <= 599:
        return _result("invalid_response", quality="invalid_http_status")
    if code in (401, 403):
        return _result("reauth_required")
    if 300 <= code < 400:
        return _result("redirect_rejected")
    if code == 429:
        return _result("rate_limited")
    if 500 <= code <= 599:
        return _result("service_error")
    if not 200 <= code <= 299:
        return _result("http_error")
    body = getattr(response, "body", None)
    content_type = getattr(response, "content_type", None)
    if type(body) is not bytes or type(content_type) is not str:
        return _result("invalid_response", quality="invalid_http_response")
    if "html" in content_type.lower():
        return _result("reauth_required")
    if len(body) > MAX_BODY:
        return _result("invalid_response", quality="response_too_large")
    beginning = body.lstrip().lower()
    if beginning.startswith((b"<html", b"<!doctype html", b"<body")):
        return _result("reauth_required")
    try:
        raw = json.loads(body.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                         parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        return _result("invalid_response", quality="invalid_json")
    if not isinstance(raw, dict):
        return _result("invalid_response", quality="unrecognized_payload")
    # No unsupported/permission/error text is interpreted as an empty sample.
    if BUSINESS_KEYS.intersection(raw):
        return _result("invalid_response", quality="business_error")
    samples = raw.get("samplePoints")
    if not isinstance(samples, dict):
        return _result("invalid_response", quality="unrecognized_payload")
    if not samples:
        return _result("empty", quality="empty")
    if set(samples) != {DATA_TYPE}:
        return _result("invalid_response", quality="unexpected_data_type")
    point = normalize_sample_point(samples[DATA_TYPE], metric, now_ns=now_ns)
    if point is None:
        return _result("invalid_response", quality="invalid_measurement", received_count=1)
    return _result("ok", quality="ok", records=[point], received_count=1)


def check_request(method, url, body=b""):
    """Exact GET allowlist: no other endpoint, query, fragment or request body."""
    if (method != "GET" or type(url) is not str or url != URL
            or type(body) is not bytes or body != b""):
        raise ValueError("request_not_allowed")


def validate_headers(headers, *, wire=False):
    """Reject extra/header-injection/control values without exposing secrets."""
    allowed = AUTH_KEYS | {"Accept"} if wire else AUTH_KEYS
    if not isinstance(headers, dict) or set(headers) - allowed:
        raise ValueError("invalid_headers")
    for value in headers.values():
        if (type(value) is not str or not value.strip() or not value.isascii()
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError("invalid_headers")
    if any(not headers.get(key) for key in ("Authorization", "x-client-id")):
        raise ValueError("invalid_headers")
    if "Accept" in headers and headers["Accept"] != "application/json":
        raise ValueError("invalid_headers")
    if sum(len(key) + len(value) for key, value in headers.items()) > MAX_HEADER_BYTES:
        raise ValueError("invalid_headers")
    return dict(headers)


class ResponseTooLarge(ValueError):
    pass


class OfficialTransport:
    """Bounded fixed GET, verified TLS, no proxy or redirect, explicit approval."""

    def __init__(self, *, network_authorized=False):
        if network_authorized is not True:
            raise ValueError("network_not_authorized")
        self._opener = request.build_opener(
            request.ProxyHandler({}), NoRedirect(),
            request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def send(self, method, url, headers, body=b""):
        check_request(method, url, body)
        checked_headers = validate_headers(headers, wire=True)
        checked_headers["Accept"] = "application/json"
        req = request.Request(URL, headers=checked_headers, method="GET")
        try:
            response = self._opener.open(req, timeout=TIMEOUT_SECONDS)
        except error.HTTPError as exc:
            response = exc
        with response:
            content_type = response.headers.get("Content-Type", "")
            # Known status/HTML classification must not be masked by huge bodies.
            if not 200 <= response.code <= 299 or "html" in content_type.lower():
                return Response(response.code, b"", content_type)
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise ResponseTooLarge("response_too_large")
            return Response(response.code, data, content_type)


def fetch(headers, metric=METRIC, *, transport=None, now_ns=None):
    """Fetch at most one sample. No retry/auth recovery; parent owns orchestration."""
    _check_metric(metric)
    try:
        checked_headers = validate_headers(headers)
    except ValueError:
        return _result("reauth_required", quality="invalid_headers")
    check_request("GET", URL)
    try:
        transport = transport if transport is not None else OfficialTransport(network_authorized=True)
        response = transport.send("GET", URL, {**checked_headers, "Accept": "application/json"}, b"")
    except ResponseTooLarge:
        return _result("invalid_response", quality="response_too_large")
    except Exception:
        # Do not log exception strings, which can contain tokens or raw payloads.
        return _result("transport_error")
    return analyse(response, metric, now_ns=now_ns)


CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS point_measurements (
    metric TEXT NOT NULL CHECK (metric = 'vo2max'),
    measured_at_ns INTEGER NOT NULL
        CHECK (typeof(measured_at_ns) = 'integer' AND measured_at_ns > 0),
    measured_at_utc TEXT NOT NULL CHECK (measured_at_utc LIKE '%+00:00'),
    end_time_ns INTEGER NOT NULL
        CHECK (typeof(end_time_ns) = 'integer' AND end_time_ns >= measured_at_ns),
    end_time_utc TEXT NOT NULL CHECK (end_time_utc LIKE '%+00:00'),
    field_name TEXT NOT NULL CHECK (field_name = 'vo2max'),
    value INTEGER NOT NULL CHECK (typeof(value) = 'integer' AND value >= 0),
    unit TEXT CHECK (unit IS NULL),
    time_zone TEXT NOT NULL CHECK (time_zone = '+0800'),
    source TEXT NOT NULL CHECK (source = 'huawei_training_camp'),
    PRIMARY KEY (metric, measured_at_ns),
    UNIQUE (metric, measured_at_utc)
)
"""


def ensure_schema(connection: sqlite3.Connection):
    """Create only point_measurements; do not migrate existing source-state CHECKs."""
    connection.execute(CREATE_TABLE)


def upsert(connection: sqlite3.Connection, record, metric=METRIC, *, now_ns=None):
    """Insert/update one normalized point, returning 1; caller owns the transaction.

    Invalid records fail before any SQL. Other measurements are never deleted.
    Call ensure_schema() once on the existing caller-owned private connection.
    """
    point = normalize_point(record, metric, now_ns=now_ns)
    if point is None:
        raise ValueError("invalid_point")
    keys = (*POINT_KEYS, "source")
    placeholders = ", ".join("?" for _ in keys)
    updates = ", ".join(f"{key}=excluded.{key}" for key in keys
                        if key not in ("metric", "measured_at_ns"))
    connection.execute(
        f"INSERT INTO point_measurements ({', '.join(keys)}) VALUES ({placeholders}) "
        f"ON CONFLICT(metric, measured_at_ns) DO UPDATE SET {updates}",
        (*[point[key] for key in POINT_KEYS], SOURCE),
    )
    return 1
