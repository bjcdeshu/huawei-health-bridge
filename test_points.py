"""Synthetic-only VO2max tests: explicit TMPDIR, blocked live IO/network.

No production credentials, browser, database, real response or health reading is
used. Every test has its own TemporaryDirectory(dir=os.environ['TMPDIR']). A
swallowed isolation violation still fails tearDown. Only test_points is exercised
here; whole-suite integration/deployment remains with the parent.
"""
import builtins
import contextlib
import http.client
import io
import json
import os
import socket
import sqlite3
import ssl
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch
from urllib import error, request
from urllib.parse import unquote

import health_points as hp
from health_sources import Result


# Entirely invented test clock/payload, not dates or values copied from an account.
def epoch_ns(stamp):
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


NOW_NS = epoch_ns(datetime(2024, 3, 5, 12, 0, tzinfo=timezone.utc)) + 987654321
START_NS = epoch_ns(datetime(2024, 2, 3, 4, 5, 6, tzinfo=timezone.utc)) + 123456789
END_NS = START_NS + 98765
AUTH = {"Authorization": "SYNTHETIC_POINTS_TOKEN", "x-client-id": "SYNTHETIC_POINTS_CLIENT"}
MARKER = "SYNTHETIC_PRIVATE_NAME_ID_GPS_RAW_NEVER_STORE"


def sample(**changes):
    return {
        "startTime": START_NS, "endTime": END_NS, "dataTypeName": "com.huawei.vo2max",
        "value": [{"fieldName": "vo2max", "integerValue": 137}], **changes,
    }


def envelope(point=None):
    return {"samplePoints": {"com.huawei.vo2max": sample() if point is None else point}}


def response(raw, code=200, content_type="application/json"):
    return hp.Response(code, json.dumps(raw, allow_nan=False).encode(), content_type)


class FakeTransport:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def send(self, method, url, headers, body):
        hp.check_request(method, url, body)
        hp.validate_headers(headers, wire=True)
        # Retain no synthetic credential values, consistent with the real adapter.
        self.calls.append((method, url, body, set(headers)))
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class PointTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(os.path.abspath(os.environ["TMPDIR"]))
        if str(scratch).startswith("/var/lib/huawei-training-camp"):
            self.fail("production_tmpdir_forbidden")
        if str(scratch.resolve()).startswith("/var/lib/huawei-training-camp"):
            self.fail("production_tmpdir_forbidden")
        self.temp = tempfile.TemporaryDirectory(prefix="vo2max-point-tests-", dir=os.environ["TMPDIR"])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.violations = []
        original_open, original_io_open = builtins.open, io.open
        original_os_open, original_connect = os.open, sqlite3.connect
        original_stat, original_lstat = os.stat, os.lstat

        def reject(label):
            self.violations.append(label)
            raise AssertionError(label)

        def path_text(path):
            return os.fsdecode(os.fspath(path))

        def check_path(path, *, dir_fd=None):
            if type(path) is int:
                # Already-open descriptors are not new path reads.
                return
            text = path_text(path)
            if text.startswith("file:"):
                text = unquote(text[5:].split("?", 1)[0])
            if dir_fd is not None:
                text = os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), text)
            candidate = Path(os.path.abspath(text))
            if str(candidate).startswith("/var/lib/huawei-training-camp"):
                reject("production_path_forbidden")
            # No project/.env reads or unrelated file writes either.
            if not candidate.is_relative_to(self.root):
                reject("path_outside_this_test")
            if not candidate.resolve().is_relative_to(self.root):
                reject("path_outside_this_test")

        def guarded_open(path, *args, **kwargs):
            check_path(path)
            return original_open(path, *args, **kwargs)

        def guarded_io_open(path, *args, **kwargs):
            check_path(path)
            return original_io_open(path, *args, **kwargs)

        def guarded_os_open(path, flags, mode=0o777, *, dir_fd=None):
            check_path(path, dir_fd=dir_fd)
            return original_os_open(path, flags, mode, dir_fd=dir_fd)

        def guarded_connect(path, *args, **kwargs):
            check_path(path)
            return original_connect(path, *args, **kwargs)

        def guarded_metadata(original, path, *args, **kwargs):
            if type(path) is not int:
                text = path_text(path)
                if kwargs.get("dir_fd") is not None:
                    text = os.path.join(os.readlink(f"/proc/self/fd/{kwargs['dir_fd']}"), text)
                if os.path.abspath(text).startswith("/var/lib/huawei-training-camp"):
                    reject("production_metadata_forbidden")
            return original(path, *args, **kwargs)

        for guard in (
            patch.object(builtins, "open", side_effect=guarded_open),
            patch.object(io, "open", side_effect=guarded_io_open),
            patch.object(os, "open", side_effect=guarded_os_open),
            patch.object(sqlite3, "connect", side_effect=guarded_connect),
            patch.object(os, "stat", side_effect=lambda *a, **k: guarded_metadata(original_stat, *a, **k)),
            patch.object(os, "lstat", side_effect=lambda *a, **k: guarded_metadata(original_lstat, *a, **k)),
            patch.object(hp.time, "time_ns", return_value=NOW_NS),
            patch.object(request.OpenerDirector, "open", side_effect=lambda *a, **k: reject("real_http_forbidden")),
            patch.object(request, "urlopen", side_effect=lambda *a, **k: reject("real_http_forbidden")),
            patch.object(http.client.HTTPConnection, "request", side_effect=lambda *a, **k: reject("real_http_forbidden")),
            patch.object(socket, "create_connection", side_effect=lambda *a, **k: reject("real_socket_forbidden")),
            patch.object(socket.socket, "connect", side_effect=lambda *a, **k: reject("real_socket_forbidden")),
        ):
            guard.start()
            self.addCleanup(guard.stop)

    def tearDown(self):
        self.assertEqual(self.violations, [], "a caught/suppressed isolation violation occurred")

    def database(self):
        connection = sqlite3.connect(self.root / "synthetic-points.sqlite3")
        self.addCleanup(connection.close)
        return connection

    def normalized(self, **changes):
        point = hp.normalize_sample_point(sample())
        self.assertIsNotNone(point)
        return {**point, **changes}

    def fake_opener(self, body=None, code=200, content_type="application/json"):
        handle = Mock()
        handle.code = code
        handle.headers = {"Content-Type": content_type}
        handle.read.return_value = response(envelope()).body if body is None else body
        handle.__enter__ = Mock(return_value=handle)
        handle.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = handle
        return opener, handle

    def test_isolation_guards_block_production_files_database_and_http(self):
        probes = (
            lambda: builtins.open("/var/lib/huawei-training-camp/auth.json"),
            lambda: Path("/var/lib/huawei-training-camp-browser/cookies.json").read_bytes(),
            lambda: os.open("/var/lib/huawei-training-camp-future/auth.json", os.O_RDONLY),
            lambda: sqlite3.connect("/var/lib/huawei-training-camp/health.sqlite3"),
            lambda: os.stat("/var/lib/huawei-training-camp/auth.json"),
            lambda: builtins.open("/srv/agent-workspace/huawei-training-camp/.env"),
            lambda: request.urlopen("https://example.invalid/synthetic"),
            lambda: socket.create_connection(("example.invalid", 443)),
        )
        for index, probe in enumerate(probes):
            with self.assertRaises(AssertionError):
                probe()
            self.assertEqual(len(self.violations), index + 1)
        # These intentional guard probes never reached any actual IO.
        self.violations.clear()

    def test_verified_envelope_no_record_id_and_result_compatibility(self):
        result = hp.analyse(response(envelope()))
        self.assertIsInstance(result, Result)
        self.assertEqual((result.status, result.quality, result.coverage, result.received_count),
                         ("ok", "ok", "latest_measurement", 1))
        self.assertEqual(len(result.records), 1)
        point = result.records[0]
        self.assertEqual(point["metric"], "vo2max")
        self.assertEqual(point["field_name"], "vo2max")
        self.assertEqual(point["value"], 137)
        self.assertNotIn("id", point)
        self.assertEqual(set(point), set(hp.POINT_KEYS))
        self.assertIsNone(result.overall)

    def test_integer_nanoseconds_keep_all_precision_in_utc(self):
        point = hp.analyse(response(envelope())).records[0]
        self.assertEqual(point["measured_at_ns"], START_NS)
        self.assertEqual(point["end_time_ns"], END_NS)
        self.assertEqual(point["measured_at_utc"], "2024-02-03T04:05:06.123456789+00:00")
        end_fraction = 123456789 + 98765
        self.assertEqual(point["end_time_utc"], f"2024-02-03T04:05:06.{end_fraction:09d}+00:00")
        self.assertEqual(point["time_zone"], "+0800")

    def test_subsecond_and_exact_second_times_do_not_round(self):
        whole = START_NS - START_NS % hp.NS_PER_SECOND
        self.assertEqual(hp.ns_to_utc(whole), "2024-02-03T04:05:06.000000000+00:00")
        self.assertEqual(hp.ns_to_utc(whole + 1), "2024-02-03T04:05:06.000000001+00:00")
        self.assertEqual(hp.ns_to_utc(whole + 999999999), "2024-02-03T04:05:06.999999999+00:00")
        self.assertEqual(hp.ns_to_utc(1), "1970-01-01T00:00:00.000000001+00:00")

    def test_old_measurement_query_success_does_not_make_measurement_recent(self):
        result = hp.fetch(AUTH, transport=FakeTransport(response(envelope())))
        self.assertEqual(result.status, "ok")  # Successful read, not an age assertion.
        point = result.records[0]
        self.assertGreater(NOW_NS - point["measured_at_ns"], 30 * 86400 * hp.NS_PER_SECOND)
        self.assertEqual(point["measured_at_ns"], START_NS)
        self.assertNotEqual(point["measured_at_utc"], hp.ns_to_utc(NOW_NS))
        self.assertNotIn("freshness", point)
        self.assertNotIn("fresh", repr(result))

    def test_missing_or_null_unit_stays_none(self):
        for change in ({}, {"unit": None}, {"unit": "UNCONFIRMED_SYNTHETIC_UNIT"}):
            with self.subTest(change=change):
                result = hp.analyse(response(envelope(sample(**change))))
                self.assertEqual(result.status, "ok")
                self.assertIsNone(result.records[0]["unit"])
        wire = sample(value=[{"fieldName": "vo2max", "integerValue": 137, "unit": "UNVERIFIED"}])
        self.assertIsNone(hp.normalize_sample_point(wire)["unit"])
        self.assertIsNone(hp.normalize_point(self.normalized(unit="UNVERIFIED"))["unit"])

    def test_invalid_boolean_nonfinite_and_future_timestamps_rejected(self):
        invalid = (None, True, False, "123", START_NS / hp.NS_PER_SECOND,
                   float("nan"), float("inf"), -float("inf"), 0, -1,
                   hp.SQLITE_MAX_INT + 1, NOW_NS + 1)
        for key in ("startTime", "endTime"):
            for value in invalid:
                with self.subTest(key=key, value_type=type(value).__name__):
                    self.assertIsNone(hp.normalize_sample_point(sample(**{key: value})))
                    self.assertIsNone(hp.ns_to_utc(value))

    def test_missing_timestamps_never_return_fresh_or_successful_empty(self):
        for key in ("startTime", "endTime"):
            for remove in (True, False):
                wire = sample()
                if remove:
                    wire.pop(key)
                else:
                    wire[key] = None
                result = hp.analyse(response(envelope(wire)))
                self.assertEqual((result.status, result.quality, result.received_count),
                                 ("invalid_response", "invalid_measurement", 1))
                self.assertEqual(result.records, [])
                self.assertNotIn(result.status, ("ok", "partial", "empty"))

    def test_time_order_and_future_end_time_are_rejected(self):
        for wire in (sample(endTime=START_NS - 1), sample(endTime=NOW_NS + 1),
                     sample(startTime=NOW_NS + 1, endTime=NOW_NS + 1)):
            self.assertEqual(hp.analyse(response(envelope(wire))).status, "invalid_response")
        self.assertEqual(hp.analyse(response(envelope(sample(endTime=START_NS)))).status, "ok")

    def test_explicit_clock_must_be_a_valid_integer_not_boolean(self):
        for clock in (True, "123", 0, -1, float("inf"), hp.SQLITE_MAX_INT + 1):
            with self.assertRaisesRegex(ValueError, "invalid_clock"):
                hp.ns_to_utc(START_NS, now_ns=clock)
        self.assertEqual(hp.ns_to_utc(START_NS, now_ns=START_NS),
                         "2024-02-03T04:05:06.123456789+00:00")
        self.assertIsNone(hp.ns_to_utc(START_NS, now_ns=START_NS - 1))

    def test_only_verified_integer_value_contract_is_accepted(self):
        invalid = (None, True, False, "137", 137.0, -1, float("nan"),
                   float("inf"), -float("inf"), hp.SQLITE_MAX_INT + 1)
        for value in invalid:
            with self.subTest(value_type=type(value).__name__):
                self.assertIsNone(hp.normalize_sample_point(sample(
                    value=[{"fieldName": "vo2max", "integerValue": value}])))
        # An explicitly returned integer zero is not a fabricated missing value.
        self.assertEqual(hp.normalize_sample_point(sample(
            value=[{"fieldName": "vo2max", "integerValue": 0}]))["value"], 0)

    def test_missing_value_or_alternative_numeric_representation_not_guessed(self):
        entries = ({"fieldName": "vo2max"}, {"fieldName": "vo2max", "floatValue": 137.0},
                   {"fieldName": "vo2max", "integerValue": 137, "longValue": 137})
        for entry in entries:
            self.assertEqual(hp.analyse(response(envelope(sample(value=[entry])))).status, "invalid_response")

    def test_wrong_dtype_field_duplicates_and_value_structure_rejected(self):
        wires = (
            sample(dataTypeName="com.huawei.vo2max.other"), sample(dataTypeName=None),
            sample(value=[{"fieldName": "other", "integerValue": 137}]),
            sample(value=[{"fieldName": "vo2max", "integerValue": 137}] * 2),
            sample(value=[]), sample(value=None), sample(value={}), sample(value=[None]),
            sample(value=[{}] * (hp.MAX_VALUE_FIELDS + 1)),
        )
        for wire in wires:
            self.assertEqual(hp.analyse(response(envelope(wire))).status, "invalid_response")
        wire = sample()
        wire.pop("dataTypeName")
        self.assertIsNone(hp.normalize_sample_point(wire))

    def test_only_explicit_empty_samplepoints_is_empty(self):
        result = hp.analyse(response({"samplePoints": {}}))
        self.assertEqual((result.status, result.quality, result.received_count, result.records),
                         ("empty", "empty", 0, []))
        for raw in ({}, {"samplePoints": None}, {"samplePoints": []},
                    {"samplePoints": {"com.huawei.vo2max": None}},
                    {"samplePoints": {"com.huawei.vo2max": {}}}, [], None):
            result = hp.analyse(response(raw))
            self.assertEqual(result.status, "invalid_response")
            self.assertEqual(result.records, [])

    def test_unknown_json_and_business_errors_are_distinct_from_empty(self):
        business = (
            {"error": "SYNTHETIC_UNKNOWN_BUSINESS_ERROR"},
            {"errorCode": "SYNTHETIC_UNKNOWN_CODE", "errorMsg": MARKER},
            {"code": 99, "message": MARKER, "samplePoints": {}},
            {"samplePoints": {}, "resultCode": "UNKNOWN_SYNTHETIC_RESULT"},
        )
        for raw in business:
            result = hp.analyse(response(raw))
            self.assertEqual((result.status, result.quality), ("invalid_response", "business_error"))
            self.assertEqual(result.records, [])
            self.assertNotIn(MARKER, repr(result))
        result = hp.analyse(response({"unknown": []}))
        self.assertEqual((result.status, result.quality), ("invalid_response", "unrecognized_payload"))

    def test_unapproved_response_data_types_not_partially_accepted(self):
        for samples in ({"com.huawei.other": sample()},
                        {"com.huawei.vo2max": sample(), "com.huawei.other": sample()}):
            result = hp.analyse(response({"samplePoints": samples}))
            self.assertEqual((result.status, result.quality, result.records),
                             ("invalid_response", "unexpected_data_type", []))

    def test_invalid_duplicate_nonfinite_and_non_utf8_json_rejected(self):
        bodies = (b"not-json", b'{"samplePoints":{},"samplePoints":{}}',
                  b'{"samplePoints":{},"raw":NaN}', b'{"raw":Infinity}',
                  b'{"raw":-Infinity}', b'\xff', b'{"samplePoints":{}}'.decode().encode("utf-16"))
        for body in bodies:
            result = hp.analyse(hp.Response(200, body))
            self.assertEqual((result.status, result.quality), ("invalid_response", "invalid_json"))
        raw = response(envelope()).body.replace(b'"integerValue": 137',
                                                b'"integerValue": 137, "integerValue": 138')
        self.assertEqual(hp.analyse(hp.Response(200, raw)).status, "invalid_response")

    def test_http_auth_redirect_rate_limit_service_and_other_errors(self):
        cases = ((401, "reauth_required"), (403, "reauth_required"),
                 (301, "redirect_rejected"), (302, "redirect_rejected"),
                 (303, "redirect_rejected"), (304, "redirect_rejected"),
                 (307, "redirect_rejected"), (308, "redirect_rejected"),
                 (429, "rate_limited"), (500, "service_error"), (503, "service_error"),
                 (400, "http_error"), (404, "http_error"))
        for code, expected in cases:
            result = hp.analyse(hp.Response(code, b"x" * (hp.MAX_BODY + 1)))
            self.assertEqual(result.status, expected)
            self.assertEqual(result.records, [])

    def test_html_login_mime_and_body_are_auth_failure(self):
        responses = (hp.Response(200, b"", "text/html; charset=utf-8"),
                     hp.Response(200, b"  <HTML>synthetic login</HTML>"),
                     hp.Response(200, b"\n<!doctype html><html>synthetic</html>"),
                     hp.Response(200, b"<body>synthetic login</body>", "text/plain"))
        for value in responses:
            self.assertEqual(hp.analyse(value).status, "reauth_required")

    def test_oversized_or_malformed_response_not_empty(self):
        self.assertEqual(hp.analyse(hp.Response(200, b"x" * (hp.MAX_BODY + 1))).quality,
                         "response_too_large")
        for item in (hp.Response(True, b"{}"), hp.Response(99, b"{}"),
                     hp.Response(600, b"{}"), hp.Response(200, "{}"),
                     hp.Response(200, b"{}", None), None):
            self.assertEqual(hp.analyse(item).status, "invalid_response")

    def test_privacy_and_aggregate_fields_are_stripped(self):
        wire = sample(id=MARKER, name=MARKER, gps=MARKER, raw={"cookie": MARKER},
                      avg=99, min=1, max=999, count=7, day="SYNTHETIC_DAY")
        wire["value"][0].update(id=MARKER, gps=MARKER, raw=MARKER)
        wire["value"].append({"fieldName": "SYNTHETIC_PRIVATE_FIELD", "stringValue": MARKER})
        raw = {**envelope(wire), "id": MARKER, "raw": MARKER}
        result = hp.analyse(response(raw))
        self.assertEqual(result.status, "ok")
        self.assertEqual(set(result.records[0]), set(hp.POINT_KEYS))
        self.assertNotIn(MARKER, repr(result.records))
        for key in ("day", "avg", "min", "max", "sum", "count", "id", "gps", "raw"):
            self.assertNotIn(key, result.records[0])
        point = hp.normalize_point({**result.records[0], "raw": MARKER, "gps": MARKER})
        self.assertEqual(point, result.records[0])
        self.assertNotIn("137", repr(result))
        self.assertNotIn("2024", repr(result))

    def test_request_allowlist_is_exact_fixed_get_query_and_empty_body(self):
        hp.check_request("GET", hp.URL)
        rejected = (
            ("POST", hp.URL, b""), ("HEAD", hp.URL, b""), ("get", hp.URL, b""),
            ("GET", hp.URL.replace("https://", "http://"), b""),
            ("GET", hp.URL.replace("com.huawei.vo2max", "com.huawei.other"), b""),
            ("GET", hp.URL.replace("%2B0800", "%2B0000"), b""),
            ("GET", hp.URL.replace("%2B0800", "+0800"), b""),
            ("GET", hp.URL + "&dataType=com.huawei.vo2max", b""),
            ("GET", hp.URL + "&details=true", b""), ("GET", hp.URL + "#fragment", b""),
            ("GET", hp.URL.replace("sampleSets", "sampleSet"), b""),
            ("GET", hp.URL.replace("https://", "https://evil.invalid@"), b""),
            ("GET", "https://example.invalid/", b""), ("GET", hp.URL, b"{}"),
            ("GET", hp.URL, None), ("GET", hp.URL, bytearray()),
        )
        for method, url, body in rejected:
            with self.assertRaisesRegex(ValueError, "request_not_allowed"):
                hp.check_request(method, url, body)

    def test_fetch_uses_one_fixed_get_no_body_and_shared_result(self):
        transport = FakeTransport(response(envelope()))
        with patch.object(hp, "OfficialTransport") as factory:
            result = hp.fetch(AUTH, transport=transport)
            factory.assert_not_called()
        self.assertEqual(result.status, "ok")
        self.assertEqual(transport.calls, [("GET", hp.URL, b"", {*AUTH, "Accept"})])
        self.assertIsInstance(result, Result)

    def test_other_metrics_rejected_before_any_transport(self):
        transport = FakeTransport(response(envelope()))
        with patch.object(hp, "OfficialTransport") as factory:
            for metric in ("steps", "athletic_assessment", "com.huawei.vo2max", "VO2max", True, None):
                for call in (lambda: hp.fetch(AUTH, metric, transport=transport),
                             lambda: hp.analyse(response(envelope()), metric),
                             lambda: hp.normalize_sample_point(sample(), metric)):
                    with self.assertRaisesRegex(ValueError, "metric_not_allowed"):
                        call()
            factory.assert_not_called()
        self.assertEqual(transport.calls, [])

    def test_invalid_headers_rejected_without_network_or_secret_echo(self):
        cases = (None, [], {}, {"Authorization": AUTH["Authorization"]},
                 {**AUTH, "Host": "example.invalid"}, {**AUTH, "Accept": "application/json"},
                 {**AUTH, "Cookie": "SYNTHETIC\r\nHost: evil.invalid"},
                 {**AUTH, "x-client-id": True}, {**AUTH, "x-client-id": ""},
                 {**AUTH, "Authorization": "   "}, {**AUTH, "Cookie": "bad\x00"},
                 {**AUTH, "Cookie": "bad\t"}, {**AUTH, "Cookie": "bad\x7f"},
                 {**AUTH, "Cookie": "非ASCII"},
                 {**AUTH, "Authorization": "x" * (hp.MAX_HEADER_BYTES + 1)})
        for headers in cases:
            transport = FakeTransport(response(envelope()))
            with patch.object(hp, "OfficialTransport") as factory:
                result = hp.fetch(headers, transport=transport)
                self.assertEqual((result.status, result.quality), ("reauth_required", "invalid_headers"))
                self.assertEqual(transport.calls, [])
                factory.assert_not_called()
                self.assertNotIn(AUTH["Authorization"], repr(result))

    def test_optional_authorized_headers_not_mutated(self):
        headers = {**AUTH, "Cookie": "SYNTHETIC_COOKIE", "x-version": "SYNTHETIC_VERSION"}
        before = dict(headers)
        transport = FakeTransport(response(envelope()))
        self.assertEqual(hp.fetch(headers, transport=transport).status, "ok")
        self.assertEqual(headers, before)
        self.assertEqual(transport.calls[0][3], {*headers, "Accept"})

    def test_all_errors_are_one_attempt_without_retry_or_raw_exception_output(self):
        outcomes = ((response({}, 401), "reauth_required"),
                    (response({}, 429), "rate_limited"), (response({}, 503), "service_error"),
                    (response({}), "invalid_response"),
                    (RuntimeError(MARKER + AUTH["Authorization"]), "transport_error"),
                    (hp.ResponseTooLarge(MARKER), "invalid_response"))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            for outcome, expected in outcomes:
                transport = FakeTransport(outcome)
                result = hp.fetch(AUTH, transport=transport)
                self.assertEqual(result.status, expected)
                self.assertEqual(len(transport.calls), 1)
                self.assertNotIn(MARKER, repr(result))
                self.assertNotIn(AUTH["Authorization"], repr(result))
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))

    def test_default_transport_path_is_exercised_only_with_mock(self):
        transport = FakeTransport(response(envelope()))
        with patch.object(hp, "OfficialTransport", return_value=transport) as factory:
            self.assertEqual(hp.fetch(AUTH).status, "ok")
            factory.assert_called_once_with(network_authorized=True)
        self.assertEqual(len(transport.calls), 1)

    def test_official_transport_tls_proxy_redirect_timeout_and_read_cap(self):
        opener, handle = self.fake_opener()
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://example.invalid:9"}), \
                patch.object(request, "build_opener", return_value=opener) as factory:
            transport = hp.OfficialTransport(network_authorized=True)
            handlers = factory.call_args.args
            https = next(item for item in handlers if isinstance(item, request.HTTPSHandler))
            self.assertTrue(https._context.check_hostname)
            self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(next(item for item in handlers if isinstance(item, request.ProxyHandler)).proxies, {})
            self.assertTrue(any(isinstance(item, hp.NoRedirect) for item in handlers))
            self.assertEqual(hp.fetch(AUTH, transport=transport).status, "ok")
            req = opener.open.call_args.args[0]
            self.assertEqual((req.get_method(), req.full_url, req.data), ("GET", hp.URL, None))
            self.assertEqual(req.get_header("Accept"), "application/json")
            self.assertEqual(opener.open.call_args.kwargs, {"timeout": 10})
            handle.read.assert_called_once_with(hp.MAX_BODY + 1)

    def test_transport_construction_needs_explicit_boolean_authorization(self):
        with patch.object(request, "build_opener") as factory:
            for authorized in (False, None, 1, "yes"):
                with self.assertRaisesRegex(ValueError, "network_not_authorized"):
                    hp.OfficialTransport(network_authorized=authorized)
            factory.assert_not_called()

    def test_transport_rechecks_url_headers_and_body_before_opener(self):
        opener, _handle = self.fake_opener()
        with patch.object(request, "build_opener", return_value=opener):
            transport = hp.OfficialTransport(network_authorized=True)
            for args in (("POST", hp.URL, AUTH, b""),
                         ("GET", hp.URL + "&other=x", AUTH, b""),
                         ("GET", hp.URL, AUTH, b"{}"),
                         ("GET", hp.URL, {**AUTH, "Host": "evil.invalid"}, b""),
                         ("GET", hp.URL, {**AUTH, "Accept": "text/html"}, b"")):
                with self.assertRaises(ValueError):
                    transport.send(*args)
            opener.open.assert_not_called()

    def test_transport_body_cap_failure_does_not_retry(self):
        opener, handle = self.fake_opener(body=b"x" * (hp.MAX_BODY + 1))
        with patch.object(request, "build_opener", return_value=opener):
            result = hp.fetch(AUTH, transport=hp.OfficialTransport(network_authorized=True))
        self.assertEqual((result.status, result.quality), ("invalid_response", "response_too_large"))
        opener.open.assert_called_once()
        handle.read.assert_called_once_with(hp.MAX_BODY + 1)

    def test_transport_known_status_or_html_skips_response_body(self):
        for code, mime, expected in ((401, "application/json", "reauth_required"),
                                     (403, "application/json", "reauth_required"),
                                     (302, "text/html", "redirect_rejected"),
                                     (429, "application/json", "rate_limited"),
                                     (503, "application/json", "service_error"),
                                     (200, "text/html", "reauth_required")):
            opener, handle = self.fake_opener(code=code, content_type=mime)
            handle.read.side_effect = AssertionError("known_error_body_must_not_be_read")
            with patch.object(request, "build_opener", return_value=opener):
                result = hp.fetch(AUTH, transport=hp.OfficialTransport(network_authorized=True))
            self.assertEqual(result.status, expected)
            handle.read.assert_not_called()
            opener.open.assert_called_once()

    def test_http_error_object_is_classified_and_closed_without_body_read(self):
        failure = error.HTTPError(hp.URL, 401, MARKER, {"Content-Type": "application/json"}, io.BytesIO(b"synthetic"))
        failure.read = Mock(side_effect=AssertionError("auth_body_must_not_be_read"))
        opener = Mock()
        opener.open.side_effect = failure
        with patch.object(request, "build_opener", return_value=opener):
            result = hp.fetch(AUTH, transport=hp.OfficialTransport(network_authorized=True))
        self.assertEqual(result.status, "reauth_required")
        failure.read.assert_not_called()
        self.assertTrue(failure.closed)

    def test_redirect_handler_rejects_same_and_other_origin(self):
        handler = hp.NoRedirect()
        req = request.Request(hp.URL)
        for target in (hp.URL, "https://example.invalid/login"):
            self.assertIsNone(handler.redirect_request(req, None, 302, "synthetic", {}, target))
        with self.assertRaises(error.HTTPError):
            handler.http_error_302(req, io.BytesIO(b"synthetic"), 302, "synthetic", {})

    def test_schema_whitelist_and_source_check_do_not_migrate_main_schema(self):
        connection = self.database()
        connection.execute("""CREATE TABLE health_source_state (
            source TEXT PRIMARY KEY CHECK (source IN
            ('activities','sleep','resting_hr','hrv','all_day_heart_rate','spo2'))
        )""")
        previous = connection.execute("SELECT sql FROM sqlite_master WHERE name='health_source_state'").fetchone()[0]
        hp.ensure_schema(connection)
        hp.ensure_schema(connection)
        self.assertEqual(connection.execute("SELECT sql FROM sqlite_master WHERE name='health_source_state'").fetchone()[0], previous)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO health_source_state VALUES ('vo2max')")
        self.assertEqual([row[1] for row in connection.execute("PRAGMA table_info(point_measurements)")],
                         [*hp.POINT_KEYS, "source"])
        self.assertEqual({row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")},
                         {"health_source_state", "point_measurements"})

    def test_point_storage_idempotent_update_preserves_measurement_identity(self):
        connection = self.database()
        hp.ensure_schema(connection)
        point = self.normalized()
        self.assertEqual(hp.upsert(connection, point), 1)
        self.assertEqual(hp.upsert(connection, point), 1)
        self.assertEqual(connection.execute("SELECT count(*) FROM point_measurements").fetchone()[0], 1)
        self.assertEqual(hp.upsert(connection, self.normalized(value=138)), 1)
        row = connection.execute("SELECT metric,measured_at_ns,measured_at_utc,value,unit,source FROM point_measurements").fetchone()
        self.assertEqual(row, ("vo2max", START_NS, "2024-02-03T04:05:06.123456789+00:00", 138, None, hp.SOURCE))
        self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_nanosecond_distinct_points_not_collapsed_to_day_or_microsecond(self):
        connection = self.database()
        hp.ensure_schema(connection)
        for ns in (START_NS, START_NS + 1):
            point = hp.normalize_sample_point(sample(startTime=ns, endTime=ns))
            hp.upsert(connection, point)
        rows = connection.execute("SELECT measured_at_ns,measured_at_utc FROM point_measurements ORDER BY measured_at_ns").fetchall()
        self.assertEqual(rows, [(START_NS, "2024-02-03T04:05:06.123456789+00:00"),
                                (START_NS + 1, "2024-02-03T04:05:06.123456790+00:00")])

    def test_storage_rewhitelists_private_fields_and_keeps_null_unit(self):
        connection = self.database()
        hp.ensure_schema(connection)
        hp.upsert(connection, self.normalized(raw=MARKER, id=MARKER, gps=MARKER,
                                             Authorization=AUTH["Authorization"], unit="UNVERIFIED",
                                             avg=123, min=1, max=999, count=2))
        connection.commit()
        connection.row_factory = sqlite3.Row
        row = dict(connection.execute("SELECT * FROM point_measurements").fetchone())
        self.assertEqual(set(row), {*hp.POINT_KEYS, "source"})
        self.assertEqual(hp.normalize_point(row), self.normalized())
        self.assertIsNone(row["unit"])
        data = (self.root / "synthetic-points.sqlite3").read_bytes().decode("latin1")
        self.assertNotIn(MARKER, data)
        self.assertNotIn(AUTH["Authorization"], data)
        self.assertNotIn("UNVERIFIED", data)

    def test_storage_rejects_missing_time_conflicting_source_or_canonical_fields(self):
        connection = self.database()
        hp.ensure_schema(connection)
        hp.upsert(connection, self.normalized())
        invalid = (
            {**self.normalized(), "metric": "other"},
            self.normalized(source="SYNTHETIC_OTHER_SOURCE"),
            self.normalized(field_name="other"), self.normalized(time_zone="UTC"),
            self.normalized(measured_at_utc=hp.ns_to_utc(NOW_NS)),
            self.normalized(end_time_utc=None), self.normalized(measured_at_ns=None),
            self.normalized(end_time_ns=NOW_NS + 1), self.normalized(value=True),
        )
        missing = self.normalized()
        missing.pop("measured_at_ns")
        for record in (*invalid, missing, {}):
            self.assertIsNone(hp.normalize_point(record))
            with self.assertRaisesRegex(ValueError, "invalid_point"):
                hp.upsert(connection, record)
        self.assertEqual(connection.execute("SELECT count(*) FROM point_measurements").fetchone()[0], 1)
        self.assertEqual(connection.execute("SELECT value FROM point_measurements").fetchone()[0], 137)

    def test_sql_source_metric_unit_checks_and_unique_timestamp_are_enforced(self):
        connection = self.database()
        hp.ensure_schema(connection)
        point = self.normalized()
        keys = (*hp.POINT_KEYS, "source")
        statement = f"INSERT INTO point_measurements ({','.join(keys)}) VALUES ({','.join('?' for _ in keys)})"
        row = {**point, "source": hp.SOURCE}
        for change in ({"source": "SYNTHETIC_WRONG"}, {"metric": "other"},
                       {"field_name": "other"}, {"unit": "UNVERIFIED"},
                       {"value": -1}, {"measured_at_ns": 0}, {"end_time_ns": START_NS - 1}):
            bad = {**row, **change}
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(statement, [bad[key] for key in keys])
        connection.execute(statement, [row[key] for key in keys])
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(statement, [row[key] for key in keys])
        altered = {**row, "measured_at_ns": START_NS + 1}
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(statement, [altered[key] for key in keys])

    def test_schema_and_upsert_never_commit_callers_existing_transaction(self):
        connection = self.database()
        connection.execute("CREATE TABLE existing_synthetic (value INTEGER)")
        connection.execute("INSERT INTO existing_synthetic VALUES (17)")
        self.assertTrue(connection.in_transaction)
        hp.ensure_schema(connection)
        hp.upsert(connection, self.normalized())
        self.assertTrue(connection.in_transaction)
        connection.rollback()
        self.assertEqual(connection.execute("SELECT count(*) FROM existing_synthetic").fetchone()[0], 0)
        self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='point_measurements'").fetchone())
        hp.ensure_schema(connection)
        connection.commit()
        hp.upsert(connection, self.normalized())
        self.assertTrue(connection.in_transaction)
        connection.rollback()
        self.assertEqual(connection.execute("SELECT count(*) FROM point_measurements").fetchone()[0], 0)

    def test_empty_failed_or_timestamp_free_payloads_cannot_delete_saved_point(self):
        connection = self.database()
        hp.ensure_schema(connection)
        hp.upsert(connection, self.normalized())
        for raw in ({"samplePoints": {}}, {"error": "SYNTHETIC_ERROR"},
                    envelope(sample(startTime=None)), {"athleticScores": [1, 2]}):
            result = hp.analyse(response(raw))
            self.assertEqual(result.records, [])
            for point in result.records:
                hp.upsert(connection, point)
        self.assertEqual(connection.execute("SELECT count(*) FROM point_measurements").fetchone()[0], 1)
        self.assertEqual(connection.execute("SELECT measured_at_ns,value FROM point_measurements").fetchone(),
                         (START_NS, 137))


if __name__ == "__main__":
    unittest.main()
