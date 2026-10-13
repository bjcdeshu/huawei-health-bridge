import contextlib
import io
import json
import ssl
import unittest
from unittest.mock import patch
from urllib import error, request

import collector as c

START, END = "1699000000000", "1700100000000"


class CollectorTests(unittest.TestCase):
    def run_response(self, response):
        transport = c.MockTransport(response)
        result = c.latest(transport, START, END)
        self.assertEqual(transport.calls, 1)
        return result

    def test_normal(self):
        result = self.run_response(c.synthetic_response())
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.summary, dict(start_time_utc="2023-11-14T22:13:20+00:00",
            activity_type=56, duration_ms=1800000, distance_m=5000, training_load=30))

    def test_empty(self):
        self.assertEqual(self.run_response(c.Response(200, b"[]")).status, "empty")

    def test_expired_login_rate_and_service(self):
        for code, status in [(401, "reauth_required"), (403, "reauth_required"),
                             (302, "reauth_required"), (429, "rate_limited"),
                             (500, "service_error"), (503, "service_error"), (400, "http_error")]:
            with self.subTest(code=code):
                self.assertEqual(self.run_response(c.Response(code, b"secret response")).status, status)
        self.assertEqual(self.run_response(c.Response(200, b"<html>login</html>", "text/html")).status, "reauth_required")

    def test_missing_and_malformed_fields(self):
        for record in [{}, {"startTime": {}, "activeTime": True, "activitySummary": "bad"},
                       {"startTime": 10**1000, "activitySummary": {"dataSummary": {"com.huawei.continuous.distance.total": {"value": 2}}}}]:
            result = self.run_response(c.Response(200, json.dumps([record]).encode()))
            self.assertEqual(result.status, "partial")
            self.assertIsNone(result.summary["distance_m"])

    def test_invalid_envelopes_and_json(self):
        for body in [b"not json", b'{"error":"login required"}', b"[null]", b"[{},{}]", b"x" * (c.MAX_BODY + 1)]:
            self.assertEqual(self.run_response(c.Response(200, body)).status, "invalid_response")

    def test_auth_placeholder_and_no_dry_run_auth(self):
        auth = lambda: self.fail("dry-run must not access auth")
        c.latest(c.MockTransport(c.synthetic_response()), START, END, auth)
        transport = c.MockTransport(c.synthetic_response())
        self.assertEqual(c.latest(transport, START, END, dry_run=False).status, "reauth_required")
        self.assertEqual(transport.calls, 0)
        for headers in [{}, {"Authorization": "test", "x-client-id": "test\ninvalid"},
                        {"Authorization": "test", "x-client-id": "test", "Host": "evil"}]:
            self.assertEqual(c.latest(transport, START, END, lambda: headers, dry_run=False).status, "reauth_required")
        self.assertEqual(c.latest(transport, START, END,
            lambda: {"Authorization": "synthetic-only", "x-client-id": "synthetic-only"}, dry_run=False).status, "ok")

    def test_no_output_or_exception_leak(self):
        class Broken:
            def send(self, *args):
                raise RuntimeError("secret credential")
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = c.latest(Broken(), START, END,
                lambda: {"Authorization": "synthetic", "x-client-id": "synthetic"}, dry_run=False)
        self.assertEqual(result.status, "transport_error")
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("secret", repr(result))
        self.assertEqual(c.latest(Broken(), START, END).status, "dry_run_only")

    def test_allowlist_and_query(self):
        body = json.dumps(dict(startTime=START, endTime=END, limit=1, order="endTimeDesc")).encode()
        for method, url in [("GET", c.URL), ("POST", c.URL + "/write"),
                            ("POST", c.URL.replace("https:", "http:")), ("POST", "https://evil.example")]:
            with self.assertRaises(ValueError):
                c.check_request(method, url, body)
        for start, end in [(END, START), ("0", END), ("-1", END), ("x", END)]:
            with self.assertRaises(ValueError):
                c.latest(c.MockTransport(c.synthetic_response()), start, end)

    def test_tls_and_redirect_policy(self):
        with self.assertRaises(ValueError):
            c.OfficialTransport()
        with patch.object(c.request, "build_opener") as build:
            c.OfficialTransport(network_authorized=True)
            handlers = build.call_args.args
            https = next(h for h in handlers if isinstance(h, request.HTTPSHandler))
            self.assertTrue(https._context.check_hostname)
            self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(next(h for h in handlers if isinstance(h, request.ProxyHandler)).proxies, {})
        handler = c.NoRedirect()
        req = request.Request(c.URL)
        for target in ["https://evil.example/login", c.URL]:
            self.assertIsNone(handler.redirect_request(req, None, 302, "Found", {}, target))
            with self.assertRaises(error.HTTPError):
                handler.http_error_302(req, io.BytesIO(b""), 302, "Found", {"location": target})


if __name__ == "__main__":
    unittest.main()
