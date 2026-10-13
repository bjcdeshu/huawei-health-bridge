"""Synthetic-only runner tests; all state/auth files live in TMPDIR.

No default production directory is opened and no real HTTP call is permitted.
"""
import contextlib
import io
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import app as a
import collector as c

SYNTHETIC_AUTH = {"Authorization": "SYNTHETIC_TOKEN_NEVER_USE",
                  "x-client-id": "SYNTHETIC_CLIENT_NEVER_USE",
                  "x-version": "SYNTHETIC_VERSION", "Cookie": "SYNTHETIC_COOKIE_NEVER_USE"}
RAW_MARKERS = ("SYNTHETIC_GPS_NEVER_STORE", "SYNTHETIC_NAME_NEVER_STORE",
               "SYNTHETIC_RAW_NEVER_STORE", "SYNTHETIC_EXCEPTION_NEVER_PRINT")


def record(**overrides):
    data = {"startTime": 1700000000000, "activityType": 56, "activeTime": 1800000,
            "activitySummary": {
                "dataSummary": {"com.huawei.continuous.distance.total": {
                    "value": [{"fieldName": "distance", "floatValue": 5000}]}},
                "performanceSummary": {"aerobicTrainingStress": 30}}}
    data.update(overrides)
    return data


def response(data=None):
    return c.Response(200, json.dumps([record()] if data is None else data).encode())


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="training-camp-tests-",
                                                      dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "private-state"
        self.auth = self.root / "synthetic-auth.json"
        # A test regression must fail rather than reach any network endpoint.
        guard = patch.object(c.request.OpenerDirector, "open",
                             side_effect=AssertionError("network_forbidden_in_tests"))
        self.network_guard = guard.start()
        self.addCleanup(guard.stop)
        # Guard paths too: a CLI parser bug must never touch production state or
        # credentials even if its explicit --state-dir/--auth-file are lost.
        original_store, original_load_auth = a.Store, a.load_auth
        def isolated_store(state_dir, *, create=False):
            if Path(state_dir) != self.state:
                raise AssertionError("state_outside_this_test")
            return original_store(state_dir, create=create)
        def isolated_auth(path):
            if not Path(path).is_relative_to(self.root):
                raise AssertionError("auth_outside_this_test")
            return original_load_auth(path)
        for isolation in (patch.object(a, "Store", side_effect=isolated_store),
                          patch.object(a, "load_auth", side_effect=isolated_auth)):
            isolation.start()
            self.addCleanup(isolation.stop)

    def write_auth(self, data=SYNTHETIC_AUTH, *, raw=None, mode=0o600, path=None):
        path = self.auth if path is None else path
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(json.dumps(data).encode() if raw is None else raw)
        os.chmod(path, mode)
        return path

    def cli(self, *arguments):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = a.main(["--state-dir", str(self.state), "--auth-file", str(self.auth), *arguments])
        self.assertEqual(errors.getvalue(), "")
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assert_no_secrets(output.getvalue())
        return code, json.loads(output.getvalue())

    def assert_no_secrets(self, text):
        for marker in (*SYNTHETIC_AUTH.values(), *RAW_MARKERS):
            self.assertNotIn(marker, text)
        for header in SYNTHETIC_AUTH:
            self.assertNotIn(header, text)

    def collect_mock(self, http_response=None, *, days=30):
        transport = c.MockTransport(response() if http_response is None else http_response)
        with patch.object(c, "OfficialTransport", return_value=transport) as factory:
            code, payload = self.cli("collect", "--lookback-days", str(days))
        factory.assert_called_once_with(network_authorized=True)
        self.assertEqual(transport.calls, 1)
        self.network_guard.assert_not_called()
        return code, payload

    def assert_reauth_without_http(self):
        with patch.object(c, "OfficialTransport") as factory, patch.object(c, "latest") as latest:
            code, payload = self.cli("collect")
        self.assertEqual(code, 3)
        self.assertEqual(payload["status"], "reauth_required")
        self.assertFalse(payload["stored"])
        factory.assert_not_called()
        latest.assert_not_called()
        self.network_guard.assert_not_called()
        self.assertEqual(a.read_status(self.state)["last_collection_status"], "reauth_required")
        self.assertEqual(a.read_status(self.state)["count"], 0)

    def test_defaults_do_not_access_production(self):
        self.assertEqual(a.DEFAULT_STATE_DIR, Path("/var/lib/huawei-training-camp"))
        self.assertEqual(a.DEFAULT_AUTH_FILE, Path("/var/lib/huawei-training-camp/auth.json"))
        self.assertEqual(a.DATABASE_NAME, "health.sqlite3")
        self.assertNotEqual(self.state, a.DEFAULT_STATE_DIR)
        self.assertTrue(self.root.is_relative_to(Path(os.environ.get("TMPDIR", tempfile.gettempdir()))))

    def test_cli_shared_options_before_or_after_command_are_preserved(self):
        parser = a.build_parser()
        options = ["--state-dir", str(self.state), "--auth-file", str(self.auth)]
        for arguments in (options + ["collect"], ["collect"] + options):
            args = parser.parse_args(arguments)
            self.assertEqual(args.state_dir, str(self.state))
            self.assertEqual(args.auth_file, str(self.auth))

    def test_init_is_private_and_does_not_load_auth_or_use_http(self):
        previous_umask = os.umask(0)
        try:
            with patch.object(a, "load_auth") as auth, patch.object(c, "OfficialTransport") as transport:
                code, payload = self.cli("init")
        finally:
            os.umask(previous_umask)
        self.assertEqual((code, payload["status"], payload["count"]), (0, "initialized", 0))
        auth.assert_not_called()
        transport.assert_not_called()
        self.assertFalse(self.auth.exists())
        self.assertFalse((self.state / "auth.json").exists())
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        database = self.state / a.DATABASE_NAME
        self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o600)
        self.assertEqual(database.stat().st_uid, os.geteuid())

    def test_status_and_latest_before_init_do_not_create_state(self):
        with patch.object(a, "load_auth") as auth, patch.object(c, "OfficialTransport") as transport:
            self.assertEqual(self.cli("status")[1], dict(status="not_initialized", source=a.SOURCE,
                count=0, last_collection_status=None, last_collection_time_utc=None))
            self.assertEqual(self.cli("latest")[1], dict(status="not_initialized", source=a.SOURCE, summary=None))
        auth.assert_not_called()
        transport.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_missing_auth_requires_reauth_without_http(self):
        self.assert_reauth_without_http()

    def test_unsafe_auth_permissions_require_reauth_without_http(self):
        for mode in (0o644, 0o640, 0o606, 0o700, 0o1600, 0o2600, 0o4600):
            with self.subTest(mode=oct(mode)):
                self.write_auth(mode=mode)
                self.assert_reauth_without_http()

    def test_auth_symlink_requires_reauth_without_http(self):
        target = self.write_auth(path=self.root / "synthetic-target.json")
        self.auth.symlink_to(target)
        self.assert_reauth_without_http()

    def test_auth_directory_and_fifo_require_reauth_without_http(self):
        self.auth.mkdir(mode=0o700)
        self.assert_reauth_without_http()
        self.auth.rmdir()
        os.mkfifo(self.auth, 0o600)
        self.assert_reauth_without_http()

    def test_auth_wrong_uid_requires_reauth_without_http(self):
        self.write_auth()
        uid = os.geteuid()
        with patch.object(a.os, "geteuid", return_value=uid + 1), patch.object(c, "OfficialTransport") as factory:
            code, payload = self.cli("collect")
        self.assertEqual((code, payload["status"]), (3, "reauth_required"))
        self.assertEqual(payload["storage_status"], "storage_error")
        factory.assert_not_called()
        self.network_guard.assert_not_called()

    def test_auth_json_and_headers_are_strict_and_never_echoed(self):
        malformed = [b"not-json", b"\xff", b"[]", b"null", b'"SYNTHETIC_TOKEN_NEVER_USE"',
            b'{"Authorization":"one","Authorization":"two","x-client-id":"synthetic"}',
            json.dumps({}).encode(), json.dumps({"Authorization": "synthetic"}).encode()]
        for value in (None, 7, True, {}, [], "", "   ", "synthetic\rattack", "synthetic\nattack"):
            malformed.append(json.dumps({**SYNTHETIC_AUTH, "Authorization": value}).encode())
            malformed.append(json.dumps({**SYNTHETIC_AUTH, "x-client-id": value}).encode())
        for key in ("Host", "Content-Type", "authorization", "gps", "proxy"):
            malformed.append(json.dumps({**SYNTHETIC_AUTH, key: "SYNTHETIC_RAW_NEVER_STORE"}).encode())
        for key in ("Cookie", "x-version"):
            for value in (False, 7, "synthetic\rattack", "synthetic\nattack"):
                malformed.append(json.dumps({**SYNTHETIC_AUTH, key: value}).encode())
        for raw in malformed:
            with self.subTest(raw_length=len(raw)):
                self.write_auth(raw=raw)
                self.assert_reauth_without_http()

    def test_auth_size_boundary_and_stricter_permissions(self):
        raw = json.dumps(SYNTHETIC_AUTH).encode()
        self.write_auth(raw=raw + b" " * (a.MAX_AUTH_BYTES - len(raw)), mode=0o400)
        self.assertEqual(a.load_auth(self.auth), SYNTHETIC_AUTH)
        self.collect_mock()
        # Restore write permission on this synthetic fixture before replacing
        # it. Tests must work as a normal user, not depend on root bypassing 0400.
        self.auth.chmod(0o600)
        self.write_auth(raw=raw + b" " * (a.MAX_AUTH_BYTES - len(raw) + 1))
        with patch.object(c, "OfficialTransport") as factory:
            code, payload = self.cli("collect")
        self.assertEqual((code, payload["status"]), (3, "reauth_required"))
        factory.assert_not_called()
        self.assertEqual(a.read_status(self.state)["count"], 1)

    def test_only_required_auth_headers_are_accepted(self):
        self.write_auth({k: SYNTHETIC_AUTH[k] for k in ("Authorization", "x-client-id")})
        self.assertEqual(self.collect_mock()[1]["status"], "ok")

    def test_collection_is_idempotent_and_upserts_by_start_and_type(self):
        self.write_auth()
        self.assertTrue(self.collect_mock()[1]["stored"])
        self.assertTrue(self.collect_mock()[1]["stored"])
        self.collect_mock(response([record(activeTime=1900000)]))
        self.assertEqual(a.read_status(self.state)["count"], 1)
        self.assertEqual(a.read_latest(self.state)["summary"]["duration_ms"], 1900000)
        with sqlite3.connect(self.state / a.DATABASE_NAME) as database:
            self.assertEqual(database.execute("SELECT source FROM activities").fetchall(), [(a.SOURCE,)])
            with self.assertRaises(sqlite3.IntegrityError):
                database.execute("INSERT INTO activities (start_time_utc, activity_type, source) VALUES (?, ?, ?)",
                    ("2023-11-14T22:13:20+00:00", 56, a.SOURCE))
        self.cli("init")
        self.assertEqual(a.read_status(self.state)["count"], 1)
        self.assertEqual(a.read_status(self.state)["last_collection_status"], "ok")

    def test_query_uses_actual_utc_bounded_window_and_original_real_path(self):
        self.write_auth()
        for days in (1, 7, 30):
            with self.subTest(days=days):
                class QueryOnlyMock(c.MockTransport):
                    def send(self, method, url, headers, body):
                        self.query = json.loads(body)
                        self.header_names = set(headers)
                        return super().send(method, url, headers, body)
                transport = QueryOnlyMock(response())
                before = datetime.now(timezone.utc)
                with patch.object(c, "OfficialTransport", return_value=transport) as factory, \
                        patch.object(c, "latest", wraps=c.latest) as original:
                    code, payload = self.cli("collect", "--lookback-days", str(days))
                after = datetime.now(timezone.utc)
                self.assertEqual(code, 0)
                factory.assert_called_once_with(network_authorized=True)
                self.assertIs(original.call_args.args[0], transport)
                self.assertIs(original.call_args.kwargs["dry_run"], False)
                query = transport.query
                self.assertEqual(set(query), {"startTime", "endTime", "limit", "order"})
                self.assertEqual(query["limit"], 1)
                self.assertEqual(query["order"], "endTimeDesc")
                self.assertEqual(int(query["endTime"]) - int(query["startTime"]), days * 86400 * 1000)
                self.assertLessEqual(int(before.timestamp() * 1000), int(query["endTime"]))
                self.assertLessEqual(int(query["endTime"]), int(after.timestamp() * 1000))
                self.assertLessEqual(before, datetime.fromisoformat(payload["collected_at_utc"]))
                self.assertLessEqual(datetime.fromisoformat(payload["collected_at_utc"]), after)
                self.assertEqual(a.read_status(self.state)["last_collection_time_utc"], payload["collected_at_utc"])
                self.assertEqual(transport.calls, 1)
                self.assertEqual(transport.header_names, set(SYNTHETIC_AUTH) | {"Content-Type"})

    def test_missing_measurements_remain_null_and_partial(self):
        self.write_auth()
        partial = {"startTime": 1700000000000, "activityType": "RUNNING"}
        code, payload = self.collect_mock(response([partial]))
        self.assertEqual((code, payload["status"], payload["stored"]), (0, "partial", True))
        summary = a.read_latest(self.state)["summary"]
        self.assertEqual(summary, dict(start_time_utc="2023-11-14T22:13:20+00:00",
            activity_type="RUNNING", duration_ms=None, distance_m=None, training_load=None))
        with sqlite3.connect(self.state / a.DATABASE_NAME) as database:
            self.assertEqual(database.execute("SELECT duration_ms, distance_m, training_load FROM activities").fetchone(),
                             (None, None, None))

    def test_unidentifiable_records_are_partial_and_not_stored(self):
        self.write_auth()
        examples = [{}, record(startTime=None), record(startTime="1700000000000"),
            record(startTime=10**1000), record(activityType=None), record(activityType=True),
            record(activityType=""), record(activityType="SYNTHETIC_NAME_NEVER_STORE with GPS"),
            record(activityType="SYNTHETIC_GPS_NEVER_STORE\n"), record(activityType=10**100)]
        for item in examples:
            with self.subTest(keys=list(item)):
                code, payload = self.collect_mock(response([item]))
                self.assertEqual((code, payload["status"], payload["stored"]), (0, "partial", False))
                self.assertEqual(a.read_status(self.state)["count"], 0)
                self.assertEqual(a.read_latest(self.state)["summary"], None)

    def test_numeric_outliers_are_null_not_storage_errors(self):
        self.write_auth()
        for value in (True, -1, "1800000", 10**100, float("inf"), float("nan")):
            with self.subTest(value_type=type(value).__name__):
                code, payload = self.collect_mock(response([record(activeTime=value)]))
                self.assertEqual((code, payload["status"], payload["stored"]), (0, "partial", True))
                self.assertIsNone(a.read_latest(self.state)["summary"]["duration_ms"])

    def test_no_raw_gps_names_headers_or_auth_in_sqlite_or_output(self):
        self.write_auth()
        raw = record(gps=[RAW_MARKERS[0]], location={"latitude": 12.345, "longitude": 67.89},
                     activityName=RAW_MARKERS[1], raw=RAW_MARKERS[2], headers=SYNTHETIC_AUTH)
        self.collect_mock(response([raw]))
        with sqlite3.connect(self.state / a.DATABASE_NAME) as database:
            columns = [row[1] for row in database.execute("PRAGMA table_info(activities)")]
            self.assertEqual(columns, [*a.SUMMARY_KEYS, "source"])
            tables = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertEqual(tables, {"activities", "collection_state"})
            rows = database.execute("SELECT * FROM activities").fetchall()
            self.assert_no_secrets(repr(rows))
        for path in self.state.iterdir():
            self.assert_no_secrets(path.read_bytes().decode("latin-1"))
        self.cli("status")
        self.cli("latest")
        self.assertEqual(stat.S_IMODE((self.state / a.DATABASE_NAME).stat().st_mode), 0o600)

    def test_empty_response_preserves_previous_health_data(self):
        self.write_auth()
        self.collect_mock()
        previous = a.read_latest(self.state)
        code, payload = self.collect_mock(response([]))
        self.assertEqual((code, payload["status"], payload["stored"]), (0, "empty", False))
        self.assertEqual(a.read_status(self.state)["count"], 1)
        self.assertEqual(a.read_status(self.state)["last_collection_status"], "empty")
        self.assertEqual(a.read_latest(self.state), previous)

    def test_http_and_auth_failure_semantics_do_not_retry_or_erase_data(self):
        self.write_auth()
        self.collect_mock()
        prior = a.read_latest(self.state)
        cases = [(401, "reauth_required"), (403, "reauth_required"),
                 (301, "reauth_required"), (302, "reauth_required"), (303, "reauth_required"),
                 (307, "reauth_required"), (308, "reauth_required"), (304, "redirect_rejected"),
                 (429, "rate_limited"), (500, "service_error"), (503, "service_error"), (400, "http_error")]
        for http_status, expected in cases:
            with self.subTest(http_status=http_status):
                code, payload = self.collect_mock(c.Response(http_status, RAW_MARKERS[2].encode()))
                self.assertEqual(code, 3 if expected == "reauth_required" else 1)
                self.assertEqual(payload["status"], expected)
                self.assertFalse(payload["stored"])
                self.assertEqual(a.read_status(self.state)["last_collection_status"], expected)
                self.assertEqual(a.read_status(self.state)["count"], 1)
                self.assertEqual(a.read_latest(self.state), prior)
        self.assertEqual(self.collect_mock(c.Response(200, b"<html>synthetic login</html>", "text/html"))[1]["status"],
                         "reauth_required")
        self.assertEqual(a.read_status(self.state)["count"], 1)

    def test_invalid_responses_are_not_mistaken_for_empty(self):
        self.write_auth()
        for body in (RAW_MARKERS[2].encode(), b'{"businessError":"synthetic"}', b"[null]", b"[{},{}]",
                     b"x" * (c.MAX_BODY + 1)):
            with self.subTest(size=len(body)):
                code, payload = self.collect_mock(c.Response(200, body))
                self.assertEqual((code, payload["status"], payload["stored"]), (1, "invalid_response", False))
                self.assertEqual(a.read_status(self.state)["count"], 0)

    def test_transport_exceptions_are_sanitized(self):
        self.write_auth()
        class BrokenMock:
            calls = 0
            def send(self, *args):
                self.calls += 1
                raise RuntimeError(RAW_MARKERS[3] + " " + SYNTHETIC_AUTH["Authorization"])
        transport = BrokenMock()
        with patch.object(c, "OfficialTransport", return_value=transport):
            code, payload = self.cli("collect")
        self.assertEqual((code, payload["status"], payload["stored"]), (1, "transport_error", False))
        self.assertEqual(transport.calls, 1)
        self.assertEqual(a.read_status(self.state)["last_collection_status"], "transport_error")
        self.assert_no_secrets((self.state / a.DATABASE_NAME).read_bytes().decode("latin-1"))

    def test_status_is_operational_only_latest_is_allowlisted_and_offline(self):
        self.write_auth()
        self.collect_mock()
        self.auth.unlink()
        with patch.object(a, "load_auth") as auth, patch.object(c, "OfficialTransport") as transport:
            code, operational = self.cli("status")
            self.assertEqual(code, 0)
            self.assertEqual(set(operational), {"status", "source", "count", "last_collection_status", "last_collection_time_utc"})
            self.assertEqual(operational["count"], 1)
            code, latest = self.cli("latest")
            self.assertEqual(code, 0)
            self.assertEqual(set(latest), {"status", "source", "summary"})
            self.assertEqual(set(latest["summary"]), set(a.SUMMARY_KEYS))
            self.assertEqual(latest["source"], a.SOURCE)
        auth.assert_not_called()
        transport.assert_not_called()

    def test_latest_is_newest_saved_start_time_not_insertion_order(self):
        self.write_auth()
        self.collect_mock(response([record(startTime=1700000100000)]))
        self.collect_mock(response([record(startTime=1700000000000)]))
        self.assertEqual(a.read_status(self.state)["count"], 2)
        self.assertEqual(a.read_latest(self.state)["summary"]["start_time_utc"], "2023-11-14T22:15:00+00:00")

    def test_default_auth_is_relative_to_selected_private_state(self):
        a.init_state(self.state)
        self.write_auth(path=self.state / "auth.json")
        transport = c.MockTransport(response())
        output = io.StringIO()
        with patch.object(c, "OfficialTransport", return_value=transport), contextlib.redirect_stdout(output):
            code = a.main(["collect", "--state-dir", str(self.state)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "ok")
        self.assertEqual(transport.calls, 1)
        self.assert_no_secrets(output.getvalue())

    def test_unsafe_state_directory_is_rejected_before_http(self):
        self.write_auth()
        self.state.mkdir(mode=0o700)
        self.state.chmod(0o755)
        with patch.object(c, "OfficialTransport") as factory:
            code, payload = self.cli("collect")
        self.assertEqual((code, payload["status"]), (1, "storage_error"))
        factory.assert_not_called()
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o755)
        self.assertFalse((self.state / a.DATABASE_NAME).exists())

    def test_state_symlink_is_rejected_without_writing_target(self):
        target = self.root / "target-state"
        target.mkdir(mode=0o700)
        self.state.symlink_to(target, target_is_directory=True)
        self.assertEqual(self.cli("init")[1]["status"], "storage_error")
        self.assertEqual(list(target.iterdir()), [])

    def test_unsafe_database_paths_are_rejected_before_http(self):
        self.write_auth()
        self.state.mkdir(mode=0o700)
        database = self.state / a.DATABASE_NAME
        target = self.write_auth(path=self.root / "synthetic-target.json")
        variants = ("symlink", "hardlink", "world_readable", "fifo", "directory")
        for variant in variants:
            with self.subTest(variant=variant):
                if variant == "symlink":
                    database.symlink_to(target)
                elif variant == "hardlink":
                    os.link(target, database)
                elif variant == "world_readable":
                    self.write_auth(raw=b"", path=database, mode=0o644)
                elif variant == "fifo":
                    os.mkfifo(database, 0o600)
                else:
                    database.mkdir(mode=0o700)
                with patch.object(c, "OfficialTransport") as factory:
                    code, payload = self.cli("collect")
                self.assertEqual((code, payload["status"]), (1, "storage_error"))
                factory.assert_not_called()
                if variant == "directory":
                    database.rmdir()
                else:
                    database.unlink()
                self.assertEqual(a.load_auth(target), SYNTHETIC_AUTH)

    def test_unsafe_sqlite_sidecar_is_rejected(self):
        self.write_auth()
        a.init_state(self.state)
        target = self.write_auth(path=self.root / "synthetic-target.json")
        sidecar = self.state / (a.DATABASE_NAME + "-journal")
        sidecar.symlink_to(target)
        with patch.object(c, "OfficialTransport") as factory:
            self.assertEqual(self.cli("collect")[1]["status"], "storage_error")
        factory.assert_not_called()
        self.assertEqual(a.load_auth(target), SYNTHETIC_AUTH)

    def test_corrupt_database_errors_do_not_echo_contents_or_fetch_http(self):
        self.write_auth()
        self.state.mkdir(mode=0o700)
        self.write_auth(raw=RAW_MARKERS[2].encode(), path=self.state / a.DATABASE_NAME)
        with patch.object(c, "OfficialTransport") as factory:
            self.assertEqual(self.cli("collect")[1]["status"], "storage_error")
            self.assertEqual(self.cli("status")[1]["status"], "storage_error")
            self.assertEqual(self.cli("latest")[1]["status"], "storage_error")
        factory.assert_not_called()

    def test_argparse_rejects_bad_windows_and_never_echoes_values(self):
        cases = [("collect", "--lookback-days", value) for value in ("0", "31", "-1", "1.5", SYNTHETIC_AUTH["Authorization"])]
        cases.extend([(), (SYNTHETIC_AUTH["Authorization"],), ("collect", "--unknown", RAW_MARKERS[3])])
        with patch.object(a, "load_auth") as auth, patch.object(c, "OfficialTransport") as transport:
            for arguments in cases:
                with self.subTest(argument_count=len(arguments)):
                    self.assertEqual(self.cli(*arguments), (2, {"status": "invalid_arguments"}))
        auth.assert_not_called()
        transport.assert_not_called()
        self.assertFalse(self.state.exists())
        for invalid in (0, 31, True, "30"):
            with self.assertRaises(a.InvalidArguments):
                a.collect_once(self.state, self.auth, lookback_days=invalid)

    def test_unexpected_exceptions_never_print_exception_text(self):
        with patch.object(a, "read_status", side_effect=RuntimeError(RAW_MARKERS[3])):
            self.assertEqual(self.cli("status"), (1, {"status": "internal_error", "source": a.SOURCE}))


if __name__ == "__main__":
    unittest.main()
