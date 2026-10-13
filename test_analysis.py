"""Synthetic-only analysis tests. No account data, credentials or live requests.

Run: TMPDIR=/approved/scratch python3 -B -m unittest -v test_analysis
Each test owns an explicit TMPDIR child. File/SQLite/metadata/auth/network guards
fail even if the analysis suppresses an exception. health.py is never imported.
Fixtures have deliberately invented values, not copied responses or readings.
"""
import builtins
import contextlib
import http.client
import io
import json
import os
import socket
import sqlite3
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib import request
from urllib.parse import unquote

import app
import health_analysis as a

NOW = datetime(2024, 3, 5, 2, 0, tzinfo=timezone.utc)  # 10:00 UTC+8
MARKER = "SYNTHETIC_PRIVATE_TEXT_MUST_NOT_LEAK"


def ns(stamp):
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


def ns_stamp(value):
    seconds, fraction = divmod(value, 1_000_000_000)
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}+00:00"


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        scratch = os.path.abspath(os.environ["TMPDIR"])
        forbidden = ("/var/lib/huawei-training-camp", "/srv/agent-workspace/huawei-training-camp")
        if scratch.startswith(forbidden) or os.path.realpath(scratch).startswith(forbidden):
            self.fail("production_TMPDIR_forbidden")
        self.temp = tempfile.TemporaryDirectory(prefix="health-analysis-tests-", dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.state = self.root / "private"
        self.violations = []
        self.reading = False
        self.read_statements = []
        originals = dict(open=builtins.open, io_open=io.open, os_open=os.open,
                         connect=sqlite3.connect, stat=os.stat, lstat=os.lstat,
                         mkdir=os.mkdir, store=app.Store, import_=builtins.__import__)

        def reject(label):
            self.violations.append(label)
            raise AssertionError(label)

        def full_path(path, dir_fd=None):
            text = os.fsdecode(os.fspath(path))
            if text.startswith("file:"):
                text = unquote(text[5:].split("?", 1)[0])
            if text.startswith("/proc/self/fd/"):
                parts = text.split("/")
                text = os.path.join(os.readlink("/proc/self/fd/" + parts[4]), *parts[5:])
            if dir_fd is not None:
                text = os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), text)
            return os.path.abspath(text)

        def check(path, *, dir_fd=None, metadata=False):
            if type(path) is int:
                return
            full = full_path(path, dir_fd)
            if full.startswith(forbidden):
                reject("production_path_forbidden")
            if Path(full).name in ("auth.json", "sync-status.json", ".env"):
                reject("credential_or_marker_access_forbidden")
            if not metadata:
                if not Path(full).is_relative_to(self.root) or not Path(os.path.realpath(full)).is_relative_to(self.root):
                    reject("path_outside_test_fixture")

        def guarded_file(original, path, *args, **kwargs):
            check(path)
            if self.reading and ((args and any(c in args[0] for c in "wax+")) or any(c in kwargs.get("mode", "r") for c in "wax+")):
                reject("analysis_file_write_forbidden")
            return original(path, *args, **kwargs)

        def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
            check(path, dir_fd=dir_fd)
            if self.reading and flags & (os.O_CREAT | os.O_WRONLY | os.O_RDWR | os.O_TRUNC):
                reject("analysis_os_write_forbidden")
            return originals["os_open"](path, flags, mode, dir_fd=dir_fd)

        def guarded_stat(original, path, *args, **kwargs):
            check(path, dir_fd=kwargs.get("dir_fd"), metadata=True)
            return original(path, *args, **kwargs)

        def guarded_mkdir(path, mode=0o777, *, dir_fd=None):
            check(path, dir_fd=dir_fd)
            if self.reading:
                reject("analysis_mkdir_forbidden")
            return originals["mkdir"](path, mode, dir_fd=dir_fd)

        def guarded_store(state_dir, **kwargs):
            check(state_dir)
            if self.reading and kwargs.get("create", False):
                reject("analysis_create_store_forbidden")
            return originals["store"](state_dir, **kwargs)

        def guarded_connect(path, *args, **kwargs):
            check(path)
            if self.reading and not (str(path).startswith("file:") and "mode=ro" in str(path) and kwargs.get("uri")):
                reject("analysis_non_readonly_sqlite_forbidden")
            db = originals["connect"](path, *args, **kwargs)
            if self.reading:
                def trace(sql):
                    verb = sql.lstrip().split()[0].upper()
                    self.read_statements.append(verb)
                    if verb not in ("SELECT", "PRAGMA", "BEGIN", "ROLLBACK"):
                        reject("analysis_SQL_mutation_forbidden")
                db.set_trace_callback(trace)
            return db

        def guarded_import(name, *args, **kwargs):
            if name in ("health", "auth_session", "browser_session"):
                reject("analysis_integration_or_auth_import_forbidden")
            return originals["import_"](name, *args, **kwargs)

        for guard in (
            patch.object(builtins, "open", side_effect=lambda *x, **k: guarded_file(originals["open"], *x, **k)),
            patch.object(io, "open", side_effect=lambda *x, **k: guarded_file(originals["io_open"], *x, **k)),
            patch.object(os, "open", side_effect=guarded_open),
            patch.object(os, "mkdir", side_effect=guarded_mkdir),
            patch.object(os, "stat", side_effect=lambda *x, **k: guarded_stat(originals["stat"], *x, **k)),
            patch.object(os, "lstat", side_effect=lambda *x, **k: guarded_stat(originals["lstat"], *x, **k)),
            patch.object(sqlite3, "connect", side_effect=guarded_connect),
            patch.object(app, "Store", side_effect=guarded_store),
            patch.object(app, "load_auth", side_effect=lambda *x, **k: reject("credential_read_forbidden")),
            patch.object(builtins, "__import__", side_effect=guarded_import),
            patch.object(request.OpenerDirector, "open", side_effect=lambda *x, **k: reject("real_network_forbidden")),
            patch.object(request, "urlopen", side_effect=lambda *x, **k: reject("real_network_forbidden")),
            patch.object(http.client.HTTPConnection, "request", side_effect=lambda *x, **k: reject("real_network_forbidden")),
            patch.object(socket.socket, "connect", side_effect=lambda *x, **k: reject("real_network_forbidden")),
            patch.object(socket.socket, "connect_ex", side_effect=lambda *x, **k: reject("real_network_forbidden")),
            patch.object(socket, "create_connection", side_effect=lambda *x, **k: reject("real_network_forbidden")),
            patch.object(socket, "getaddrinfo", side_effect=lambda *x, **k: reject("real_network_forbidden")),
        ):
            guard.start()
            self.addCleanup(guard.stop)

    def tearDown(self):
        self.assertEqual(self.violations, [], "isolation violation, possibly suppressed")

    def initialize(self, *, quality=False):
        with app.Store(self.state, create=True) as store:
            store.connection.executescript("""
                CREATE TABLE metric_stats(metric TEXT, day TEXT, time_zone TEXT,
                    field_name TEXT, unit TEXT, avg, min, max, sum, count, source TEXT);
                CREATE TABLE point_measurements(metric TEXT, measured_at_ns INTEGER,
                    measured_at_utc TEXT, end_time_ns INTEGER, end_time_utc TEXT,
                    field_name TEXT, value, unit TEXT, time_zone TEXT, source TEXT);
                CREATE TABLE health_source_state(name TEXT PRIMARY KEY, last_status TEXT,
                    checked_at_utc TEXT, last_success_time_utc TEXT, received_records INTEGER,
                    stored_records INTEGER, coverage TEXT, quality TEXT, lookback_days INTEGER, query_limit INTEGER);
                CREATE TABLE health_sync_state(singleton INTEGER PRIMARY KEY,
                    last_status TEXT, checked_at_utc TEXT, last_success_time_utc TEXT,
                    authentication_required INTEGER, blocked_auth_fingerprint TEXT);
            """)
            fields = ",".join(k + (" TEXT" if k.endswith("_utc") else " INTEGER") for k in a.SLEEP_FIELDS)
            store.connection.execute("CREATE TABLE sleep_records(" + fields + ", source TEXT)")
            if quality:
                self.create_quality(store.connection)

    def create_quality(self, db):
        db.execute("""CREATE TABLE health_record_quality(source TEXT, record_key TEXT,
            field TEXT, last_valid_at_utc TEXT, last_seen_at_utc TEXT, retained INTEGER,
            PRIMARY KEY(source,record_key,field))""")

    @contextlib.contextmanager
    def db(self):
        db = sqlite3.connect(self.state / app.DATABASE_NAME)
        try:
            with db:
                yield db
        finally:
            db.close()

    def analysis(self, **kwargs):
        self.reading = True
        output, errors = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                result = a.build_analysis(self.state, now=kwargs.pop("now", NOW), **kwargs)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(errors.getvalue(), "")
            encoded = json.dumps(result, sort_keys=True, allow_nan=False)
            self.assertNotIn(MARKER, encoded)
            self.assertNotIn("blocked_auth_fingerprint", encoded)
            return result
        finally:
            self.reading = False

    def metric(self, name, day, avg=None, low=None, high=None, count=None, **changes):
        field, unit, _ = a.METRICS[name]
        row = dict(metric=name, day=day, time_zone="+0800", field_name=field, unit=unit,
                   avg=avg, min=low, max=high, sum=None, count=count, source=app.SOURCE)
        row.update(changes)
        with self.db() as db:
            db.execute("INSERT INTO metric_stats(" + ",".join(row) + ") VALUES (" + ",".join("?" for _ in row) + ")", tuple(row.values()))

    def sleep(self, start, end, minutes, code=1, **changes):
        row = {k: None for k in a.SLEEP_FIELDS}
        row.update(start_time_utc=start, end_time_utc=end, wakeup_time_utc=end,
                   total_sleep_minutes=minutes, sleep_type=code, source=app.SOURCE)
        row.update(changes)
        with self.db() as db:
            db.execute("INSERT INTO sleep_records(" + ",".join(row) + ") VALUES (" + ",".join("?" for _ in row) + ")", tuple(row.values()))
        return start + "|" + str(code)

    def workout(self, start, minutes, distance, code=99):
        with self.db() as db:
            db.execute("INSERT INTO activities VALUES (?,?,?,?,?,?)",
                       (start, code, minutes * 60000 if minutes is not None else None, distance, None, app.SOURCE))
        return start + "|" + str(code)

    def point(self, stamp, value, **changes):
        row = dict(metric="vo2max", measured_at_ns=stamp, measured_at_utc=ns_stamp(stamp),
                   end_time_ns=stamp, end_time_utc=ns_stamp(stamp), field_name="vo2max", value=value,
                   unit=None, time_zone="+0800", source=app.SOURCE)
        row.update(changes)
        with self.db() as db:
            db.execute("INSERT INTO point_measurements(" + ",".join(row) + ") VALUES (" + ",".join("?" for _ in row) + ")", tuple(row.values()))
        return str(stamp)

    def quality(self, source, key, field, retained, last_valid="2024-03-01T00:00:00+00:00"):
        with self.db() as db:
            db.execute("INSERT INTO health_record_quality VALUES (?,?,?,?,?,?)",
                       (source, key, field, last_valid, NOW.isoformat(), retained))

    def test_missing_state_is_never_created_and_has_stable_empty_schema(self):
        result = self.analysis()
        self.assertEqual(result["status"], "not_initialized")
        self.assertFalse(self.state.exists())
        self.assertEqual(tuple(result["sources"]), a.SOURCE_NAMES)
        for source in result["sources"].values():
            current = source["current"]
            self.assertEqual(current["coverage"]["observed_record_count"], 0)
            self.assertEqual(current["coverage"]["missing_dates"], result["scope"]["dates"])
            for summary in current["summary"].values():
                self.assertIsNone(summary["mean"])
                self.assertEqual(summary["sample_count"], 0)

    def test_default_completed_utc8_dates_baseline_and_midnight(self):
        result = self.analysis()
        self.assertEqual((result["scope"]["start"], result["scope"]["end"]), ("2024-02-27", "2024-03-04"))
        self.assertEqual(result["scope"]["baseline"]["dates"], [(date(2024, 1, 30) + timedelta(days=i)).isoformat() for i in range(28)])
        self.assertEqual(result["scope"]["incomplete_dates"], [])
        later = self.analysis(now=datetime(2024, 3, 5, 16, 0, tzinfo=timezone.utc))
        self.assertEqual(later["scope"]["end"], "2024-03-05")
        self.assertEqual(later["timezone"], "+08:00")

    def test_monthly_range_crosses_leap_day_without_zero_filling(self):
        result = self.analysis(days=30)
        self.assertEqual(len(result["scope"]["dates"]), 30)
        self.assertEqual(result["scope"]["start"], "2024-02-04")
        self.assertIn("2024-02-29", result["scope"]["dates"])
        self.assertEqual(result["sources"]["hrv"]["current"]["daily"], [])

    def test_include_today_and_explicit_today_are_partial_with_completed_sleep(self):
        self.initialize()
        self.sleep("2024-03-04T16:00:00+00:00", "2024-03-04T23:00:00+00:00", 390)
        default = self.analysis()
        self.assertEqual(default["sources"]["sleep"]["current"]["session_counts"]["observed"], 0)
        for options in ({"include_today": True}, {"start": "2024-03-05", "end": "2024-03-05"}):
            result = self.analysis(**options)
            self.assertEqual(result["scope"]["incomplete_dates"], ["2024-03-05"])
            current = result["sources"]["sleep"]["current"]
            self.assertEqual(current["summary"]["main_sleep_minutes"]["mean"], 390)
            self.assertTrue(current["daily"][0]["incomplete"])
            self.assertTrue(current["daily"][0]["main_sleep"]["complete"])

    def test_invalid_dates_counts_and_clocks_fail_before_open(self):
        cases = [{"days": 0}, {"days": True}, {"days": 367}, {"days": "7"},
                 {"baseline_days": -1}, {"baseline_days": True}, {"baseline_days": 367}, {"include_today": 1},
                 {"start": "20240301"}, {"end": "2024-02-30"}, {"start": MARKER},
                 {"end": "2024-03-06"}, {"start": "2024-03-03", "end": "2024-03-02"},
                 {"start": "2020-01-01", "end": "2024-03-02"}, {"start": "0001-01-01", "end": "0001-01-02"},
                 {"now": datetime(2024, 3, 5)}, {"now": MARKER}]
        with patch.object(app, "Store") as store:
            for options in cases:
                with self.subTest(options=sorted(options)):
                    with self.assertRaises(app.InvalidArguments) as error:
                        self.analysis(**options)
                    self.assertEqual(str(error.exception), "")
            store.assert_not_called()

    def test_explicit_end_start_precedence_and_disabled_baseline(self):
        result = self.analysis(days=30, start=date(2024, 2, 1), end="2024-02-03", baseline_days=2, include_today=True)
        self.assertEqual(result["scope"]["days"], 3)
        self.assertEqual(result["scope"]["baseline"]["dates"], ["2024-01-30", "2024-01-31"])
        self.assertFalse(result["scope"]["includes_today"])
        self.assertEqual(self.analysis(end="2024-03-01", days=2)["scope"]["dates"], ["2024-02-29", "2024-03-01"])
        disabled = self.analysis(baseline_days=0)
        self.assertEqual(disabled["scope"]["baseline"]["dates"], [])
        self.assertIsNone(disabled["sources"]["hrv"]["comparison"]["avg"]["mean_delta"])

    def test_daily_unweighted_stats_and_baseline_deltas_with_missing_days(self):
        self.initialize()
        for day, value, count in (("2024-03-01", 10, 100), ("2024-03-03", 30, 1), ("2024-02-25", 4, 1), ("2024-02-26", 8, 5)):
            self.metric("resting_hr", day, avg=value, count=count)
        source = self.analysis()["sources"]["resting_hr"]
        summary = source["current"]["summary"]["avg"]
        self.assertEqual((summary["mean"], summary["median"], summary["min"], summary["max"], summary["range"]), (20, 20, 10, 30, 20))
        self.assertEqual(summary["sample_count"], 2)
        self.assertEqual(source["comparison"]["avg"]["mean_delta"], 14)
        self.assertEqual(source["current"]["underlying_samples"]["known_count_sum"], 101)
        self.assertEqual(source["current"]["coverage"]["usable_dates"], ["2024-03-01", "2024-03-03"])
        self.assertEqual(len(source["current"]["coverage"]["missing_dates"]), 5)

    def test_hrv_unknown_unit_spo2_fields_and_no_invented_all_day_average(self):
        self.initialize()
        self.metric("hrv", "2024-03-04", avg=10, unit="ms")
        self.metric("all_day_heart_rate", "2024-03-04", avg=999, low=20, high=70)
        self.metric("spo2", "2024-03-04", avg=50, low=40, high=60)
        sources = self.analysis()["sources"]
        self.assertIsNone(sources["hrv"]["current"]["summary"]["avg"]["unit"])
        self.assertEqual(set(sources["all_day_heart_rate"]["current"]["summary"]), {"min", "max"})
        self.assertNotIn("999", json.dumps(sources["all_day_heart_rate"]))
        self.assertEqual(sources["spo2"]["current"]["summary"]["min"]["mean"], 40)
        self.assertEqual(sources["spo2"]["current"]["summary"]["max"]["unit"], "percent")

    def test_zero_counts_invalid_numbers_and_missing_fields_are_not_measurements(self):
        self.initialize()
        self.metric("hrv", "2024-03-01", avg=0, count=0)
        self.metric("hrv", "2024-03-02", avg=float("inf"))
        self.metric("hrv", "2024-03-03", avg=-1)
        self.metric("hrv", "2024-03-04", avg=10)
        current = self.analysis()["sources"]["hrv"]["current"]
        self.assertEqual(current["coverage"]["observed_day_count"], 4)
        self.assertEqual(current["coverage"]["usable_day_count"], 1)
        self.assertEqual(current["summary"]["avg"]["mean"], 10)
        self.assertIsNone(current["underlying_samples"]["known_count_sum"])
        self.assertEqual(current["underlying_samples"]["usable_days_with_unknown_count"], 1)
        self.assertEqual(current["daily"][0]["exclusion_reasons"], ["zero_measurement_count"])

    def test_daily_duplicates_and_wrong_timezone_are_excluded_not_averaged(self):
        self.initialize()
        self.metric("hrv", "2024-03-01", avg=10)
        self.metric("hrv", "2024-03-01", avg=20)
        self.metric("hrv", "2024-03-02", avg=20, time_zone="+0000")
        self.metric("hrv", "2024-03-03", avg=20, field_name=MARKER)
        current = self.analysis()["sources"]["hrv"]["current"]
        self.assertEqual(current["coverage"]["observed_record_count"], 4)
        self.assertEqual(current["summary"]["avg"]["sample_count"], 0)
        self.assertIn("duplicate_daily_records", current["daily"][0]["exclusion_reasons"])

    def test_retained_values_excluded_fieldwise_not_entire_daily_row(self):
        self.initialize(quality=True)
        self.metric("spo2", "2024-03-04", avg=10, low=5, high=15, count=0)
        self.quality("spo2", "2024-03-04", "avg", 1)
        self.quality("spo2", "2024-03-04", "min", 0)
        self.quality("spo2", "2024-03-04", "count", 1)
        source = self.analysis()["sources"]["spo2"]
        self.assertIsNone(source["current"]["summary"]["avg"]["mean"])
        self.assertEqual(source["current"]["summary"]["min"]["mean"], 5)
        self.assertIsNone(source["current"]["daily"][0]["sample_count"])
        self.assertEqual(source["current"]["quality"]["retained_field_count"], 2)
        self.assertIn("retained_values_excluded", source["warnings"])
        self.assertIn("some_field_provenance_unknown", source["warnings"])

    def test_missing_or_malformed_quality_never_means_all_fresh(self):
        self.initialize()
        self.metric("hrv", "2024-03-04", avg=10)
        for expected, ddl in (("legacy_unknown", None), ("available", "good"), ("unavailable_schema", "bad")):
            if ddl is not None:
                with self.db() as db:
                    db.execute("DROP TABLE IF EXISTS health_record_quality")
                    if ddl == "good":
                        self.create_quality(db)
                    else:
                        db.execute("CREATE TABLE health_record_quality(unknown_column TEXT)")
            result = self.analysis()
            self.assertEqual(result["provenance"]["table_status"], expected)
            source = result["sources"]["hrv"]["current"]
            self.assertEqual(source["summary"]["avg"]["mean"], 10)
            self.assertGreater(source["quality"]["unknown_provenance_field_count"], 0)

    def test_invalid_retention_flag_excludes_field_without_leaking_metadata(self):
        self.initialize(quality=True)
        self.metric("hrv", "2024-03-04", avg=10)
        self.quality("hrv", "2024-03-04", "avg", MARKER, last_valid=MARKER)
        current = self.analysis()["sources"]["hrv"]["current"]
        self.assertIsNone(current["summary"]["avg"]["mean"])
        self.assertEqual(current["quality"]["invalid_metadata_field_count"], 1)

    def test_sleep_waking_date_main_short_additional_and_raw_codes(self):
        self.initialize()
        self.sleep("2024-03-02T17:00:00+00:00", "2024-03-02T22:00:00+00:00", 240, code=91)
        self.sleep("2024-03-03T04:00:00+00:00", "2024-03-03T07:30:00+00:00", 180, code=92)
        self.sleep("2024-03-03T09:00:00+00:00", "2024-03-03T10:00:00+00:00", 30, code=93)
        current = self.analysis()["sources"]["sleep"]["current"]
        self.assertEqual(current["coverage"]["observed_dates"], ["2024-03-03"])
        self.assertEqual(current["summary"]["main_sleep_minutes"]["mean"], 240)
        self.assertEqual(current["summary"]["short_additional_sleep_minutes"]["sum"], 30)
        day = current["daily"][0]
        self.assertEqual(day["main_sleep"]["fields"]["sleep_type"], 91)
        self.assertEqual(day["other_long_sessions"][0]["fields"]["total_sleep_minutes"], 180)
        self.assertIn("sleep_latency_minutes", day["main_sleep"]["missing_fields"])
        self.assertIsNone(day["main_sleep"]["fields"]["deep_sleep_minutes"])

    def test_sleep_overlapping_duplicates_exclude_all_members_without_inflation(self):
        self.initialize()
        for code in (1, 2):
            self.sleep("2024-03-02T17:00:00+00:00", "2024-03-02T23:00:00+00:00", 300, code)
        self.sleep("2024-03-02T22:30:00+00:00", "2024-03-03T00:00:00+00:00", 60, 3)
        current = self.analysis()["sources"]["sleep"]["current"]
        self.assertEqual(current["session_counts"], {"observed": 3, "main": 0, "short_additional": 0, "other_long": 0, "excluded": 3})
        self.assertEqual(current["daily"][0]["main_selection_status"], "ambiguous_overlap")
        self.assertIsNone(current["summary"]["main_sleep_minutes"]["mean"])
        self.assertTrue(all("overlapping_or_duplicate_session" in r["exclusion_reasons"] for r in current["daily"][0]["excluded_sessions"]))

    def test_sleep_overlap_outside_range_and_tied_longest_are_ambiguous(self):
        self.initialize()
        self.sleep("2024-03-03T13:00:00+00:00", "2024-03-03T15:59:00+00:00", 179, 1)
        self.sleep("2024-03-03T15:00:00+00:00", "2024-03-03T21:00:00+00:00", 300, 2)
        current = self.analysis(start="2024-03-04", end="2024-03-04")["sources"]["sleep"]["current"]
        self.assertIsNone(current["daily"][0]["main_sleep"])
        self.assertEqual(current["session_counts"]["excluded"], 1)
        self.sleep("2024-03-01T17:00:00+00:00", "2024-03-01T21:00:00+00:00", 240, 3)
        self.sleep("2024-03-02T04:00:00+00:00", "2024-03-02T08:00:00+00:00", 240, 4)
        tied = self.analysis(start="2024-03-02", end="2024-03-02")["sources"]["sleep"]["current"]
        self.assertEqual(tied["daily"][0]["main_selection_status"], "ambiguous_longest_tie")
        self.assertIsNone(tied["summary"]["main_sleep_minutes"]["mean"])
        self.assertEqual(tied["session_counts"]["other_long"], 2)

    def test_sleep_missing_duration_retained_score_and_end_fallback(self):
        self.initialize(quality=True)
        key = self.sleep("2024-03-02T17:00:00+00:00", "2024-03-02T22:00:00+00:00", 240, sleep_score=80, wakeup_time_utc=None)
        self.quality("sleep", key, "sleep_score", 1)
        self.sleep("2024-03-03T17:00:00+00:00", "2024-03-03T22:00:00+00:00", None)
        current = self.analysis()["sources"]["sleep"]["current"]
        self.assertEqual(current["summary"]["main_sleep_minutes"]["sample_count"], 1)
        main = current["daily"][0]["main_sleep"]
        self.assertEqual(main["waking_date_basis"], "end_time_utc_fallback")
        self.assertIsNone(main["fields"]["sleep_score"])
        self.assertIn("missing_or_retained_total_sleep_minutes", current["daily"][1]["excluded_sessions"][0]["exclusion_reasons"])

    def test_sleep_incomplete_and_retained_end_are_not_current_valid(self):
        self.initialize(quality=True)
        key = self.sleep("2024-03-03T17:00:00+00:00", "2024-03-03T22:00:00+00:00", 240)
        self.quality("sleep", key, "end_time_utc", 1)
        self.sleep("2024-03-05T01:00:00+00:00", "2024-03-05T05:00:00+00:00", 200)
        current = self.analysis(include_today=True)["sources"]["sleep"]["current"]
        self.assertEqual(current["summary"]["main_sleep_minutes"]["sample_count"], 0)
        self.assertEqual(current["session_counts"]["excluded"], 2)
        self.assertIn("session_not_completed_as_of_now", current["daily"][-1]["excluded_sessions"][0]["exclusion_reasons"])

    def test_workout_counts_durations_distances_are_not_all_day_activity(self):
        self.initialize()
        self.workout("2024-03-01T00:00:00+00:00", 20, 100, code="raw.7")
        self.workout("2024-03-03T00:00:00+00:00", 40, None)
        current = self.analysis()["sources"]["activities"]["current"]
        self.assertEqual(current["usable_workout_count"], 2)
        self.assertEqual(current["summary"]["duration_ms"]["sum"], 60 * 60000)
        self.assertEqual(current["summary"]["distance_m"]["sum"], 100)
        self.assertEqual(current["summary"]["distance_m"]["sample_count"], 1)
        self.assertEqual(current["daily"][0]["records"][0]["values"]["activity_type"], "raw.7")
        self.assertEqual(len(current["daily"]), 2)
        self.assertNotIn("steps", current)

    def test_activity_provenance_uses_exact_composite_identity(self):
        self.initialize(quality=True)
        key = self.workout("2024-03-01T00:00:00+00:00", 20, 100)
        self.quality("activities", key, "duration_ms", 1)
        self.quality("activities", key, "distance_m", 0)
        source = self.analysis()["sources"]["activities"]
        self.assertIsNone(source["current"]["summary"]["duration_ms"]["sum"])
        self.assertEqual(source["current"]["summary"]["distance_m"]["sum"], 100)
        self.assertEqual(source["current"]["quality"]["retained_field_count"], 1)
        self.assertEqual(source["current"]["usable_workout_count"], 1)

    def test_overlapping_workouts_excluded_from_counts_and_totals(self):
        self.initialize()
        self.workout("2024-03-01T00:00:00+00:00", 60, 100, 1)
        self.workout("2024-03-01T00:30:00+00:00", 60, 100, 2)
        current = self.analysis()["sources"]["activities"]["current"]
        self.assertEqual(current["observed_workout_count"], 2)
        self.assertEqual(current["usable_workout_count"], 0)
        self.assertIsNone(current["summary"]["duration_ms"]["sum"])

    def test_old_vo2_point_is_not_weekly_signal_but_newest_time_remains_available(self):
        self.initialize()
        stamp = ns(datetime(2023, 12, 1, tzinfo=timezone.utc)) + 123456789
        self.point(stamp, 137)
        source = self.analysis()["sources"]["vo2max"]
        self.assertEqual(source["current"]["summary"]["value"]["sample_count"], 0)
        self.assertEqual(source["baseline"]["summary"]["value"]["sample_count"], 0)
        latest = source["latest_saved_measurement"]
        self.assertEqual(latest["measured_at_ns"], stamp)
        self.assertEqual(latest["measured_at_utc"], ns_stamp(stamp))
        self.assertFalse(latest["within_scope"])
        self.assertNotIn("value", latest)
        self.assertNotIn("start_time_utc", json.dumps(source))

    def test_vo2_nanoseconds_utc8_date_boundary_baseline_and_unknown_unit(self):
        self.initialize()
        boundary = ns(datetime(2024, 3, 4, 16, 0, tzinfo=timezone.utc))
        self.point(boundary - 1, 20)
        self.point(boundary, 100)
        self.point(ns(datetime(2024, 2, 26, tzinfo=timezone.utc)), 10)
        source = self.analysis()["sources"]["vo2max"]
        self.assertEqual(source["current"]["summary"]["value"]["mean"], 20)
        self.assertEqual(source["comparison"]["value"]["mean_delta"], 10)
        self.assertIsNone(source["current"]["summary"]["value"]["unit"])
        self.assertEqual(source["current"]["daily"][0]["date"], "2024-03-04")
        self.assertEqual(source["current"]["daily"][0]["measurements"][0]["measured_at_ns"], boundary - 1)
        included = self.analysis(include_today=True)["sources"]["vo2max"]["current"]
        self.assertEqual(included["summary"]["value"]["mean"], 60)
        self.assertTrue(included["daily"][-1]["incomplete"])

    def test_vo2_retained_future_and_inconsistent_timestamps_are_not_used(self):
        self.initialize(quality=True)
        key = self.point(ns(datetime(2024, 3, 3, tzinfo=timezone.utc)), 20)
        self.quality("vo2max", key, "value", 1)
        self.point(ns(NOW) + 1, 30)
        self.point(ns(datetime(2024, 3, 4, tzinfo=timezone.utc)), 40, measured_at_utc=MARKER)
        source = self.analysis()["sources"]["vo2max"]
        self.assertEqual(source["invalid_saved_record_count"], 2)
        self.assertEqual(source["current"]["summary"]["value"]["sample_count"], 0)
        self.assertFalse(source["latest_saved_measurement"]["value_usable"])
        self.assertEqual(source["current"]["quality"]["retained_field_count"], 1)

    def test_collection_metadata_does_not_claim_auth_or_complete_history(self):
        self.initialize()
        with self.db() as db:
            db.execute("INSERT INTO health_source_state VALUES (?,?,?,?,?,?,?,?,?,?)",
                       ("hrv", "transport_error", NOW.isoformat(), (NOW - timedelta(hours=1)).isoformat(), 0, 0, "coverage_limited", "partial", 7, None))
            db.execute("INSERT INTO health_sync_state VALUES (1,?,?,?,?,?)",
                       ("reauth_required", NOW.isoformat(), None, 1, MARKER))
        result = self.analysis()
        collection = result["sources"]["hrv"]["collection"]
        self.assertEqual(collection["status"], "transport_error")
        self.assertEqual(collection["freshness"], "collection_failed")
        self.assertEqual(collection["last_success_age_seconds"], 3600)
        self.assertEqual(collection["coverage"], "coverage_limited")
        self.assertTrue(result["collection"]["saved_authentication_required"])
        self.assertEqual(result["collection"]["authentication"], "not_checked")
        self.assertFalse(result["complete_history"])

    def test_legacy_database_supported_without_schema_migration_or_auth(self):
        with app.Store(self.state, create=True) as store:
            store.record("partial", NOW.isoformat(), None)
        result = self.analysis()
        self.assertEqual(result["sources"]["activities"]["collection"]["coverage"], "legacy_latest_only")
        self.assertEqual(result["provenance"]["table_status"], "legacy_unknown")
        with self.db() as db:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertEqual(tables, {"activities", "collection_state"})

    def test_deterministic_readonly_snapshot_has_no_file_or_database_mutation(self):
        self.initialize(quality=True)
        self.metric("hrv", "2024-03-04", avg=10)
        database = self.state / app.DATABASE_NAME
        before = (database.read_bytes(), database.stat().st_mtime_ns, sorted(p.name for p in self.state.iterdir()))
        first = self.analysis()
        second = self.analysis()
        after = (database.read_bytes(), database.stat().st_mtime_ns, sorted(p.name for p in self.state.iterdir()))
        self.assertEqual(first, second)
        self.assertEqual(before, after)
        self.assertIn("BEGIN", self.read_statements)
        self.assertFalse(set(self.read_statements) - {"SELECT", "PRAGMA", "BEGIN", "ROLLBACK"})

    def test_short_sleep_coverage_does_not_claim_missing_main_is_zero(self):
        self.initialize()
        self.sleep("2024-03-03T04:00:00+00:00", "2024-03-03T04:30:00+00:00", 20)
        current = self.analysis()["sources"]["sleep"]["current"]
        self.assertEqual(current["coverage"]["usable_record_count"], 1)
        self.assertEqual(current["coverage"]["excluded_record_count"], 0)
        self.assertEqual(current["coverage"]["usable_dates"], ["2024-03-03"])
        self.assertEqual(current["summary"]["main_sleep_minutes"]["usable_dates"], [])
        self.assertIn("2024-03-03", current["summary"]["main_sleep_minutes"]["missing_usable_dates"])
        self.assertIsNone(current["summary"]["main_sleep_minutes"]["sum"])

    def test_provenance_lookup_uses_saved_timestamp_without_normalizing_key(self):
        self.initialize(quality=True)
        key = self.workout("2024-03-01T00:00:00.000000+00:00", 20, 100)
        self.quality("activities", key, "distance_m", 1)
        current = self.analysis()["sources"]["activities"]["current"]
        self.assertIsNone(current["summary"]["distance_m"]["sum"])
        self.assertEqual(current["quality"]["retained_field_count"], 1)
        self.assertEqual(self.analysis(now=NOW.astimezone(a.LOCAL_ZONE)), self.analysis(now=NOW))

    def test_saved_auth_check_failure_is_metadata_only(self):
        self.initialize()
        with self.db() as db:
            db.execute("INSERT INTO health_sync_state VALUES (1,?,?,?,?,?)",
                       ("auth_check_error", NOW.isoformat(), None, 0, MARKER))
        result = self.analysis()
        self.assertEqual(result["collection"]["last_status"], "auth_check_error")
        self.assertEqual(result["collection"]["authentication"], "not_checked")
        self.assertEqual(result["sources"]["hrv"]["status"], "not_collected")

    def test_storage_exception_does_not_echo_paths_or_saved_data(self):
        with patch.object(app, "Store", side_effect=app.StorageError(MARKER)):
            with self.assertRaises(app.StorageError) as error:
                self.analysis()
            self.assertEqual(str(error.exception), "")
        self.state.mkdir(mode=0o700)
        database = self.state / app.DATABASE_NAME
        with os.fdopen(os.open(database, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as handle:
            handle.write(b"SYNTHETIC_NOT_A_DATABASE")
        with self.assertRaises(app.StorageError) as error:
            self.analysis()
        self.assertEqual(str(error.exception), "")


if __name__ == "__main__":
    unittest.main()
