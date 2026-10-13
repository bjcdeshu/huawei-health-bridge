"""Synthetic history tests; explicit TMPDIR, guarded storage and no real HTTP.

Run from the source copy:
TMPDIR=/var/lib/hermes/cache/scratch /usr/bin/python3 -B -m unittest test_history
The production auth/DB/browser/profile trees are never read. Any isolation
violation, even if swallowed by an adapter, fails tearDown. Fixtures are invented.
"""
import builtins
import fcntl
import io
import json
import os
import socket
import sqlite3
import ssl
import stat
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch
from urllib import error, parse, request

import app
import collector
import health_history as history
import health_sources as sources
import sleep_collector as sleep

NOW = datetime(2026, 10, 12, 8, 30, 12, 345000, tzinfo=timezone.utc)
AUTH = {"Authorization": "SYNTHETIC_HISTORY_TOKEN", "x-client-id": "SYNTHETIC_HISTORY_CLIENT"}
NEW_AUTH = {**AUTH, "Authorization": "SYNTHETIC_CHANGED_VERIFIED_TOKEN"}
MARKER = "SYNTHETIC_RAW_ID_NAME_GPS_SECRET_NEVER_PERSIST"
START, END = "2026-09-01", "2026-09-07"


def response(raw, code=200, content_type="application/json"):
    return collector.Response(code, json.dumps(raw).encode(), content_type)


def activity(start_ms, **changes):
    raw = dict(startTime=start_ms, endTime=start_ms + 1800000, activityType=56,
               activeTime=1800000, activityName=MARKER, id=MARKER, gps=MARKER,
               activitySummary={"dataSummary": {"com.huawei.continuous.distance.total": {
                   "value": [{"fieldName": "distance", "floatValue": 5000}]}},
                   "performanceSummary": {"aerobicTrainingStress": 30}})
    return {**raw, **changes}


def sleep_record(start_ns, **changes):
    values = [{"fieldName": name, "longValue": start_ns // 1000000 + 300000}
              for name in sleep.TIME_FIELDS]
    values += [{"fieldName": name, "integerValue": 40} for name in sleep.MINUTE_FIELDS]
    values += [{"fieldName": name, "integerValue": 2} for name in sleep.INT_FIELDS]
    values += [{"fieldName": MARKER, "longValue": 1234}]
    return {**dict(startTime=start_ns, endTime=start_ns + 3600 * 1000000000,
                   value=values, id=MARKER, fragments=MARKER, gps=MARKER), **changes}


def stats(metric, first="2026-09-01", last=None, *, count=2, block=None):
    field_name = sources.METRICS[metric][2]
    block = dict(avg=54.5, min=50, max=59, sum=109, count=count) if block is None else block
    days = sorted({first, last or first})
    entries = [dict(fieldName=field_name, startDay=int(day.replace("-", "")),
                    statistics=block, id=MARKER) for day in days]
    return dict(results=[dict(fieldName=field_name, statistics=block, raw=MARKER)],
                groupResults=[dict(groupStatistics=entries, name=MARKER)])


class FakeTransport:
    def __init__(self, handler=None, *, empty=False):
        self.calls = []
        self.handler = handler
        self.empty = empty

    def send(self, method, url, headers, body):
        history.check_request(method, url, body, now=NOW)
        if method == "GET":
            params = dict(parse.parse_qsl(parse.urlsplit(url).query))
            source, divisor = "sleep", 1000000000
            low, high = int(params["startTime"]), int(params["endTime"])
        else:
            params = json.loads(body)
            if url == sources.ACTIVITIES_URL:
                source, divisor = "activities", 1000
                low, high = int(params["startTime"]), int(params["endTime"])
            else:
                item = params["reqs"][0]
                source = next(name for name in history.SOURCE_NAMES[2:]
                              if sources.METRICS[name][1] == item["dataType"])
                first, last = sources.day_string(item["startDay"]), sources.day_string(item["endDay"])
        if source in ("sleep", "activities"):
            first = sleep.stamp(low, divisor)
            last = sleep.stamp(high, divisor)
            first = datetime.fromisoformat(first).astimezone(sources.LOCAL_ZONE).date().isoformat()
            last = datetime.fromisoformat(last).astimezone(sources.LOCAL_ZONE).date().isoformat()
        call = dict(method=method, url=url, source=source, params=params, headers=dict(headers),
                    start_day=first, end_day=last)
        self.calls.append(call)
        if self.handler is not None:
            value = self.handler(call)
            if isinstance(value, Exception):
                raise value
            if value is not None:
                return value
        if source == "activities":
            return response([] if self.empty else [activity(low + 3600000)])
        if source == "sleep":
            return response({"healthRecords": [] if self.empty else [sleep_record(low + 3600 * 1000000000)]})
        return response(dict(results=[], groupResults=[]) if self.empty else stats(source, first, last))


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="history-tests-", dir=os.environ["TMPDIR"])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "private"
        self.violations = []
        original_store, original_open = app.Store, os.open
        original_connect, original_io_open, original_builtin_open = sqlite3.connect, io.open, builtins.open
        original_stat, original_lstat, original_mkdir = os.stat, os.lstat, os.mkdir

        def safe(path, dir_fd=None):
            if isinstance(path, int):
                return True
            value = os.fsdecode(path)
            if value.startswith("file:"):
                value = value[5:].split("?", 1)[0]
            if value.startswith("/proc/self/fd/"):
                pieces = value.split("/")
                value = os.readlink("/proc/self/fd/" + pieces[4]) + "/" + "/".join(pieces[5:])
            if dir_fd is not None:
                value = os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), value)
            return Path(os.path.abspath(os.path.normpath(value))).is_relative_to(self.root)

        def reject(label):
            self.violations.append(label)
            raise AssertionError(label)

        def guarded_store(state_dir, **kwargs):
            if Path(state_dir) != self.state:
                reject("store_outside_explicit_TMPDIR")
            return original_store(state_dir, **kwargs)

        def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
            if not safe(path, dir_fd):
                reject("os_open_outside_explicit_TMPDIR")
            return original_open(path, flags, mode, dir_fd=dir_fd)

        def guarded_connect(path, *args, **kwargs):
            if not safe(path):
                reject("sqlite_outside_explicit_TMPDIR")
            return original_connect(path, *args, **kwargs)

        def guarded_file(original):
            def open_file(path, *args, **kwargs):
                # traceback source reads are permitted; health/private data is not.
                if not safe(path) and not (isinstance(path, (str, Path)) and str(path).endswith(".py")):
                    reject("file_read_outside_explicit_TMPDIR")
                return original(path, *args, **kwargs)
            return open_file

        def guarded_metadata(original):
            def read_meta(path, *args, **kwargs):
                if not isinstance(path, int) and os.fsdecode(path).startswith((
                        "/var/lib/huawei-training-camp", "/var/lib/hermes/profiles/")):
                    reject("production_metadata_forbidden")
                return original(path, *args, **kwargs)
            return read_meta

        def guarded_mkdir(path, mode=0o777, *, dir_fd=None):
            if not safe(path, dir_fd):
                reject("mkdir_outside_explicit_TMPDIR")
            return original_mkdir(path, mode, dir_fd=dir_fd)

        for guard in (
            patch.object(app, "Store", side_effect=guarded_store),
            patch.object(app, "load_auth", side_effect=lambda *a, **k: reject("credential_read_forbidden")),
            patch.object(os, "open", side_effect=guarded_open),
            patch.object(os, "mkdir", side_effect=guarded_mkdir),
            patch.object(os, "stat", side_effect=guarded_metadata(original_stat)),
            patch.object(os, "lstat", side_effect=guarded_metadata(original_lstat)),
            patch.object(sqlite3, "connect", side_effect=guarded_connect),
            patch.object(builtins, "open", side_effect=guarded_file(original_builtin_open)),
            patch.object(io, "open", side_effect=guarded_file(original_io_open)),
            patch.object(history, "utc_now", return_value=NOW),
            patch.object(request.OpenerDirector, "open", side_effect=lambda *a, **k: reject("real_HTTP_forbidden")),
            patch.object(request, "urlopen", side_effect=lambda *a, **k: reject("real_urlopen_forbidden")),
            patch.object(socket.socket, "connect", side_effect=lambda *a, **k: reject("real_socket_forbidden")),
            patch.object(socket, "create_connection", side_effect=lambda *a, **k: reject("real_connection_forbidden")),
        ):
            guard.start()
            self.addCleanup(guard.stop)

    def tearDown(self):
        self.assertEqual(self.violations, [], "an isolation violation was caught or suppressed")

    def run_history(self, transport=None, provider=None, **kwargs):
        return history.run_backfill(self.state, provider or (lambda: AUTH),
            start=kwargs.pop("start", START), end=kwargs.pop("end", END),
            transport=transport if transport is not None else FakeTransport(), **kwargs)

    def db(self):
        return sqlite3.connect(self.state / app.DATABASE_NAME)

    def assert_private(self, payload):
        text = json.dumps(payload)
        for forbidden in (MARKER, *AUTH.values(), NEW_AUTH["Authorization"], "token_hash",
                          "Authorization", "x-client-id", "distance_m", "training_load",
                          "sleep_score", '"avg"', '"min"', '"max"', '"records"'):
            self.assertNotIn(forbidden, text)

    def test_plan_365_calendar_days_exact_partition(self):
        windows = history.plan_windows(now=NOW)
        days = [date.fromisoformat(first) + timedelta(days=offset)
                for first, last in windows
                for offset in range((date.fromisoformat(last) - date.fromisoformat(first)).days + 1)]
        today = NOW.astimezone(sources.LOCAL_ZONE).date()
        self.assertEqual(len(days), 365)
        self.assertEqual(len(set(days)), len(days))
        self.assertEqual(days, [today - timedelta(days=offset) for offset in reversed(range(365))])
        self.assertEqual(len(windows), (365 + 29) // 30)
        self.assertTrue(all(0 <= (date.fromisoformat(last) - date.fromisoformat(first)).days < 30 for first, last in windows))

    def test_leap_day_inclusive_and_no_gap_or_overlap(self):
        leap_now = datetime(2024, 3, 3, 0, tzinfo=timezone.utc)
        windows = history.plan_windows(5, end="2024-03-02", window_days=2, now=leap_now)
        self.assertEqual(windows, [("2024-02-27", "2024-02-28"),
                                  ("2024-02-29", "2024-03-01"), ("2024-03-02", "2024-03-02")])
        for left, right in zip(windows, windows[1:]):
            self.assertEqual(date.fromisoformat(left[1]) + timedelta(days=1), date.fromisoformat(right[0]))

    def test_plan_rejects_future_out_of_year_invalid_and_bool(self):
        cases = [dict(days=True), dict(days=0), dict(days=366), dict(window_days=31),
                 dict(window_days=False), dict(start=START), dict(start=END, end=START),
                 dict(start="2026-02-30", end=END), dict(start="٢٠٢٦-٠٩-٠١", end=END),
                 dict(start="2025-10-12", end="2025-10-12"), dict(end="2026-10-13", days=1),
                 dict(now=NOW.replace(tzinfo=None)), dict(start=NOW, end=END)]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(app.InvalidArguments):
                history.plan_windows(**kwargs)

    def test_fetch_validates_every_option_before_transport_or_state(self):
        transport = Mock()
        for source, first, last, kwargs in [
            ("gps", START, END, {}), ("sleep", "2026-08-01", "2026-08-31", {}),
            ("activities", START, END, {"activity_limit": True}),
            ("resting_hr", "2026-10-13", "2026-10-13", {}),
            ("hrv", "2025-10-12", "2025-10-12", {})]:
            with self.assertRaises(app.InvalidArguments):
                history.fetch_window(AUTH, source, first, last, transport, **kwargs)
        transport.send.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_sleep_GET_ns_activity_POST_str_ms_and_historical_not_now(self):
        fake = FakeTransport()
        for source in ("sleep", "activities"):
            result = history.fetch_window(AUTH, source, START, END, fake)
            self.assertEqual(len(result.records), 1)
        get, post = fake.calls
        self.assertEqual((get["method"], post["method"]), ("GET", "POST"))
        self.assertEqual(set(get["params"]), {"startTime", "endTime", "dataType"})
        self.assertEqual(get["params"]["dataType"], sleep.DATA_TYPE)
        self.assertNotIn('subDataType',get['params'])
        self.assertIs(type(post["params"]["startTime"]), str)
        self.assertIs(type(post["params"]["endTime"]), str)
        self.assertEqual(post["params"]["limit"], 100)
        self.assertEqual(post["params"]["order"], "endTimeDesc")
        low_ms, high_ms = map(int, (post["params"]["startTime"], post["params"]["endTime"]))
        self.assertEqual(int(get["params"]["startTime"]), low_ms * 1000000)
        self.assertEqual(int(get["params"]["endTime"]) + 1, (high_ms + 1) * 1000000)
        self.assertEqual(high_ms - low_ms + 1, 7 * 86400000)
        self.assertLess(high_ms, history._units(NOW, 1000))
        self.assertEqual(get["headers"], AUTH)
        self.assertEqual(post["headers"]["Content-Type"], "application/json")

    def test_adjacent_wire_boundaries_do_not_overlap_and_today_not_future(self):
        windows = history.plan_windows(32, window_days=30)
        for divisor in (1000, 1000000000):
            bounds = [history._bounds(date.fromisoformat(first), date.fromisoformat(last), divisor, NOW)
                      for first, last in windows]
            self.assertEqual(bounds[0][1] + 1, bounds[1][0])
            self.assertEqual(bounds[-1][1], history._units(NOW, divisor))
        fake = FakeTransport(empty=True)
        history.fetch_window(AUTH, "activities", "2026-10-12", "2026-10-12", fake)
        self.assertEqual(int(fake.calls[0]["params"]["endTime"]), history._units(NOW, 1000))

    def test_metric_exact_calendar_types_req_group_equality_COUNT(self):
        fake = FakeTransport()
        for metric in history.SOURCE_NAMES[2:]:
            self.assertEqual(history.fetch_window(AUTH, metric, START, END, fake).status, "ok")
            call = fake.calls[-1]
            dto = call["params"]
            self.assertEqual(set(dto), {"reqs", "groupReqs"})
            self.assertEqual(dto["reqs"], dto["groupReqs"])
            item = dto["reqs"][0]
            self.assertIs(type(item["startDay"]), str if metric == "hrv" else int)
            self.assertIs(type(item["endDay"]), str if metric == "hrv" else int)
            self.assertEqual((str(item["startDay"]), str(item["endDay"])), ("20260901", "20260907"))
            self.assertEqual(item["strategy"], ["MAX", "MIN", "AVG", "SUM", "COUNT"])
            self.assertEqual((item["groupOption"], item["timeZone"]), ("day", "+0800"))
            self.assertEqual(item.get("fieldNames"), [sources.METRICS[metric][2]] if metric == "hrv" else None)

    def test_metric_descriptors_read_dynamically_not_copied(self):
        fake = FakeTransport()
        replacement = (sources.RESTING_HR_URL, "com.huawei.synthetic.allowed.resting_heart_rate", "syntheticBpm", "bpm")
        with patch.dict(sources.METRICS, resting_hr=replacement):
            result = history.fetch_window(AUTH, "resting_hr", START, END, fake)
            self.assertEqual(result.records[0]["field_name"], "syntheticBpm")
            self.assertEqual(fake.calls[-1]["params"]["reqs"][0]["dataType"], replacement[1])
            self.run_history(fake, source_names=["resting_hr"])
            with self.db() as db:
                self.assertEqual(db.execute("SELECT field_name FROM metric_stats LIMIT 1").fetchone(), ("syntheticBpm",))

    def test_strict_request_allowlist_rejects_units_types_keys_and_redirect_targets(self):
        first, last = date.fromisoformat(START), date.fromisoformat(END)
        method, url, body = history._payload("activities", first, last, NOW, 100)
        original = json.loads(body)
        for change in ({"startTime": int(original["startTime"])}, {"limit": True},
                       {"order": "startTimeAsc"}, {"detailDataType": ["gps"]},
                       {"startTime": str(int(original["startTime"]) * 1000000)}):
            with self.assertRaises((ValueError, app.InvalidArguments)):
                history.check_request(method, url, json.dumps({**original, **change}).encode())
        for bad_method, bad_url in (("GET", url), ("POST", url + "#fragment"),
                                    ("POST", url + "/detail"), ("POST", "http://example.invalid")):
            with self.assertRaises(ValueError):
                history.check_request(bad_method, bad_url, body)
        method, url, body = history._payload("sleep", first, last, NOW, 100)
        for bad_url, bad_body in ((url + "&startTime=1", body), (url + "#fragment", body),
                                  (url.replace("startTime=", "startTime=0"), body),
                                  (url+'&subDataType=gps', body), (url, b"{}")):
            with self.assertRaises(ValueError):
                history.check_request(method, bad_url, bad_body)
        for name in history.SOURCE_NAMES[2:]:
            method, url, body = history._payload(name, first, last, NOW, 100)
            item = json.loads(body)["reqs"][0]
            for change in ({"startDay": int(item["startDay"]) if name == "hrv" else str(item["startDay"])},
                           {"endDay": True}, {"strategy": list(history.STRATEGIES[:-1])},
                           {"timeZone": "UTC"}, {"fieldNames": ["gps"]}):
                bad = {**item, **change}
                with self.assertRaises(ValueError):
                    history.check_request(method, url, json.dumps(dict(reqs=[bad], groupReqs=[bad])).encode())
            with self.assertRaises(ValueError):
                history.check_request(method, url, json.dumps(dict(reqs=[item], groupReqs=[])).encode())

    def test_shared_metric_analyser_count_zero_no_measurements_no_duplicates(self):
        raw = stats("resting_hr", count=0, block=dict(avg=0, min=0, max=0, sum=0, count=0))
        fake = FakeTransport(lambda call: response(raw))
        with patch.object(sources, "analyse_metric", wraps=sources.analyse_metric) as analyse:
            result = history.fetch_window(AUTH, "resting_hr", START, END, fake)
            analyse.assert_called_once()
        self.assertEqual((result.status, result.received_count, result.records, result.coverage),
                         ("empty", 1, [], "queried"))
        output = self.run_history(fake, source_names=["resting_hr"])
        self.assertEqual((output["status"], output["received_records"], output["stored_records"]), ("empty", 1, 0))
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM metric_stats").fetchone()[0], 0)
        self.assert_private(output)

    def test_unknown_count_remains_null_not_zero_and_duplicate_day_first_wins(self):
        raw = stats("hrv", block=dict(avg=64, min=50, max=70))
        raw["groupResults"][0]["groupStatistics"].append(
            dict(fieldName="avgHrv", startDay=20260901, statistics=dict(avg=99, count=3)))
        result = history.fetch_window(AUTH, "hrv", START, END, FakeTransport(lambda call: response(raw)))
        self.assertEqual(len(result.records), 1)
        self.assertEqual((result.records[0]["avg"], result.records[0]["count"], result.records[0]["unit"]), (64, None, None))

    def test_unknown_business_errors_duplicate_JSON_and_oversize_not_empty(self):
        malformed = [{"error": MARKER}, {}, {"results": None, "groupResults": []},
                     {"results": [], "groupResults": [{}]},
                     {"results": [{"fieldName": "unknown", "statistics": {}}], "groupResults": []}]
        for raw in malformed:
            result = history.fetch_window(AUTH, "hrv", START, END, FakeTransport(lambda call, raw=raw: response(raw)))
            self.assertEqual((result.status, result.coverage, result.records), ("invalid_response", "not_assessed", []))
        for body in (b'{"results":[],"results":[],"groupResults":[]}', b"not-json", b"x" * (history.MAX_BODY + 1)):
            fake = FakeTransport(lambda call, body=body: collector.Response(200, body))
            self.assertEqual(history.fetch_window(AUTH, "hrv", START, END, fake).status, "invalid_response")
        with self.assertRaises(ValueError):
            history.check_request("POST", sources.ACTIVITIES_URL, b"x" * (history.MAX_REQUEST_BODY + 1))

    def test_out_of_window_records_rejected_for_every_source(self):
        low_ms = history._bounds(date.fromisoformat(START), date.fromisoformat(END), 1000, NOW)[0]
        for name in history.SOURCE_NAMES:
            if name == "activities":
                raw = [activity(low_ms - 1)]
            elif name == "sleep":
                raw = {"healthRecords": [sleep_record(low_ms * 1000000 - 3600*10**9,endTime=low_ms*1000000-1)]}
            else:
                raw = stats(name, "2026-08-31")
            result = history.fetch_window(AUTH, name, START, END, FakeTransport(lambda call, raw=raw: response(raw)))
            self.assertEqual((result.status, result.records, result.coverage), ("invalid_response", [], "not_assessed"), name)

    def test_end_times_outside_window_and_wrong_units_not_accepted(self):
        low, high = history._bounds(date.fromisoformat(START), date.fromisoformat(END), 1000, NOW)
        cases = [
            ("activities", [activity(low + 3600000, endTime=high + 1)]),
            ("activities", [activity((low + 3600000) * 1000000)]),
            ("sleep", {"healthRecords": [sleep_record(low + 3600000)]}),
            ("sleep", {"healthRecords": [sleep_record((low + 3600000) * 1000000,
                endTime=(high + 1) * 1000000)]})]
        for name, raw in cases:
            result = history.fetch_window(AUTH, name, START, END, FakeTransport(lambda call, raw=raw: response(raw)))
            self.assertEqual((result.status, result.records), ("invalid_response", []))

    def test_integer_only_timestamps_malformed_record_partial_not_stored(self):
        low, _ = history._bounds(date.fromisoformat(START), date.fromisoformat(END), 1000, NOW)
        raw = [activity(float(low + 3600000)), activity(low + 7200000)]
        result = history.fetch_window(AUTH, "activities", START, END, FakeTransport(lambda call: response(raw)))
        self.assertEqual((result.status, result.received_count, len(result.records)), ("partial", 2, 1))
        fake = FakeTransport(lambda call: response({"healthRecords": [sleep_record(low * 1000000 + 3600 * 1000000000, value=[])]}))
        result = history.fetch_window(AUTH, "sleep", START, END, fake)
        self.assertEqual((result.status, result.received_count, result.records), ("partial", 1, []))

    def test_summary_whitelists_AND_result_repr_hide_raw_and_measurements(self):
        fake = FakeTransport()
        for name in history.SOURCE_NAMES:
            result = history.fetch_window(AUTH, name, START, END, fake)
            keys = app.SUMMARY_KEYS if name == "activities" else sleep.KEYS if name == "sleep" else sources.METRIC_KEYS
            self.assertTrue(result.records)
            self.assertEqual(set(result.records[0]), set(keys))
            self.assertNotIn(MARKER, repr(result.records))
            self.assertNotIn("54.5", repr(result))
            self.assertNotIn("records", repr(result))

    def test_full_365_six_sources_empty_queries_not_archive_proof_and_resume(self):
        fake = FakeTransport(empty=True)
        output = history.run_backfill(self.state, lambda: AUTH, days=365, transport=fake)
        expected = len(history.plan_windows()) * len(history.SOURCE_NAMES)
        self.assertEqual((output["status"], output["completed_windows"], output["queried_windows"],
                          output["pending_windows"], output["network_calls"]), ("empty", expected, expected, 0, expected))
        self.assertFalse(output["complete_history"])
        self.assertEqual(output["stored_records"], 0)
        provider = Mock(side_effect=RuntimeError(MARKER))
        resumed = history.run_backfill(self.state, provider, days=365, transport=FakeTransport())
        provider.assert_not_called()
        self.assertEqual((resumed["status"], resumed["network_calls"]), ("empty", 0))
        self.assert_private(output)
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM health_history_coverage").fetchone()[0], expected)
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone(), ("ok",))
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.state / app.DATABASE_NAME).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.state / "sync.lock").stat().st_mode), 0o600)

    def test_idempotent_upsert_forced_repeat_and_no_live_state_changes(self):
        with app.Store(self.state, create=True) as store:
            history.ensure_schema(store.connection)
            original = app.normalize_summary(collector.summarize(activity(
                history._units(NOW - timedelta(days=90), 1000), activityType=99)))
            store.record("ok", (NOW - timedelta(days=1)).isoformat(), original)
            db = store.connection
            with db:
                db.execute("INSERT INTO sleep_collection_state VALUES (1,'ok',?,9)", (NOW.isoformat(),))
                db.execute("CREATE TABLE health_source_state (name TEXT PRIMARY KEY,last_status TEXT,checked_at_utc TEXT)")
                db.execute("INSERT INTO health_source_state VALUES ('activities','ok',?)", (NOW.isoformat(),))
                db.execute("CREATE TABLE health_sync_state (singleton INTEGER PRIMARY KEY,last_status TEXT,checked_at_utc TEXT)")
                db.execute("INSERT INTO health_sync_state VALUES (1,'ok',?)", (NOW.isoformat(),))
            live_tables = ("collection_state", "sleep_collection_state", "health_source_state", "health_sync_state")
            before = {name: db.execute("SELECT * FROM " + name).fetchall() for name in live_tables}
        one = self.run_history()
        two = self.run_history(resume=False)
        three = self.run_history()
        self.assertEqual((one["status"], two["status"], three["network_calls"]), ("ok", "ok", 0))
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM activities").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT count(*) FROM sleep_records").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT count(*) FROM metric_stats").fetchone()[0], 8)
            self.assertEqual(db.execute("SELECT activity_type FROM activities WHERE activity_type=99").fetchone(), (99,))
            after = {name: db.execute("SELECT * FROM " + name).fetchall() for name in live_tables}
            self.assertEqual(after, before)
            self.assertEqual([row[1] for row in db.execute("PRAGMA table_info(metric_stats)")], [*sources.METRIC_KEYS, "source"])
        raw_db = (self.state / app.DATABASE_NAME).read_bytes().decode("latin1")
        for marker in (*AUTH.values(), MARKER):
            self.assertNotIn(marker, raw_db)
        self.assert_private(two)

    def test_offline_coverage_does_not_create_or_change_files_or_read_auth(self):
        initial = history.read_coverage(self.state, start=START, end=END)
        self.assertEqual(initial["status"], "not_initialized")
        self.assertFalse(self.state.exists())
        self.run_history()
        path = self.state / app.DATABASE_NAME
        before = path.read_bytes()
        saved = history.read_coverage(self.state, start=START, end=END)
        self.assertEqual(saved["status"], "ok")
        self.assertEqual(before, path.read_bytes())
        self.assert_private(saved)

    def test_old_fixed_scope_remains_readable_but_not_fetchable(self):
        fake = FakeTransport(empty=True)
        history.run_backfill(self.state, lambda: AUTH, transport=fake)
        plan = history.plan_windows(now=NOW)
        tomorrow = NOW + timedelta(days=1)
        path = self.state / app.DATABASE_NAME
        before = path.read_bytes()
        saved = history.read_coverage(self.state, start=plan[0][0], end=plan[-1][1], now=tomorrow)
        # The old current-day tail was only queried up to that day's clock time.
        self.assertEqual(saved["queried_days"], 364 * len(history.SOURCE_NAMES))
        self.assertEqual(before, path.read_bytes())
        provider, transport = Mock(return_value=AUTH), Mock()
        with self.assertRaises(app.InvalidArguments):
            history.run_backfill(self.state, provider, start=plan[0][0], end=plan[-1][1],
                                 now=tomorrow, transport=transport, resume=False)
        provider.assert_not_called()
        transport.send.assert_not_called()

    def test_completed_old_scope_resume_is_offline_but_old_holes_are_rejected(self):
        self.run_history(FakeTransport(empty=True), source_names=["sleep"])
        later = NOW + timedelta(days=365)
        provider, fake = Mock(side_effect=RuntimeError(MARKER)), FakeTransport()
        result = self.run_history(fake, provider, source_names=["sleep"], now=later, window_days=2)
        self.assertEqual((result["status"], result["network_calls"], result["queried_days"]), ("empty", 0, 7))
        provider.assert_not_called()
        self.assertEqual(fake.calls, [])
        for kwargs in (dict(end="2026-09-08"), dict(source_names=["hrv"]), dict(resume=False)):
            options = {"source_names": ["sleep"], "now": later, **kwargs}
            with self.subTest(kwargs=kwargs), self.assertRaises(app.InvalidArguments):
                self.run_history(fake, provider, **options)
        provider.assert_not_called()
        self.assertEqual(fake.calls, [])

    def test_partly_old_scope_only_fetches_pending_recent_dates(self):
        plan = history.plan_windows(now=NOW)
        history.run_backfill(self.state, lambda: AUTH, transport=FakeTransport(empty=True), source_names=["sleep"])
        tomorrow = NOW + timedelta(days=1)
        current = NOW.astimezone(sources.LOCAL_ZONE).date().isoformat()
        with patch(__name__ + ".NOW", tomorrow):
            fake = FakeTransport(empty=True)
            result = history.run_backfill(self.state, lambda: AUTH, start=plan[0][0], end=plan[-1][1],
                                          source_names=["sleep"], now=tomorrow, transport=fake)
        self.assertEqual(result["queried_days"], 365)
        self.assertEqual([(call["start_day"], call["end_day"]) for call in fake.calls], [(current, current)])

    def test_offline_planner_allows_old_year_but_keeps_shape_bounds(self):
        plan = history.plan_coverage_windows(start="2020-01-01", end="2020-12-30", now=NOW)
        self.assertEqual((plan[0][0], plan[-1][1]), ("2020-01-01", "2020-12-30"))
        saved = history.read_coverage(self.state, start="2020-01-01", end="2020-12-30")
        self.assertEqual(saved["status"], "not_initialized")
        self.assertEqual(saved["missing_intervals"]["sleep"],
                         [{"start_day": "2020-01-01", "end_day": "2020-12-30"}])
        for kwargs in (dict(days=True), dict(days=366), dict(start=START),
                       dict(start=END, end=START), dict(start="2026-02-30", end=END),
                       dict(start="2020-01-01", end="2021-01-01"),
                       dict(days=1, end="2026-10-13"), dict(window_days=31)):
            with self.subTest(kwargs=kwargs), self.assertRaises(app.InvalidArguments):
                history.read_coverage(self.state, **kwargs)
        self.assertFalse(self.state.exists())

    def test_rolling_year_unions_old_windows_and_fetches_only_unfinished_tail(self):
        history.run_backfill(self.state, lambda: AUTH, transport=FakeTransport(empty=True))
        tomorrow = NOW + timedelta(days=1)
        today = NOW.astimezone(sources.LOCAL_ZONE).date().isoformat()
        next_day = tomorrow.astimezone(sources.LOCAL_ZONE).date().isoformat()
        view = history.read_coverage(self.state, now=tomorrow)
        self.assertGreater(view["queried_windows"], 0)
        self.assertEqual(view["queried_days"], 363 * len(history.SOURCE_NAMES))
        for intervals in view["missing_intervals"].values():
            self.assertEqual(intervals, [{"start_day": today, "end_day": next_day}])
        with self.db() as db:
            old = db.execute("SELECT * FROM health_history_coverage ORDER BY source,start_day,end_day").fetchall()
            self.assertEqual(len(old), 78)
        with patch(__name__ + ".NOW", tomorrow):
            fake = FakeTransport(empty=True)
            result = history.run_backfill(self.state, lambda: AUTH, transport=fake, now=tomorrow)
        self.assertEqual(result["network_calls"], len(history.SOURCE_NAMES))
        self.assertEqual({(call["start_day"], call["end_day"]) for call in fake.calls}, {(today, next_day)})
        self.assertEqual(result["queried_days"], 365 * len(history.SOURCE_NAMES))
        self.assertEqual(result["pending_windows"], 0)
        self.assertFalse(result["complete_history"])
        with self.db() as db:
            new = db.execute("SELECT * FROM health_history_coverage").fetchall()
        self.assertTrue(set(old).issubset(set(new)))
        self.assert_private(result)

    def test_resegmented_scope_resumes_without_credentials_or_network(self):
        self.run_history(FakeTransport(empty=True), source_names=["sleep"], window_days=2)
        provider, fake = Mock(side_effect=RuntimeError(MARKER)), FakeTransport()
        view = self.run_history(fake, provider, source_names=["sleep"], window_days=5)
        self.assertEqual((view["status"], view["completed_windows"], view["queried_days"],
                          view["network_calls"]), ("empty", 2, 7, 0))
        self.assertEqual(view["missing_intervals"], {"sleep": []})
        provider.assert_not_called()
        self.assertEqual(fake.calls, [])

    def test_overlapping_windows_count_days_once_and_do_not_hide_holes(self):
        self.run_history(FakeTransport(empty=True), start=START, end="2026-09-03", source_names=["sleep"])
        self.run_history(FakeTransport(empty=True), start="2026-09-02", end="2026-09-04",
                         source_names=["sleep"], resume=False)
        self.run_history(FakeTransport(empty=True), start="2026-09-06", end="2026-09-06", source_names=["sleep"])
        view = history.read_coverage(self.state, start=START, end=END, source_names=["sleep"])
        self.assertEqual((view["queried_days"], view["completed_windows"]), (5, 0))
        self.assertEqual(view["missing_intervals"], {"sleep": [
            {"start_day": "2026-09-05", "end_day": "2026-09-05"},
            {"start_day": END, "end_day": END}]})
        fake = FakeTransport(empty=True)
        result = self.run_history(fake, source_names=["sleep"])
        self.assertEqual([(call["start_day"], call["end_day"]) for call in fake.calls],
                         [("2026-09-05", "2026-09-05"), (END, END)])
        self.assertEqual((result["status"], result["queried_days"]), ("empty", 7))
        self.assertEqual(result["missing_intervals"], {"sleep": []})

    def test_missing_intervals_are_source_specific_and_budget_resume_is_bounded(self):
        self.run_history(FakeTransport(empty=True), start="2026-09-02", end="2026-09-03", source_names=["sleep"])
        self.run_history(FakeTransport(empty=True), start="2026-09-05", end="2026-09-06", source_names=["sleep"])
        view = history.read_coverage(self.state, start=START, end=END, source_names=["sleep", "hrv"])
        self.assertEqual(view["missing_intervals"]["hrv"], [{"start_day": START, "end_day": END}])
        fake = FakeTransport(empty=True)
        first = self.run_history(fake, source_names=["sleep", "hrv"], max_calls=1)
        self.assertEqual((first["status"], first["network_calls"]), ("call_limit", 1))
        self.assertEqual([(call["start_day"], call["end_day"]) for call in fake.calls], [(START, START)])
        resumed = FakeTransport(empty=True)
        result = self.run_history(resumed, source_names=["sleep", "hrv"])
        self.assertEqual([(call["source"], call["start_day"], call["end_day"]) for call in resumed.calls],
                         [("sleep", "2026-09-04", "2026-09-04"), ("sleep", END, END), ("hrv", START, END)])
        self.assertEqual((result["pending_windows"], result["queried_days"]), (0, 14))

    def test_limited_dates_are_not_queried_but_terminal_resume_is_preserved(self):
        self.run_history(FakeTransport(self.capped), start=START, end=START, source_names=["activities"])
        self.run_history(FakeTransport(empty=True), start="2026-09-02", end="2026-09-03", source_names=["activities"])
        provider = Mock(side_effect=RuntimeError(MARKER))
        result = self.run_history(provider=provider, start=START, end="2026-09-03", source_names=["activities"])
        self.assertEqual((result["status"], result["completed_windows"], result["queried_windows"],
                          result["completed_days"], result["queried_days"], result["network_calls"]),
                         ("coverage_limited", 1, 0, 3, 2, 0))
        self.assertEqual(result["missing_intervals"], {"activities": [{"start_day": START, "end_day": START}]})
        provider.assert_not_called()

    def test_split_children_cover_shifted_scope_without_reprobing_completed_days(self):
        fake = FakeTransport(lambda call: sources.ResponseTooLarge("SYNTHETIC_CAP")
                             if call["start_day"] != call["end_day"] else None)
        first = self.run_history(fake, start=START, end="2026-09-04", source_names=["sleep"], max_calls=3)
        self.assertEqual((first["status"], first["queried_days"]), ("call_limit", 1))
        view = history.read_coverage(self.state, start=START, end="2026-09-05", source_names=["sleep"])
        self.assertEqual(view["missing_intervals"]["sleep"],
                         [{"start_day": "2026-09-02", "end_day": "2026-09-05"}])
        resumed = FakeTransport(empty=True)
        result = self.run_history(resumed, start=START, end="2026-09-05", source_names=["sleep"])
        self.assertEqual([(call["start_day"], call["end_day"]) for call in resumed.calls],
                         [("2026-09-02", "2026-09-05")])
        self.assertEqual((result["queried_days"], result["completed_windows"]), (5, 1))

    def test_clipped_legacy_record_counts_are_unknown_not_prorated(self):
        self.run_history(source_names=["sleep"])
        view = history.read_coverage(self.state, start="2026-09-02", end="2026-09-03", source_names=["sleep"])
        self.assertEqual((view["status"], view["queried_days"]), ("ok", 2))
        self.assertIsNone(view["received_records"])
        self.assertIsNone(view["stored_records"])
        self.assertIsNone(view["windows"][0]["stored_count"])

    def test_malformed_overlapping_dates_and_limited_flags_never_certify_coverage(self):
        self.run_history(FakeTransport(empty=True), source_names=["sleep"])
        with self.db() as db:
            db.execute("UPDATE health_history_coverage SET coverage_limited=1")
            db.execute("INSERT INTO health_history_coverage VALUES (?,?,?,?,?,?,?,?,?)",
                       ("sleep", "2026-08-00", "2026-09-99", "ok", "queried", 0, 0, NOW.isoformat(), 0))
        view = history.read_coverage(self.state, start=START, end=END, source_names=["sleep"], window_days=2)
        self.assertEqual(view["queried_days"], 0)
        self.assertEqual(view["missing_intervals"]["sleep"], [{"start_day": START, "end_day": END}])
        self.assert_private(view)

    def test_record_queried_window_clips_today_and_does_not_commit(self):
        # UTC Oct 11 17:00 is already Oct 12 in the source's calendar.
        at = datetime(2026, 10, 11, 17, tzinfo=timezone.utc)
        with app.Store(self.state, create=True) as store:
            db = store.connection
            history.ensure_schema(db)
            self.assertEqual(history.record_queried_window(db, "sleep", "2026-10-10", "2026-10-12", at), 2)
            self.assertTrue(db.in_transaction)
            self.assertEqual(db.execute("SELECT start_day,end_day FROM health_history_coverage").fetchall(),
                             [("2026-10-10", "2026-10-11")])
            db.rollback()
            self.assertEqual(db.execute("SELECT count(*) FROM health_history_coverage").fetchone()[0], 0)
            self.assertEqual(history.record_queried_window(db, "sleep", "2026-10-12", "2026-10-12", at), 0)
            for status in ("coverage_limited", "service_error", "split", MARKER):
                with self.subTest(status=status), self.assertRaises(app.InvalidArguments):
                    history.record_queried_window(db, "sleep", START, END, at, status=status)
            with db:
                history.record_queried_window(db, "sleep", "2026-10-10", "2026-10-12", at.isoformat(), status="empty")
        view = history.read_coverage(self.state, start="2026-10-10", end="2026-10-12", source_names=["sleep"])
        self.assertEqual(view["queried_days"], 2)
        self.assertEqual(view["missing_intervals"]["sleep"], [{"start_day": "2026-10-12", "end_day": "2026-10-12"}])
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM sleep_records").fetchone()[0], 0)

    def test_union_matches_day_oracle_across_display_partitions(self):
        entries = [("sleep", 1, 8, "split", "not_assessed"),
                   ("sleep", 1, 3, "empty", "queried"),
                   ("sleep", 3, 5, "partial", "queried"),
                   ("sleep", 6, 8, "coverage_limited", "coverage_limited"),
                   ("sleep", 8, 10, "ok", "queried"),
                   ("sleep", 12, 13, "service_error", "not_assessed"),
                   ("hrv", 2, 4, "empty", "queried"),
                   ("hrv", 4, 7, "ok", "queried")]
        queried, completed = {name: set() for name in ("sleep", "hrv")}, {name: set() for name in ("sleep", "hrv")}
        with app.Store(self.state, create=True) as store:
            history.ensure_schema(store.connection)
            with store.connection:
                for name, first, last, status, coverage in entries:
                    history._coverage(store.connection, name, f"2026-09-{first:02d}", f"2026-09-{last:02d}",
                                      history.WindowResult(status, coverage=coverage), NOW.isoformat())
                    if status in ("ok", "empty", "partial", "coverage_limited"):
                        completed[name].update(range(first, last + 1))
                    if coverage == "queried":
                        queried[name].update(range(first, last + 1))
        for width in (1, 2, 7, 30):
            with self.subTest(window_days=width):
                result = history.read_coverage(self.state, start=START, end="2026-09-14",
                                               source_names=["sleep", "hrv"], window_days=width)
                self.assertEqual(result["queried_days"], sum(map(len, queried.values())))
                self.assertEqual(result["completed_days"], sum(map(len, completed.values())))
                self.assertEqual(result["coverage_limited_days"], sum(len(completed[s] - queried[s]) for s in queried))
                for name, intervals in result["missing_intervals"].items():
                    missing = {day for interval in intervals
                               for day in range(int(interval["start_day"][-2:]), int(interval["end_day"][-2:]) + 1)}
                    self.assertEqual(missing, set(range(1, 15)) - queried[name])
                for row in result["windows"]:
                    scope = set(range(int(row["start_day"][-2:]), int(row["end_day"][-2:]) + 1))
                    self.assertEqual(row["coverage"] == "queried", scope <= queried[row["source"]])
                self.assertFalse(result["complete_history"])
                self.assert_private(result)

    def test_record_helper_finishes_yesterdays_snapshot_without_losing_counts(self):
        today = NOW.astimezone(sources.LOCAL_ZONE).date().isoformat()
        self.run_history(start=today, end=today, source_names=["sleep"])
        tomorrow = NOW + timedelta(days=1)
        with self.db() as db:
            before = db.execute("SELECT received_count,stored_count FROM health_history_coverage").fetchone()
            self.assertEqual(history.record_queried_window(db, "sleep", today, today, tomorrow), 1)
            self.assertEqual(db.execute("SELECT received_count,stored_count FROM health_history_coverage").fetchone(), before)
            for checked_at in (None, NOW.replace(tzinfo=None), "not-a-timestamp"):
                with self.assertRaises(app.InvalidArguments):
                    history.record_queried_window(db, "sleep", today, today, checked_at)
        view = history.read_coverage(self.state, start=today, end=today, source_names=["sleep"], now=tomorrow)
        self.assertEqual((view["queried_days"], view["missing_intervals"]), (1, {"sleep": []}))

    def test_single_day_split_marker_cannot_bypass_budget_or_recurse(self):
        self.run_history(FakeTransport(empty=True), start=START, end=START, source_names=["sleep"])
        with self.db() as db:
            db.execute("UPDATE health_history_coverage SET status='split',coverage='not_assessed',coverage_limited=1")
        fake = FakeTransport(empty=True)
        result = self.run_history(fake, start=START, end=START, source_names=["sleep"], max_calls=1)
        self.assertEqual((result["status"], result["network_calls"]), ("empty", 1))
        self.assertEqual(len(fake.calls), 1)

    def test_shared_storage_retains_nullable_fields_and_provenance(self):
        self.run_history(source_names=["activities"])
        with self.db() as db:
            before = db.execute("SELECT distance_m,training_load FROM activities").fetchone()
        def partial(call):
            low = int(call["params"]["startTime"])
            return response([activity(low + 3600000, activitySummary={})])
        with patch.object(history.storage, "store_records", wraps=history.storage.store_records) as writer:
            result = self.run_history(FakeTransport(partial), source_names=["activities"], resume=False)
            self.assertEqual(writer.call_count, 1)
            self.assertEqual(writer.call_args.args[1], "activities")
            self.assertEqual(writer.call_args.args[3], NOW.isoformat())
        self.assertEqual(result["stored_records"], 1)
        with self.db() as db:
            self.assertEqual(db.execute("SELECT distance_m,training_load FROM activities").fetchone(), before)
            retained = db.execute("SELECT field FROM health_record_quality WHERE source='activities' AND retained=1 ORDER BY field").fetchall()
            self.assertEqual(retained, [("distance_m",), ("training_load",)])

    def test_activity_cap_adaptive_split_no_false_full_coverage(self):
        def handler(call):
            if call["start_day"] != call["end_day"]:
                low = int(call["params"]["startTime"])
                return response([activity(low + 3600000 + offset * 1000) for offset in range(100)])
        fake = FakeTransport(handler)
        result = self.run_history(fake, start="2026-09-01", end="2026-09-02", source_names=["activities"])
        self.assertEqual((result["status"], result["network_calls"], result["stored_records"], result["received_records"]), ("ok", 3, 2, 2))
        self.assertEqual([(call["start_day"], call["end_day"]) for call in fake.calls],
                         [("2026-09-01", "2026-09-02"), ("2026-09-01", "2026-09-01"), ("2026-09-02", "2026-09-02")])
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM activities").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT count(*) FROM health_history_coverage").fetchone()[0], 3)
        self.assertEqual(self.run_history(start="2026-09-01", end="2026-09-02", source_names=["activities"])["network_calls"], 0)

    def capped(self, call):
        low = int(call["params"]["startTime"])
        return response([activity(low + 3600000 + offset * 1000) for offset in range(100)])

    def test_overlapping_previous_sleep_is_accepted_but_not_rebinned(self):
        low,high=history._bounds(date.fromisoformat(START),date.fromisoformat(END),10**9,NOW)
        raw={'healthRecords':[sleep_record(low-6*3600*10**9,endTime=low+2*3600*10**9),sleep_record(low+3*3600*10**9)]}
        fake=FakeTransport(lambda call:response(raw))
        parsed=history.fetch_window(AUTH,'sleep',START,END,fake)
        self.assertEqual(len(parsed.records),2)
        saved=self.run_history(fake,source_names=['sleep'])
        self.assertEqual(saved['received_records'],2)
        self.assertEqual(saved['stored_records'],1)
        with self.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM sleep_records').fetchone()[0],1)

    def test_sleep_cross_midnight_end_is_preserved_and_binned_by_start(self):
        low,high=history._bounds(date.fromisoformat(END),date.fromisoformat(END),10**9,NOW)
        start=high-1800*10**9;end=start+6*3600*10**9
        raw={'healthRecords':[sleep_record(start,endTime=end)]}
        fake=FakeTransport(lambda call:response(raw))
        parsed=history.fetch_window(AUTH,'sleep',END,END,fake)
        self.assertEqual(parsed.status,'ok')
        self.assertEqual(len(parsed.records),1)
        self.assertEqual(parsed.records[0]['end_time_utc'],sleep.stamp(end,10**9))
        saved=self.run_history(fake,start=END,end=END,source_names=['sleep'])
        self.assertEqual((saved['completed_windows'],saved['stored_records']),(1,1))
        with self.db() as db:self.assertEqual(db.execute('SELECT end_time_utc FROM sleep_records').fetchone()[0],sleep.stamp(end,10**9))
        bad={'healthRecords':[sleep_record(start,endTime=start+25*3600*10**9)]}
        self.assertEqual(history.fetch_window(AUTH,'sleep',END,END,FakeTransport(lambda call:response(bad))).status,'invalid_response')

    def test_sleep_reencoding_near_body_cap_keeps_compact_valid_response(self):
        low=history._bounds(date.fromisoformat(START),date.fromisoformat(END),10**9,NOW)[0]
        item=sleep_record(low+3600*10**9)
        item['synthetic_fragment_padding']=''
        raw={'healthRecords':[item]}
        wire=json.dumps(raw,separators=(',',':'),ensure_ascii=False).encode()
        item['synthetic_fragment_padding']='x'*(history.MAX_BODY-len(wire))
        wire=json.dumps(raw,separators=(',',':'),ensure_ascii=False).encode()
        self.assertLessEqual(len(wire),history.MAX_BODY)
        self.assertGreater(len(json.dumps([item]).encode()),history.MAX_BODY)
        fake=FakeTransport(lambda call:collector.Response(200,wire,'application/json'))
        result=history.fetch_window(AUTH,'sleep',START,END,fake)
        self.assertEqual(result.status,'ok')
        self.assertEqual(len(result.records),1)
        self.assertNotIn('synthetic_fragment_padding',result.records[0])

    def test_sleep_response_body_cap_splits_without_increasing_limit(self):
        def handler(call):
            if call['start_day']!=call['end_day']:
                return sources.ResponseTooLarge('SYNTHETIC_CAP')
        fake=FakeTransport(handler)
        result=self.run_history(fake,start=START,end='2026-09-02',source_names=['sleep'])
        self.assertEqual((result['status'],result['network_calls'],result['stored_records']),('ok',3,2))
        self.assertEqual(result['coverage_limited_windows'],0)
        self.assertEqual(history.MAX_BODY,collector.MAX_BODY)
        with self.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM sleep_records').fetchone()[0],2)
        limited=self.run_history(FakeTransport(lambda call:sources.ResponseTooLarge('SYNTHETIC_CAP')),
            start='2026-09-03',end='2026-09-03',source_names=['sleep'])
        self.assertEqual((limited['status'],limited['stored_records']),('coverage_limited',0))

    def test_single_day_cap_and_depth_limit_stay_limited_and_resumable(self):
        result = self.run_history(FakeTransport(self.capped), start=START, end=START, source_names=["activities"])
        self.assertEqual((result["status"], result["coverage_limited_windows"], result["stored_records"], result["queried_windows"]),
                         ("coverage_limited", 1, 100, 0))
        self.assertFalse(result["complete_history"])
        self.assertEqual(self.run_history(start=START, end=START, source_names=["activities"])["network_calls"], 0)
        result = self.run_history(FakeTransport(self.capped), start=START, end="2026-09-02",
                                  source_names=["activities"], max_split_depth=0)
        self.assertEqual((result["status"], result["network_calls"], result["queried_windows"]), ("coverage_limited", 1, 0))

    def test_global_call_budget_resumes_split_tree_without_repeating_probes(self):
        fake = FakeTransport(self.capped)
        result = self.run_history(fake, start=START, end="2026-09-08", source_names=["activities", "sleep"], max_calls=4)
        self.assertEqual((result["status"], result["network_calls"]), ("call_limit", 4))
        self.assertEqual((result["received_records"], result["stored_records"]), (100, 100))
        partial_status = history.read_coverage(self.state, start=START, end="2026-09-08", source_names=["activities", "sleep"])
        self.assertEqual((partial_status["received_records"], partial_status["stored_records"]), (100, 100))
        self.assertEqual(len(fake.calls), 4)
        completed_leaf = fake.calls[-1]
        resumed_fake = FakeTransport(empty=True)
        resumed = self.run_history(resumed_fake, start=START, end="2026-09-08", source_names=["activities", "sleep"])
        previous_pairs = {(call["start_day"], call["end_day"]) for call in fake.calls}
        activity_pairs = {(call["start_day"], call["end_day"]) for call in resumed_fake.calls if call["source"] == "activities"}
        self.assertFalse(activity_pairs & previous_pairs)
        self.assertNotIn(completed_leaf["start_day"], {first for first, last in activity_pairs if first == last})
        self.assertEqual(resumed["pending_windows"], 0)
        self.assertEqual(resumed["status"], "coverage_limited")
        self.assertEqual(resumed["queried_windows"], 1)
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM activities").fetchone()[0], 100)

    def test_invalid_runtime_options_fail_before_store_provider_network(self):
        provider, fake = Mock(return_value=AUTH), FakeTransport()
        cases = [dict(max_calls=True), dict(max_calls=0), dict(max_calls=1025),
                 dict(max_split_depth=6), dict(max_split_depth=-1), dict(resume=1),
                 dict(source_names=[]), dict(source_names=["gps"]),
                 dict(source_names=["sleep", "sleep"]), dict(storage_callback=1), dict(recover_headers=1)]
        for kwargs in cases:
            with self.assertRaises(app.InvalidArguments):
                self.run_history(fake, provider, **kwargs)
        provider.assert_not_called()
        self.assertFalse(self.state.exists())
        self.assertEqual(fake.calls, [])

    def test_401_global_stop_and_same_rejected_token_stays_blocked(self):
        fake = FakeTransport(lambda call: response({}, 401))
        result = self.run_history(fake)
        self.assertEqual((result["status"], result["network_calls"], result["completed_windows"]), ("reauth_required", 1, 0))
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(fake.calls[0]["source"], "activities")
        callback = Mock(return_value=dict(headers=NEW_AUTH, vps_auth_verified=True))
        blocked_fake = FakeTransport()
        result = self.run_history(blocked_fake, lambda: {**AUTH, "Cookie": "SYNTHETIC_CHANGED_COOKIE", "x-client-id": "CHANGED_CLIENT"}, recover_headers=callback)
        self.assertEqual((result["status"], result["network_calls"]), ("reauth_required", 0))
        callback.assert_not_called()
        self.assertEqual(blocked_fake.calls, [])
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM health_history_auth_block").fetchone()[0], 1)
        self.assert_private(result)

    def test_401_recovery_once_verified_changed_token_retry_then_continue(self):
        fake = FakeTransport(lambda call: response({}, 401) if call["headers"]["Authorization"] == AUTH["Authorization"] else None)
        recovery = Mock(return_value=dict(headers=NEW_AUTH, vps_auth_verified=True))
        result = self.run_history(fake, source_names=["activities", "sleep", "hrv"], recover_headers=recovery)
        self.assertEqual((result["status"], result["network_calls"], result["completed_windows"]), ("ok", 4, 3))
        recovery.assert_called_once_with(AUTH)
        self.assertEqual([call["headers"]["Authorization"] for call in fake.calls],
                         [AUTH["Authorization"], *([NEW_AUTH["Authorization"]] * 3)])
        self.assert_private(result)

    def test_failed_retry_halts_globally_no_second_recovery(self):
        fake = FakeTransport(lambda call: response({}, 401))
        recovery = Mock(return_value=dict(headers=NEW_AUTH, vps_auth_verified=True))
        result = self.run_history(fake, recover_headers=recovery)
        self.assertEqual((result["status"], len(fake.calls), recovery.call_count), ("reauth_required", 2, 1))
        self.assertEqual([call["source"] for call in fake.calls], ["activities", "activities"])
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM health_history_auth_block").fetchone()[0], 2)
        third = self.run_history(FakeTransport(), lambda: NEW_AUTH)
        self.assertEqual((third["status"], third["network_calls"]), ("reauth_required", 0))

    def test_unverified_or_unchanged_recovery_never_retries(self):
        cases = [dict(headers=AUTH, vps_auth_verified=True),
                 dict(headers={**AUTH, "Cookie": "CHANGED_COOKIE"}, vps_auth_verified=True),
                 dict(headers=NEW_AUTH, vps_auth_verified=False),
                 dict(headers=NEW_AUTH, vps_auth_verified=1),
                 dict(headers=NEW_AUTH, vps_auth_verified=True, status="reauth_required")]
        for index, payload in enumerate(cases):
            auth = {**AUTH, "Authorization": "SYNTHETIC_REJECTED_" + str(index)}
            if index < 2:
                payload["headers"] = {**payload["headers"], "Authorization": auth["Authorization"]}
            fake = FakeTransport(lambda call: response({}, 401))
            callback = Mock(return_value=payload)
            result = self.run_history(fake, lambda auth=auth: auth, recover_headers=callback)
            self.assertEqual((result["status"], len(fake.calls), callback.call_count), ("reauth_required", 1, 1))

    def test_403_redirect_or_HTML_stop_without_recovery_callback(self):
        for index, reply in enumerate((response({}, 403), response({}, 302),
                                       collector.Response(200, b"<HTML>login</HTML>", "text/html"))):
            fake = FakeTransport(lambda call, reply=reply: reply)
            callback = Mock(return_value=dict(headers=NEW_AUTH, vps_auth_verified=True))
            result = self.run_history(fake, lambda index=index: {**AUTH, "Authorization": "SYNTHETIC_BLOCKED_OTHER_" + str(index)}, recover_headers=callback)
            self.assertEqual((result["status"], len(fake.calls)), ("reauth_required", 1))
            callback.assert_not_called()

    def test_later_source_401_stops_later_windows_and_sources(self):
        fake = FakeTransport(lambda call: response({}, 401) if call["source"] == "resting_hr" else None)
        result = self.run_history(fake)
        self.assertEqual(result["status"], "reauth_required")
        self.assertEqual([call["source"] for call in fake.calls], ["activities", "sleep", "resting_hr"])
        self.assertEqual(result["completed_windows"], 2)
        resumed_fake = FakeTransport()
        resumed = self.run_history(resumed_fake, lambda: NEW_AUTH)
        self.assertEqual(resumed["status"], "ok")
        self.assertEqual([call["source"] for call in resumed_fake.calls], list(history.SOURCE_NAMES[2:]))

    def test_missing_malformed_or_provider_error_has_no_network(self):
        malformed = [None, {}, {**AUTH, "Host": "attacker.invalid"},
                     {**AUTH, "Authorization": "bad\r\nheader"},
                     {**AUTH, "Cookie": "bad\x00cookie"}, {**AUTH, "x-version": 1},
                     {**AUTH, "Cookie": "x" * (app.MAX_AUTH_BYTES + 1)}]
        for headers in malformed:
            fake = FakeTransport()
            result = self.run_history(fake, lambda headers=headers: headers)
            self.assertEqual((result["status"], result["network_calls"], fake.calls), ("reauth_required", 0, []))
        fake = FakeTransport()
        result = self.run_history(fake, Mock(side_effect=RuntimeError(MARKER)))
        self.assertEqual((result["status"], fake.calls), ("reauth_required", []))
        self.assert_private(result)

    def test_no_non_auth_retry_unknown_error_not_coverage_or_auth_verified(self):
        for index, reply in enumerate((response({}, 429), response({}, 503), response({}, 400),
                                      response({"error": MARKER}), RuntimeError(MARKER))):
            fake = FakeTransport(lambda call, reply=reply: reply)
            recovery = Mock()
            result = self.run_history(fake, recover_headers=recovery)
            self.assertEqual((result["status"], result["network_calls"], result["completed_windows"]), ("collection_error", 1, 0))
            recovery.assert_not_called()
            self.assertEqual(result["windows"][0]["coverage"], "not_assessed")
            with self.db() as db:
                self.assertEqual(db.execute("SELECT count(*) FROM health_history_auth_block").fetchone()[0], 0)
            self.assert_private(result)
        retried = self.run_history(FakeTransport(empty=True))
        self.assertEqual((retried["status"], retried["network_calls"]), ("empty", len(history.SOURCE_NAMES)))

    def test_injected_storage_callback_atomic_rollback_and_no_secret_error_output(self):
        def fail(db, source, records):
            history.store_records(db, source, records)
            raise RuntimeError(MARKER)
        result = self.run_history(storage_callback=fail)
        self.assertEqual((result["status"], result["network_calls"], result["completed_windows"]), ("storage_error", 1, 0))
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM activities").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM health_history_coverage").fetchone()[0], 0)
        self.assert_private(result)
        captured = []
        def save(db, source, records):
            captured.append((source, records))
            return history.store_records(db, source, records)
        good = self.run_history(storage_callback=save)
        self.assertEqual((good["status"], len(captured)), ("ok", len(history.SOURCE_NAMES)))
        self.assertTrue(all(MARKER not in repr(records) for _, records in captured))

    def test_invalid_storage_callback_count_rolls_back(self):
        def bad(db, source, records):
            history.store_records(db, source, records)
            return True
        result = self.run_history(storage_callback=bad)
        self.assertEqual(result["status"], "storage_error")
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM activities").fetchone()[0], 0)

    def test_empty_or_error_never_deletes_original_summary_rows(self):
        self.run_history()
        with self.db() as db:
            before = {table: db.execute("SELECT * FROM " + table).fetchall()
                      for table in ("activities", "sleep_records", "metric_stats")}
        self.run_history(FakeTransport(empty=True), resume=False)
        self.run_history(FakeTransport(lambda call: response({}, 503)), resume=False)
        with self.db() as db:
            after = {table: db.execute("SELECT * FROM " + table).fetchall() for table in before}
        self.assertEqual(before, after)

    def test_shared_sync_lock_blocks_before_headers_or_HTTP(self):
        app.init_state(self.state)
        fd = os.open(self.state / "sync.lock", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            provider, fake = Mock(return_value=AUTH), FakeTransport()
            result = self.run_history(fake, provider)
            self.assertEqual((result["status"], result["network_calls"]), ("already_running", 0))
            provider.assert_not_called()
            self.assertEqual(fake.calls, [])
        finally:
            os.close(fd)

    def test_unsafe_permissions_or_symlink_store_refused_before_credentials(self):
        self.state.mkdir(mode=0o755)
        self.state.chmod(0o755)
        provider, fake = Mock(return_value=AUTH), FakeTransport()
        with self.assertRaises(app.StorageError):
            self.run_history(fake, provider)
        provider.assert_not_called()
        self.assertEqual(fake.calls, [])
        self.state.chmod(0o700)
        target = self.root / "synthetic-target"
        target.write_bytes(b"SYNTHETIC_NOT_A_DATABASE")
        target.chmod(0o600)
        (self.state / app.DATABASE_NAME).symlink_to(target)
        with self.assertRaises(app.StorageError):
            self.run_history(fake, provider)
        self.assertEqual(target.read_bytes(), b"SYNTHETIC_NOT_A_DATABASE")
        provider.assert_not_called()

    def test_worst_case_30_day_split_is_bounded_at_59_calls(self):
        fake = FakeTransport(self.capped)
        result = self.run_history(fake, start=START, end="2026-09-30", source_names=["activities"])
        self.assertEqual((result["status"], result["network_calls"], result["stored_records"]),
                         ("coverage_limited", 2 * 30 - 1, 30 * 100))
        self.assertEqual(len(fake.calls), 2 * 30 - 1)
        leaf_calls = [call for call in fake.calls if call["start_day"] == call["end_day"]]
        self.assertEqual(len(leaf_calls), 30)
        self.assertEqual(len({call["start_day"] for call in leaf_calls}), 30)
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM activities").fetchone()[0], 3000)

    def test_corrupt_coverage_readback_does_not_echo_raw_or_skip_resume(self):
        self.run_history(source_names=["activities"])
        with self.db() as db:
            db.execute("UPDATE health_history_coverage SET status=?,received_count=?,collected_at_utc=?",
                       (MARKER, MARKER, MARKER))
        saved = history.read_coverage(self.state, start=START, end=END, source_names=["activities"])
        self.assertEqual((saved["status"], saved["completed_windows"]), ("not_complete", 0))
        self.assertEqual(saved["windows"][0]["status"], "invalid_response")
        self.assertEqual(saved["windows"][0]["coverage"], "not_assessed")
        self.assert_private(saved)
        self.assertEqual(self.run_history(source_names=["activities"])["network_calls"], 1)

    def test_tls_no_proxy_redirect_timeout_body_caps_and_401_before_body(self):
        handle = Mock()
        handle.code = 200
        handle.headers = {"Content-Type": "application/json"}
        handle.read.return_value = b"[]"
        handle.__enter__ = Mock(return_value=handle)
        handle.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = handle
        with patch.object(request, "build_opener", return_value=opener) as factory:
            transport = history.OfficialTransport(network_authorized=True, now=NOW)
            handlers = factory.call_args.args
            https = next(item for item in handlers if isinstance(item, request.HTTPSHandler))
            self.assertTrue(https._context.check_hostname)
            self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(next(item for item in handlers if isinstance(item, request.ProxyHandler)).proxies, {})
            self.assertTrue(any(isinstance(item, collector.NoRedirect) for item in handlers))
            self.assertEqual(history.fetch_window(AUTH, "activities", START, END, transport).status, "empty")
            self.assertEqual(opener.open.call_args.kwargs, {"timeout": 10})
            handle.read.assert_called_once_with(history.MAX_BODY + 1)
            handle.read.return_value = b"x" * (history.MAX_BODY + 1)
            self.assertEqual(history.fetch_window(AUTH, "activities", START, END, transport).status, "invalid_response")
            handle.code = 401
            handle.read.reset_mock()
            result = history.fetch_window(AUTH, "sleep", START, END, transport)
            self.assertEqual((result.status, result.http_status), ("reauth_required", 401))
            handle.read.assert_not_called()
            req = opener.open.call_args.args[0]
            self.assertEqual((req.method, req.data), ("GET", None))
            handle.code = 200
            handle.read.return_value = b"[]"
            opener.open.side_effect = error.HTTPError(sources.ACTIVITIES_URL, 401, MARKER, {}, io.BytesIO())
            result = history.fetch_window(AUTH, "activities", START, END, transport)
            self.assertEqual((result.status, result.http_status), ("reauth_required", 401))
        with self.assertRaises(ValueError):
            history.OfficialTransport()


if __name__ == "__main__":
    unittest.main(verbosity=2)
