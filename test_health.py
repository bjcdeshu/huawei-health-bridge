"""Synthetic regression tests. State/auth/CLI live ONLY in explicit TMPDIR.

Guards cover Store, credentials, metadata, os.open, SQLite and all real network
opens; a swallowed isolation exception still fails tearDown. No real response
fixtures or production credentials are read. Baseline tests remain unchanged.
"""
import contextlib
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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch
from urllib import request

import app
import collector
import health as h
import health_sources as hs
import health_points as hp
import sleep_collector as sleep
from test_app import record as baseline_activity
from test_sleep import record as baseline_sleep

NOW = datetime(2026, 8, 17, 16, 30, tzinfo=timezone.utc)
BASE_MS = int(NOW.timestamp() * 1000) - 3600000
AUTH = {"Authorization": "SYNTHETIC_HEALTH_TOKEN", "x-client-id": "SYNTHETIC_HEALTH_CLIENT"}
MARKER = "SYNTHETIC_PRIVATE_RAW_NAME_ID_GPS_NEVER_STORE"


def response(raw, code=200):
    return collector.Response(code, json.dumps(raw).encode())


def activity(offset=0, **changes):
    return baseline_activity(startTime=BASE_MS + offset, activityName=MARKER,
                             id=MARKER, gps=MARKER, raw=MARKER, **changes)


def sleep_response():
    raw = baseline_sleep()
    shift = BASE_MS - 1700000000000 - 8 * 3600000
    raw["startTime"] += shift * 1000000
    raw["endTime"] += shift * 1000000
    for entry in raw["value"]:
        if entry["fieldName"] in sleep.TIME_FIELDS:
            entry["longValue"] += shift
    return response({"healthRecords": [raw]})


def stats_response(metric, *, entries=None, overall=True):
    field = hs.METRICS[metric][2]
    block = dict(avg=54.5, min=50, max=59, count=2, sum=109)
    entries = [dict(fieldName=field, startDay=20260818, statistics=block, id=MARKER, unit="ms")] if entries is None else entries
    if overall:
        results = [dict(fieldName=field, statistics=block, raw=MARKER)]
    else:
        results = []
    return response(dict(results=results, groupResults=[dict(groupStatistics=entries, name=MARKER)]))


def point_fixture():
    stamp=int((NOW-timedelta(days=60)).timestamp()*1_000_000_000)
    return hp.normalize_sample_point({'startTime':stamp,'endTime':stamp,'dataTypeName':hp.DATA_TYPE,
        'value':[{'fieldName':'vo2max','integerValue':137}]},now_ns=int(NOW.timestamp()*1_000_000_000))


class FakeTransport:
    def __init__(self, overrides=None, items=None):
        self.calls = []
        self.overrides = overrides or {}
        self.responses = {
            hs.ACTIVITIES_URL: response([activity(), activity(-3600000, activityType="57")] if items is None else items),
            hs.RESTING_HR_URL: stats_response("resting_hr"),
            hs.HRV_URL: stats_response("hrv"),
            **(overrides or {}),
        }

    def send(self, method, url, headers, body):
        hs.check_request(method, url, body)
        self.calls.append((method, url, json.loads(body), set(headers)))
        value = self.responses[url]
        payload = json.loads(body)
        if url == hs.RESTING_HR_URL and url not in self.overrides:
            dtype = payload['reqs'][0]['dataType']
            metric = next(name for name,spec in hs.METRICS.items() if spec[1]==dtype)
            value = stats_response(metric)
        if isinstance(value, Exception):
            raise value
        return value


class HealthTests(unittest.TestCase):
    def setUp(self):
        # No fallback to /tmp, production, or the current project directory.
        self.temp = tempfile.TemporaryDirectory(prefix="unified-health-tests-", dir=os.environ["TMPDIR"])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "private"
        self.auth = self.root / "synthetic-auth.json"
        self.violations = []
        original_store, original_auth = app.Store, app.load_auth
        original_mtime, original_open, original_connect = h._auth_mtime, os.open, sqlite3.connect

        def safe(path):
            value = os.fspath(path)
            if value.startswith("file:"):
                value = value[5:].split("?", 1)[0]
            if value.startswith("/proc/self/fd/"):
                pieces = value.split("/")
                value = os.readlink("/proc/self/fd/" + pieces[4]) + "/" + "/".join(pieces[5:])
            return Path(value).is_relative_to(self.root)

        def reject(label):
            self.violations.append(label)
            raise AssertionError(label)

        def guarded_store(state_dir, **kwargs):
            if Path(state_dir) != self.state:
                reject("state_outside_this_test")
            return original_store(state_dir, **kwargs)

        def guarded_auth(path):
            if not safe(path):
                reject("auth_outside_this_test")
            return original_auth(path)

        def guarded_mtime(path):
            if not safe(path):
                reject("credential_metadata_outside_this_test")
            return original_mtime(path)

        def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
            full = path if dir_fd is None else os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), os.fspath(path))
            if not safe(full):
                reject("file_open_outside_this_test")
            return original_open(path, flags, mode, dir_fd=dir_fd)

        def guarded_connect(path, *args, **kwargs):
            if not safe(path):
                reject("database_outside_this_test")
            return original_connect(path, *args, **kwargs)

        for guard in (
            patch.object(app, "Store", side_effect=guarded_store),
            patch.object(app, "load_auth", side_effect=guarded_auth),
            patch.object(h, "_auth_mtime", side_effect=guarded_mtime),
            patch.object(os, "open", side_effect=guarded_open),
            patch.object(sqlite3, "connect", side_effect=guarded_connect),
            patch.object(h, "utc_now", return_value=NOW),
            patch.object(hs, "utc_now", return_value=NOW),
            patch.object(request.OpenerDirector, "open", side_effect=lambda *a, **k: reject("real_network_forbidden")),
            patch.object(socket.socket, "connect", side_effect=lambda *a, **k: reject("real_socket_forbidden")),
        ):
            guard.start()
            self.addCleanup(guard.stop)

    def tearDown(self):
        self.assertEqual(self.violations, [], "an isolation violation was caught/suppressed")

    def write_auth(self, headers=None, path=None):
        path = path or self.auth
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as out:
            json.dump(AUTH if headers is None else headers, out)
        os.utime(path, ns=(int(NOW.timestamp() * 1000000000) - 1000000000,) * 2)
        return path

    @contextlib.contextmanager
    def fake_http(self, *, overrides=None, items=None, sleep_result=None):
        transport = FakeTransport(overrides, items)
        sleep_result = sleep.analyse(sleep_response()) if sleep_result is None else sleep_result
        with patch.object(hs, "OfficialTransport", return_value=transport) as factory, \
                patch.object(sleep, "fetch", return_value=sleep_result) as fetch, \
                patch.object(hp,'fetch',return_value=hs.Result('ok',[point_fixture()],1,coverage='latest_measurement',quality='ok')):
            yield transport, fetch, factory

    def sync(self, **kwargs):
        return h.run_once(self.state, self.auth, **kwargs)

    def cli(self, *arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = h.main(list(arguments))
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(len(stdout.getvalue().splitlines()), 1)
        self.assert_private(stdout.getvalue())
        return code, json.loads(stdout.getvalue())

    def assert_private(self, text):
        for marker in (*AUTH.values(), MARKER, "SYNTHETIC_PRIVATE_ID", "SYNTHETIC_GPS", "SYNTHETIC_FRAGMENTS"):
            self.assertNotIn(marker, text)
        for key in AUTH:
            self.assertNotIn(key, text)

    def db(self):
        return sqlite3.connect(self.state / app.DATABASE_NAME)

    def test_cli_paths_before_after_and_mixed_never_reset_to_production(self):
        options = ["--state-dir", str(self.state), "--auth-file", str(self.auth)]
        for name in ("sync", "status", "capabilities", "latest", "report"):
            for args in (options + [name], [name] + options,
                         options[:2] + [name] + options[2:]):
                parsed = h.build_parser().parse_args(args)
                self.assertEqual((parsed.state_dir, parsed.auth_file), (str(self.state), str(self.auth)))
        self.write_auth()
        with self.fake_http() as (transport, fetch, factory):
            for args in (options + ["sync"], ["sync"] + options):
                self.assertEqual(self.cli(*args)[0], 0)
            self.assertEqual(len(transport.calls), 2*(1+len(hs.METRICS)))
            self.assertEqual(fetch.call_count, 2)
        for name in ("status", "capabilities", "latest", "report"):
            with patch.object(app, "load_auth") as auth, patch.object(hs, "OfficialTransport") as net:
                self.assertEqual(self.cli(name, *options)[0], 0)
                auth.assert_not_called(); net.assert_not_called()
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM activities").fetchone()[0], 2)

    def test_uninitialized_offline_commands_do_not_create_state_or_read_auth(self):
        with patch.object(app, "load_auth") as auth:
            for command in ("status", "latest", "report"):
                self.assertEqual(self.cli("--state-dir", str(self.state), command)[1]["status"], "not_initialized")
            auth.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_invalid_options_are_rejected_before_file_or_network_access(self):
        options = ["--state-dir", str(self.state), "--auth-file", str(self.auth)]
        cases = [("sync", "--activity-limit", "101"), ("sync", "--activity-days", "31"),
                 ("sync", "--metric-days", "0"), ("report", "--limit", "0"),
                 ("report", "--limit", AUTH["Authorization"]), ("bad",)]
        with patch.object(app, "Store") as store, patch.object(app, "load_auth") as auth:
            for args in cases:
                self.assertEqual(self.cli(*options, *args), (2, {"status": "invalid_arguments"}))
            for kwargs in ({"activity_days": True}, {"sleep_days": 31}, {"metric_days": 0}, {"activity_limit": 101}):
                with self.assertRaises(app.InvalidArguments):
                    self.sync(**kwargs)
            store.assert_not_called(); auth.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_default_auth_is_inside_the_explicit_state(self):
        app.init_state(self.state)
        self.write_auth(path=self.state / "auth.json")
        with self.fake_http():
            code, result = self.cli("sync", "--state-dir", str(self.state))
        self.assertEqual((code, result["status"]), (0, "ok"))

    def test_multiple_activities_upsert_preserve_existing_rows_and_units(self):
        self.write_auth()
        with app.Store(self.state, create=True) as store:
            old = app.normalize_summary(collector.summarize(activity(-86400000, activityType=99)))
            store.record("ok", (NOW - timedelta(days=1)).isoformat(), old)
        with self.fake_http(items=[activity(), activity(-3600000, activityType="57")]) as (transport, fetch, _):
            first = self.sync(activity_limit=2)
            second = self.sync(activity_limit=2)
        self.assertEqual(first["status"], "coverage_limited")
        meta = second["sources"]["activities"]
        self.assertEqual((meta["count"], meta["received_records"], meta["stored_records"]), (3, 2, 2))
        self.assertEqual(meta["coverage"], "coverage_limited")
        self.assertFalse(meta["complete_history"])
        self.assertEqual(len(transport.calls), 2*(1+len(hs.METRICS)))
        fetch.assert_called_with(AUTH, days=7)
        with self.fake_http(items=[activity(activeTime=1900000), activity(-3600000, activityType="57")]):
            self.sync()
        latest = h.read_view(self.state, self.auth, mode="latest")["sources"]["activities"]["summary"]
        self.assertEqual((latest["duration_ms"], latest["distance_m"], latest["training_load"]), (1900000, 5000, 30))
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM activities").fetchone()[0], 3)
            self.assertEqual(db.execute("SELECT activity_type FROM activities WHERE activity_type=99").fetchone(), (99,))
            self.assertEqual([r[1] for r in db.execute("PRAGMA table_info(activities)")], [*app.SUMMARY_KEYS, "source"])
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.state / app.DATABASE_NAME).stat().st_mode), 0o600)
        self.assert_private((self.state / app.DATABASE_NAME).read_bytes().decode("latin1"))

    def test_cap_hit_counts_raw_records_even_if_some_cannot_be_stored(self):
        result = hs.analyse_activities(response([activity(), {}]), limit=2)
        self.assertEqual((result.status, result.coverage, result.quality, result.received_count, len(result.records)),
                         ("coverage_limited", "coverage_limited", "partial", 2, 1))
        self.assertEqual(hs.analyse_activities(response([{}, {}, {}]), limit=2).status, "invalid_response")
        self.assertEqual(hs.analyse_activities(response([])).status, "empty")

    def test_activity_request_and_allowlist_enforce_trailing_bounded_summary_only(self):
        for days in (1, 30):
            payload = hs.activity_request(days, 100)
            hs.check_request("POST", hs.ACTIVITIES_URL, json.dumps(payload).encode())
            self.assertEqual(int(payload["endTime"]) - int(payload["startTime"]), days * 86400000)
        payload = hs.activity_request()
        for change in ({"limit": True}, {"limit": 101}, {"order": "startTimeAsc"},
                       {"detailDataType": ["gps"]}, {"endTime": str(int(payload["endTime"]) - 60001)}):
            with self.assertRaises(ValueError):
                hs.check_request("POST", hs.ACTIVITIES_URL, json.dumps({**payload, **change}).encode())
        for method, url in (("GET", hs.ACTIVITIES_URL), ("POST", hs.ACTIVITIES_URL + "/details"),
                            ("POST", "http://example.invalid")):
            with self.assertRaises(ValueError):
                hs.check_request(method, url, json.dumps(payload).encode())
        # A returned record outside the requested window is not fresh coverage.
        self.assertEqual(hs.analyse_activities(response([activity()]), start_ms=BASE_MS + 1, end_ms=BASE_MS + 1000).records, [])

    def test_metric_request_day_types_timezone_and_fixed_shapes(self):
        self.write_auth()
        with self.fake_http() as (transport, _, _):
            self.sync()
        queries = {(url,payload['reqs'][0]['dataType']): payload for _,url,payload,_ in transport.calls if 'reqs' in payload}
        for metric in hs.METRICS:
            expected_type = str if metric == 'hrv' else int
            data = queries[(hs.METRICS[metric][0],hs.METRICS[metric][1])]
            self.assertEqual(set(data), {"reqs", "groupReqs"})
            self.assertEqual(data["reqs"], data["groupReqs"])
            item = data["reqs"][0]
            self.assertIs(type(item["startDay"]), expected_type)
            self.assertIs(type(item["endDay"]), expected_type)
            self.assertEqual((str(item["startDay"]), str(item["endDay"])), ("20260812", "20260818"))
            self.assertEqual((item["timeZone"], item["groupOption"], item["strategy"]), ("+0800", "day", ["MAX", "MIN", "AVG", "SUM", "COUNT"]))
            self.assertEqual(item.get("fieldNames"), ["avgHrv"] if metric == "hrv" else None)
            for change in ({"startDay": int(item["startDay"]) if metric == "hrv" else str(item["startDay"])},
                           {"timeZone": "UTC"}, {"groupOption": None}, {"dataType": "com.huawei.spO2"}):
                wrong = {**item, **change}
                with self.assertRaises(ValueError):
                    hs.check_request("POST", hs.METRICS[metric][0], json.dumps({"reqs": [wrong], "groupReqs": [wrong]}).encode())
        for invalid in (True, 20260230, "٢٠٢٦٠٨١٨", "2026-08-18", 20260818.0):
            self.assertIsNone(hs.day_string(invalid))

    def test_metric_parser_results_groups_first_duplicate_day_and_whitelist(self):
        field = "avgHrv"
        blocks = [dict(fieldName=field, startDay=day, statistics=dict(avg=value, min=1, max=99, count=2), raw=MARKER)
                  for day, value in ((20260818, 55), ("20260817", 44), (20260818, 77))]
        raw = dict(results=[dict(fieldName=field, statistics=dict(avg=66, max=99, min=1, count=4))],
                   groupResults=[dict(groupStatistics=blocks)])
        result = hs.analyse_metric(response(raw), "hrv", start_day="20260812", end_day="20260818")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.overall["avg"], 66)
        self.assertEqual([(r["day"], r["avg"]) for r in result.records], [("2026-08-17", 44), ("2026-08-18", 55)])
        self.assertTrue(all(r["unit"] is None and r["sum"] is None for r in result.records))
        self.assertEqual(set(result.records[0]), set(hs.METRIC_KEYS))
        self.assertNotIn(MARKER, repr(result.records))
        self.assertNotIn("2026", repr(result))

    def test_explicit_zero_sample_count_is_not_a_physiological_zero(self):
        field=hs.METRICS['resting_hr'][2]
        raw=dict(results=[dict(fieldName=field,statistics=dict(avg=0,min=0,max=0,sum=0,count=0))],
            groupResults=[dict(groupStatistics=[dict(fieldName=field,startDay=20260818,statistics=dict(avg=0,min=0,max=0,sum=0,count=0))])])
        result=hs.analyse_metric(response(raw),'resting_hr',start_day=20260812,end_day=20260818)
        self.assertEqual(result.status,'empty')
        self.assertEqual(result.records,[])
        self.assertTrue(all(result.overall[k] is None for k in ['avg','min','max','sum']))
        self.assertEqual(result.overall['count'],0)
        self.assertIn('COUNT',hs.metric_request('resting_hr')['reqs'][0]['strategy'])

    def test_metric_empty_null_missing_and_invalid_are_distinct(self):
        parse = lambda data: hs.analyse_metric(response(data), "resting_hr", start_day=20260812, end_day=20260818)
        self.assertEqual(parse(dict(results=[], groupResults=[])).status, "empty")
        raw = dict(results=[dict(fieldName="restBpm", statistics=None)],
                   groupResults=[dict(groupStatistics=[dict(fieldName="restBpm", startDay=20260818, statistics=dict(avg=None, min=True))])])
        result = parse(raw)
        self.assertEqual(result.status, "partial")
        self.assertEqual(len(result.records), 1)
        self.assertTrue(all(result.records[0][k] is None for k in hs.STAT_KEYS))
        for data in ({}, {"error": "not_supported"}, {"results": None, "groupResults": []},
                     {"results": [], "groupResults": [{}]},
                     {"results": [{"fieldName": "unknown", "statistics": {}}], "groupResults": []}):
            self.assertEqual(parse(data).status, "invalid_response")
        values = hs.stat_block(dict(avg=float("nan"), min=-1, max=10**100, count=True, sum="12"))
        self.assertTrue(all(v is None for v in values.values()))
        raw["groupResults"][0]["groupStatistics"][0]["startDay"] = 20260230
        self.assertEqual(parse(raw).records, [])

    def test_metric_daily_storage_upserts_without_deleting_on_empty_or_error(self):
        self.write_auth()
        entries = [dict(fieldName="avgHrv", startDay=20260818,
                        statistics=dict(avg=61, min=50, max=70, count=2)),
                   dict(fieldName="avgHrv", startDay=20260817,
                        statistics=dict(avg=None, min=None, max=None, count=0))]
        with self.fake_http(overrides={hs.HRV_URL: stats_response("hrv", entries=entries)}):
            self.sync(); self.sync()
        with self.db() as db:
            self.assertEqual(db.execute("SELECT metric,unit,count FROM metric_stats ORDER BY metric,day").fetchall(),
                             [("all_day_heart_rate", "bpm", 2), ("hrv", None, 2), ("resting_hr", "bpm", 2), ("spo2", "percent", 2)])
            self.assertIsNone(db.execute("SELECT avg,min,max,sum FROM metric_stats WHERE metric='hrv' AND day='2026-08-17'").fetchone())
            self.assertEqual([r[1] for r in db.execute("PRAGMA table_info(metric_stats)")], [*hs.METRIC_KEYS, "source"])
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        with self.fake_http(overrides={hs.RESTING_HR_URL: response(dict(results=[], groupResults=[])), hs.HRV_URL: response({}, 503)}, items=[]):
            result = self.sync()
        self.assertEqual(result["status"], "collection_error")
        self.assertEqual(result["sources"]["resting_hr"]["last_collection_status"], "empty")
        self.assertEqual(result["sources"]["hrv"]["last_collection_status"], "service_error")
        report = h.read_view(self.state, self.auth, mode="report", limit=1)
        for name in ("resting_hr", "hrv"):
            self.assertEqual((report["sources"][name]["count"], report["sources"][name]["returned_records"]),
                             (1, 1))
        self.assertEqual(report["sources"]["hrv"]["records"][0]["avg"], 61)
        self.assertEqual(report["sources"]["activities"]["count"], 2)
        self.assert_private((self.state / app.DATABASE_NAME).read_bytes().decode("latin1"))

    def test_unified_status_has_no_health_values_and_report_marks_stale_auth(self):
        self.write_auth()
        with self.fake_http():
            self.sync()
        db_path = self.state / app.DATABASE_NAME
        before = db_path.read_bytes()
        with patch.object(app, "load_auth") as auth:
            status = h.read_view(self.state, self.auth)
            latest = h.read_view(self.state, self.auth, mode="latest")
            report = h.read_view(self.state, self.auth, mode="report", limit=1)
            auth.assert_not_called()
        self.assertEqual(set(status["sources"]), set(h.SOURCE_NAMES))
        for entry in status["sources"].values():
            self.assertNotIn("summary", entry); self.assertNotIn("records", entry)
            self.assertEqual(entry["freshness"], "fresh")
        self.assertEqual(latest["sources"]["sleep"]["summary"]["total_sleep_minutes"], 420)
        self.assertEqual(report["sources"]["activities"]["returned_records"], 1)
        self.assertEqual(before, db_path.read_bytes())
        with self.fake_http(overrides={hs.ACTIVITIES_URL: response({}, 401)}):
            self.sync()
        stale = h.read_view(self.state, self.auth, mode="latest")
        self.assertEqual((stale["status"], stale["authentication"]["state"]), ("reauth_required", "reauth_required"))
        self.assertTrue(stale["saved_data_only"])
        self.assertEqual(stale["sources"]["activities"]["summary"], latest["sources"]["activities"]["summary"])
        self.assertTrue(all(s["freshness"] == "stale_auth" for s in stale["sources"].values()))

    def test_auth_failure_stops_remaining_sources_and_marker_edits_do_not_unblock(self):
        self.write_auth()
        with self.fake_http(overrides={hs.ACTIVITIES_URL: response({}, 401)}) as (transport, fetch, _):
            result = self.sync()
            self.assertEqual(len(transport.calls), 1); fetch.assert_not_called()
        self.assertTrue(result["network_attempted"])
        self.assertFalse(result["sources"]["hrv"]["network_attempted"])
        marker = self.state / "sync-status.json"
        marker.write_text(json.dumps(dict(authentication_required=False, checked_at_utc=NOW.isoformat())))
        marker.chmod(0o600)
        with self.db() as db:
            db.execute("UPDATE health_sync_state SET authentication_required=0 WHERE singleton=1")
        self.assertEqual(h.read_view(self.state, self.auth)["authentication"]["state"], "reauth_required")
        os.utime(self.auth, ns=(int(NOW.timestamp() * 1000000000),) * 2)
        with self.fake_http() as (transport, fetch, factory):
            blocked = self.sync()
            self.assertFalse(blocked["network_attempted"])
            self.assertEqual(transport.calls, []); fetch.assert_not_called(); factory.assert_not_called()
        # New credentials only permit verification. They are not called valid
        # until an endpoint returns a recognized success (not a marker edit).
        self.write_auth({**AUTH, "Authorization": "SYNTHETIC_RENEWED_TOKEN"})
        self.assertEqual(h.read_view(self.state, self.auth)["status"], "reauth_required")
        with self.fake_http() as (transport, _, _):
            recovered = self.sync()
        self.assertEqual((recovered["status"], recovered["authentication"]["state"], len(transport.calls)), ("ok", "verified", 1+len(hs.METRICS)))

    def test_sleep_or_metric_auth_failure_also_stops_following_requests(self):
        self.write_auth()
        with self.fake_http(sleep_result=sleep.Result("reauth_required")) as (transport, fetch, _):
            self.assertEqual(self.sync()["status"], "reauth_required")
            self.assertEqual([c[1] for c in transport.calls], [hs.ACTIVITIES_URL])
            fetch.assert_called_once()
        self.write_auth({**AUTH, "Authorization": "SYNTHETIC_ANOTHER_TOKEN"})
        with self.fake_http(overrides={hs.RESTING_HR_URL: response({}, 403)}) as (transport, _, _):
            self.assertEqual(self.sync()["status"], "reauth_required")
            self.assertEqual([c[1] for c in transport.calls], [hs.ACTIVITIES_URL, hs.RESTING_HR_URL])

    def test_missing_auth_and_legacy_pause_have_no_network_and_preserve_v1(self):
        with self.fake_http() as (transport, fetch, factory):
            self.assertEqual(self.sync()["status"], "reauth_required")
            self.assertEqual(transport.calls, []); fetch.assert_not_called(); factory.assert_not_called()
        self.write_auth()
        # Simulate the newer deployed v1 scheduler refusing the same auth.
        at = NOW + timedelta(seconds=1)
        marker = self.state / "sync-status.json"
        marker.write_text(json.dumps(dict(authentication_required=True, auth_mtime_ns=self.auth.stat().st_mtime_ns, checked_at_utc=at.isoformat())))
        marker.chmod(0o600)
        with app.Store(self.state, create=True) as store:
            store.record("reauth_required", at.isoformat(), app.normalize_summary(collector.summarize(activity())))
        with self.fake_http() as (transport, fetch, factory):
            result = self.sync()
            self.assertFalse(result["network_attempted"])
            self.assertEqual(transport.calls, []); fetch.assert_not_called(); factory.assert_not_called()
        self.assertEqual(h.read_view(self.state, self.auth, mode="latest")["sources"]["activities"]["count"], 1)

    def test_legacy_database_failure_pauses_even_without_json_marker(self):
        self.write_auth()
        with app.Store(self.state, create=True) as store:
            store.record("reauth_required", NOW.isoformat(), None)
        with self.fake_http() as (transport, _, _):
            self.assertFalse(self.sync()["network_attempted"])
            self.assertEqual(transport.calls, [])

    def test_changed_auth_and_old_sync_results_are_not_fresh_without_verification(self):
        self.write_auth()
        with self.fake_http():
            self.sync()
        old = h.read_view(self.state, self.auth)
        later = NOW + timedelta(days=3)
        with patch.object(h, "utc_now", return_value=later):
            stale = h.read_view(self.state, self.auth)
        self.assertTrue(all(e["freshness"] == "stale" for e in stale["sources"].values()))
        os.utime(self.auth, ns=(self.auth.stat().st_mtime_ns + 1,) * 2)
        changed = h.read_view(self.state, self.auth)
        self.assertEqual(changed["authentication"]["state"], "verification_required")
        self.assertTrue(all(e["freshness"] == "stale_auth" for e in changed["sources"].values()))
        self.assertEqual(changed["last_success_time_utc"], old["last_success_time_utc"])

    def test_capabilities_do_not_invent_support_or_hrv_units(self):
        cap = h.capabilities()["capabilities"]
        self.assertEqual(set(cap), {*h.SOURCE_NAMES, "steps"})
        for name in h.SOURCE_NAMES:
            self.assertTrue(cap[name]["integrated"])
        self.assertEqual(cap["hrv"]["unit"], None)
        self.assertEqual((cap['steps']['integrated'],cap['steps']['availability']),(False,'not_verified'))
        self.assertEqual(cap['all_day_heart_rate']['granularity'],'daily_min_max')
        self.assertFalse(cap['all_day_heart_rate']['raw_time_series_verified'])
        self.assertEqual(cap['spo2']['unit'],'percent')
        self.assertNotIn("unsupported", json.dumps(cap))

    def test_http_transport_and_invalid_errors_are_distinct_never_retried(self):
        cases = [(401, "reauth_required"), (429, "rate_limited"), (503, "service_error"), (400, "http_error"), (304, "redirect_rejected")]
        for code, expected in cases:
            result = hs.analyse_metric(response({}, code), "hrv", start_day="20260812", end_day="20260818")
            self.assertEqual(result.status, expected)
        for body in (b"not_json", b'{"error":"login"}', b"x" * (hs.MAX_BODY + 1)):
            result = hs.analyse_metric(collector.Response(200, body), "hrv", start_day="20260812", end_day="20260818")
            self.assertEqual(result.status, "invalid_response")
        self.assertEqual(hs.analyse_activities(collector.Response(200, b"<HTML>login</HTML>", "text/html")).status, "reauth_required")
        self.write_auth()
        with self.fake_http(overrides={hs.HRV_URL: RuntimeError(MARKER)}) as (transport, _, _):
            result = self.sync()
        self.assertEqual(result["sources"]["hrv"]["last_collection_status"], "transport_error")
        self.assertEqual(len(transport.calls), 1+len(hs.METRICS))
        self.assert_private(json.dumps(result))

    def test_service_failures_do_not_fabricate_auth_failure_or_verification(self):
        self.write_auth()
        with self.fake_http(overrides={hs.ACTIVITIES_URL: response({}, 503),
                hs.RESTING_HR_URL: response({}, 429), hs.HRV_URL: response({})},
                sleep_result=sleep.Result("transport_error")) as (transport, _, _), \
                patch.object(hp,'fetch',return_value=hs.Result('service_error')):
            result = self.sync()
        self.assertEqual(result["status"], "collection_error")
        self.assertEqual(result["authentication"]["state"], "unverified")
        self.assertIsNone(result["authentication"]["last_verified_time_utc"])
        self.assertFalse(result["authentication_required"])
        self.assertEqual(len(transport.calls), 1+len(hs.METRICS))
        self.assertTrue(all(e["coverage"] == "not_assessed" for e in result["sources"].values()))

    def test_official_transport_tls_no_proxy_no_redirect_bounds_and_timeout(self):
        handle = Mock()
        handle.code = 200
        handle.headers = {"Content-Type": "application/json"}
        handle.read.return_value = b"[]"
        handle.__enter__ = Mock(return_value=handle)
        handle.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = handle
        with patch.object(request, "build_opener", return_value=opener) as factory:
            transport = hs.OfficialTransport(network_authorized=True)
            handlers = factory.call_args.args
            https = next(x for x in handlers if isinstance(x, request.HTTPSHandler))
            self.assertTrue(https._context.check_hostname)
            self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(next(x for x in handlers if isinstance(x, request.ProxyHandler)).proxies, {})
            self.assertTrue(any(isinstance(x, collector.NoRedirect) for x in handlers))
            self.assertEqual(hs.fetch_activities(AUTH, transport=transport).status, "empty")
            self.assertEqual(opener.open.call_args.kwargs, {"timeout": 10})
            handle.read.assert_called_once_with(hs.MAX_BODY + 1)
            handle.read.return_value = b"x" * (hs.MAX_BODY + 1)
            self.assertEqual(hs.fetch_activities(AUTH, transport=transport).status, "invalid_response")
            self.assertEqual(opener.open.call_count, 2)
            handle.code = 401
            handle.read.reset_mock()
            self.assertEqual(hs.fetch_activities(AUTH, transport=transport).status, "reauth_required")
            handle.read.assert_not_called()
        with self.assertRaises(ValueError):
            hs.OfficialTransport()

    def test_point_integrates_without_day_aggregation_and_retains_old_measurement_age(self):
        self.write_auth()
        with self.fake_http():
            self.sync();self.sync()
        with self.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM point_measurements").fetchone()[0],1)
            self.assertEqual(db.execute("SELECT count(*) FROM metric_stats WHERE metric='vo2max'").fetchone()[0],0)
        saved=h.read_view(self.state,self.auth,mode='latest')['sources']['vo2max']
        self.assertEqual(saved['count'],1)
        self.assertEqual(saved['coverage'],'latest_measurement')
        self.assertIsNone(saved['lookback_days'])
        self.assertEqual(saved['freshness'],'fresh')
        self.assertEqual(saved['data_freshness'],'stale')
        self.assertEqual(saved['summary']['value'],137)
        self.assertEqual(saved['summary']['measured_at_ns'],point_fixture()['measured_at_ns'])
        self.assertIsNone(saved['summary']['unit'])
        self.assertFalse(any(k in saved['summary'] for k in ['day','avg','min','max','count']))
        with self.fake_http(),patch.object(hp,'fetch',return_value=hs.Result('invalid_response')):
            result=self.sync()
        self.assertEqual(result['sources']['vo2max']['count'],1)
        self.assertEqual(result['sources']['vo2max']['freshness'],'collection_failed')

    def test_existing_six_source_state_rows_migrate_atomically_for_vo2(self):
        app.init_state(self.state)
        with app.Store(self.state,create=True) as store:
            h.ensure_schema(store.connection)
            db=store.connection
            ddl=db.execute("SELECT sql FROM sqlite_master WHERE name='health_source_state'").fetchone()[0]
            db.execute('DROP TABLE health_source_state')
            db.execute(ddl.replace(",'vo2max'",''))
            row=('activities','ok',NOW.isoformat(),NOW.isoformat(),2,2,'bounded_window','ok',30,100)
            db.execute('INSERT INTO health_source_state VALUES (?,?,?,?,?,?,?,?,?,?)',row);db.commit()
            h.ensure_schema(db);h.ensure_schema(db)
            self.assertEqual(db.execute('SELECT * FROM health_source_state').fetchall(),[row])
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='health_source_state_before_points'").fetchone())
            self.assertIn("'vo2max'",db.execute("SELECT sql FROM sqlite_master WHERE name='health_source_state'").fetchone()[0])
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok')

    def test_private_auth_hook_precedes_pause_and_cannot_clear_it_without_proof(self):
        app.init_state(self.state)
        self.write_auth(path=self.state/'auth.json')
        with self.fake_http(overrides={hs.ACTIVITIES_URL:response({},401)}):
            h.run_once(self.state)
        with patch.object(app,'DEFAULT_STATE_DIR',self.state), patch.object(h.auth_session,'ensure_auth',return_value={'status':'reauth_required','vps_auth_verified':False}) as hook, self.fake_http() as (transport,fetch,factory):
            result=h.run_once(self.state)
            self.assertEqual(result['status'],'reauth_required')
            hook.assert_called_once_with(self.state,force=True)
            self.assertEqual(transport.calls,[])
            fetch.assert_not_called()
        with patch.object(app,'DEFAULT_STATE_DIR',self.state), patch.object(h.auth_session,'ensure_auth',return_value={'status':'ok','vps_auth_verified':True,'revalidated':True}) as hook, self.fake_http():
            result=h.run_once(self.state)
            self.assertEqual(result['authentication']['state'],'verified')
            hook.assert_called_once_with(self.state,force=True)

    def test_expired_endpoint_gets_only_one_verified_changed_token_retry(self):
        app.init_state(self.state)
        self.write_auth(path=self.state/'auth.json')
        def renew(state,force=False):
            self.assertEqual(state,self.state)
            if force:
                self.write_auth({**AUTH,'Authorization':'SYNTHETIC_NEW_ROTATED'},path=self.state/'auth.json')
                return {'status':'ok','vps_auth_verified':True,'revalidated':True,'renewed':True}
            return {'status':'ok','vps_auth_verified':True,'renewed':False}
        success=hs.analyse_activities(response([activity()]))
        with patch.object(app,'DEFAULT_STATE_DIR',self.state), patch.object(h.auth_session,'ensure_auth',side_effect=renew) as hook, self.fake_http(), patch.object(hs,'fetch_activities',side_effect=[hs.Result('reauth_required'),success]) as activity_fetch:
            result=h.run_once(self.state)
            self.assertEqual(result['status'],'ok')
            self.assertEqual(activity_fetch.call_count,2)
            self.assertEqual(hook.call_count,2)
            self.assertEqual(activity_fetch.call_args_list[0].args[0]['Authorization'],AUTH['Authorization'])
            self.assertEqual(activity_fetch.call_args_list[1].args[0]['Authorization'],'SYNTHETIC_NEW_ROTATED')

    def test_unchanged_rejected_token_is_not_retried_after_recovery(self):
        app.init_state(self.state)
        self.write_auth(path=self.state/'auth.json')
        with patch.object(app,'DEFAULT_STATE_DIR',self.state), patch.object(h.auth_session,'ensure_auth',return_value={'status':'ok','vps_auth_verified':True,'revalidated':True}) as hook, self.fake_http() as (transport,fetch,factory), patch.object(hs,'fetch_activities',return_value=hs.Result('reauth_required')) as activity_fetch:
            result=h.run_once(self.state)
            self.assertEqual(result['status'],'reauth_required')
            self.assertEqual(activity_fetch.call_count,1)
            self.assertEqual(hook.call_count,2)
            self.assertEqual(transport.calls,[])
            fetch.assert_not_called()

    def test_unified_history_cli_uses_explicit_paths_and_resume_is_offline(self):
        from test_history import FakeTransport as HistoryFake
        self.write_auth()
        transport=HistoryFake(empty=True)
        options=['--start','2026-08-10','--end','2026-08-16']
        with patch.object(h.history,'utc_now',return_value=NOW),patch.object(h.history,'OfficialTransport',return_value=transport):
            code,out=self.cli(*['--state-dir',str(self.state),'--auth-file',str(self.auth),'backfill',*options])
        self.assertEqual(code,0)
        self.assertTrue(out['requested_scope_queried'])
        self.assertFalse(out['complete_history'])
        self.assertEqual(out['completed_windows'],len(h.history.SOURCE_NAMES))
        self.assertEqual(len(transport.calls),len(h.history.SOURCE_NAMES))
        with patch.object(h.history,'utc_now',return_value=NOW),patch.object(app,'load_auth',side_effect=AssertionError('no credential read on completed resume')):
            code,resumed=self.cli(*['backfill','--state-dir',str(self.state),'--auth-file',str(self.auth),*options])
            saved_code,saved=self.cli(*['history-status','--state-dir',str(self.state),*options])
        self.assertEqual((code,saved_code,resumed['network_calls']),(0,0,0))
        self.assertEqual(saved['scope_start'],'2026-08-10')
        self.assertEqual(saved['completed_windows'],len(h.history.SOURCE_NAMES))
        self.assert_private(json.dumps(saved))

    def test_history_cli_validates_scope_before_storage_or_credentials(self):
        with patch.object(app,'Store',side_effect=AssertionError('no storage')),patch.object(app,'load_auth',side_effect=AssertionError('no credentials')):
            for extra in [['--days','366'],['--window-days','31'],['--start','2026-02-30','--end','2026-03-01'],['--source','vo2max']]:
                code,out=self.cli(*['backfill','--state-dir',str(self.state),*extra])
                self.assertEqual((code,out['status']),(2,'invalid_arguments'))
        self.assertFalse(self.state.exists())

    def test_shared_lock_and_unsafe_state_fail_before_auth_or_http(self):
        self.write_auth()
        app.init_state(self.state)
        fd = os.open(self.state / "sync.lock", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.fake_http() as (transport, fetch, _), patch.object(app, "load_auth") as auth:
                result = self.sync()
                self.assertEqual(result["status"], "already_running")
                self.assertEqual(transport.calls, []); fetch.assert_not_called(); auth.assert_not_called()
        finally:
            os.close(fd)
        self.state.chmod(0o755)
        with patch.object(app, "load_auth") as auth:
            self.assertEqual(self.cli("sync", "--state-dir", str(self.state), "--auth-file", str(self.auth))[1]["status"], "storage_error")
            auth.assert_not_called()


if __name__ == "__main__":
    unittest.main()
