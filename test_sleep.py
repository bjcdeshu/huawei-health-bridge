"""Synthetic-only sleep/scheduler regression tests; never access real auth."""
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib import error, request, parse

import app
import collector
import sleep_collector as s
import sync

AUTH = {"Authorization": "SYNTHETIC_ONLY", "x-client-id": "SYNTHETIC_ONLY"}
BASE_MS = 1700000000000


def record():
    values = {"go_bed_time": BASE_MS - 300000, "fall_asleep_time": BASE_MS,
              "wakeup_time": BASE_MS + 425 * 60000, "all_sleep_time": 420,
              "light_sleep_time": 220, "deep_sleep_time": 120, "dream_time": 80,
              "awake_time": 5, "sleep_latency": 5, "wakeup_count": 1,
              "sleep_score": 80, "sleep_efficiency": 98, "sleep_type": 1}
    return {"startTime": BASE_MS * 1000000, "endTime": (BASE_MS + 425 * 60000) * 1000000,
            "value": [{"fieldName": k, "longValue": v} for k, v in values.items()],
            "id": "SYNTHETIC_PRIVATE_ID", "gps": "SYNTHETIC_GPS", "subData": "SYNTHETIC_FRAGMENTS"}


def response(items=None):
    return collector.Response(200, json.dumps({"healthRecords": [record()] if items is None else items}).encode())


class SleepTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sleep-tests-", dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "private"
        app.init_state(self.state)
        guard = patch.object(request.OpenerDirector, "open", side_effect=AssertionError("network_forbidden_in_tests"))
        self.network = guard.start()
        self.addCleanup(guard.stop)
        originals = app.Store, app.load_auth
        def guarded_store(state_dir, **kw):
            self.assertEqual(Path(state_dir), self.state)
            return originals[0](state_dir, **kw)
        def guarded_auth(path):
            self.assertTrue(Path(path).is_relative_to(self.state))
            return originals[1](path)
        for guard in [patch.object(app, "Store", side_effect=guarded_store), patch.object(app, "load_auth", side_effect=guarded_auth)]:
            guard.start()
            self.addCleanup(guard.stop)

    def auth(self):
        p = self.state / "auth.json"
        p.write_text(json.dumps(AUTH))
        p.chmod(0o600)

    def collect(self, data=None):
        self.auth()
        result = s.analyse(response(data))
        with patch.object(s, "fetch", return_value=result) as fetch:
            out = s.collect_once(self.state)
        fetch.assert_called_once()
        self.network.assert_not_called()
        return out

    def test_time_units_and_allowlisted_values(self):
        result = s.analyse(response())
        self.assertEqual(result.status, "ok")
        x = result.records[0]
        self.assertEqual(x["start_time_utc"], "2023-11-14T22:13:20+00:00")
        self.assertEqual(x["fall_asleep_time_utc"], x["start_time_utc"])
        self.assertEqual(x["total_sleep_minutes"], 420)
        self.assertEqual(x["rem_sleep_minutes"], 80)
        self.assertEqual(set(x), set(s.KEYS))
        self.assertNotIn("summary", repr(result))
        self.assertNotIn("2023", repr(result))

    def test_response_errors_and_empty_are_distinct(self):
        for code, expected in [(401,"reauth_required"),(403,"reauth_required"),(302,"reauth_required"),
                               (429,"rate_limited"),(503,"service_error"),(400,"http_error")]:
            self.assertEqual(s.analyse(collector.Response(code, b"SYNTHETIC_PRIVATE")).status, expected)
        self.assertEqual(s.analyse(response([])).status, "empty")
        self.assertEqual(s.analyse(collector.Response(200,b"<html>login</html>","text/html")).status,"reauth_required")
        for body in [b"not-json",b'{"error":"login"}',b'{"healthRecords":null}',b'[null]',b"x"*(collector.MAX_BODY+1)]:
            self.assertEqual(s.analyse(collector.Response(200,body)).status,"invalid_response")

    def test_missing_and_malformed_values_are_not_zero(self):
        raw = record()
        raw["value"] = [{"fieldName":"sleep_type","longValue":1},
                        {"fieldName":{},"longValue":12},
                        {"fieldName":"all_sleep_time","longValue":True}]
        r=s.analyse(response([raw]))
        self.assertEqual(r.status,"partial")
        self.assertIsNone(r.records[0]["total_sleep_minutes"])
        self.assertIsNone(r.records[0]["sleep_score"])
        for value in [True,-1,float("nan"),float("inf"),10**100,"420"]:
            self.assertIsNone(s.integer(value))
        raw["startTime"]="not-a-timestamp"
        self.assertEqual(s.analyse(response([raw])).records,[])

    def test_sleep_storage_is_idempotent_and_never_saves_raw(self):
        self.collect();self.collect()
        out=s.read(self.state,latest=True)
        self.assertEqual(out["count"],1)
        self.assertEqual(out["summary"]["total_sleep_minutes"],420)
        with sqlite3.connect(self.state/app.DATABASE_NAME) as db:
            columns=[x[1] for x in db.execute("PRAGMA table_info(sleep_records)")]
            self.assertEqual(columns,[*s.KEYS,"source"])
            self.assertEqual(db.execute("SELECT count(*) FROM activities").fetchone()[0],0)
            self.assertEqual(db.execute("SELECT source FROM sleep_records").fetchone()[0],app.SOURCE)
        binary=(self.state/app.DATABASE_NAME).read_bytes()
        for marker in [b"SYNTHETIC_PRIVATE_ID",b"SYNTHETIC_GPS",b"SYNTHETIC_FRAGMENTS",b"SYNTHETIC_ONLY"]:
            self.assertNotIn(marker,binary)
        self.assertEqual((self.state/app.DATABASE_NAME).stat().st_mode & 0o777,0o600)

    def test_empty_and_failure_preserve_saved_records(self):
        self.collect()
        for r in [s.Result("empty"),s.Result("reauth_required"),s.Result("service_error")]:
            with patch.object(s,"fetch",return_value=r):
                out=s.collect_once(self.state)
            self.assertEqual(out["status"],r.status)
            self.assertEqual(s.read(self.state,latest=True)["count"],1)

    def test_missing_auth_has_no_network(self):
        with patch.object(s,"fetch") as fetch:
            out=s.collect_once(self.state)
        self.assertEqual(out["status"],"reauth_required")
        fetch.assert_not_called()
        self.network.assert_not_called()

    def test_fixed_get_query_uses_nanoseconds_and_tls(self):
        opener=unittest.mock.Mock()
        handle=unittest.mock.Mock()
        handle.status=200;handle.headers={"Content-Type":"application/json"};handle.read.return_value=response([]).body
        handle.__enter__=unittest.mock.Mock(return_value=handle);handle.__exit__=unittest.mock.Mock(return_value=False)
        opener.open.return_value=handle
        now=1700000000000000000
        with patch.object(s.time,"time_ns",return_value=now),patch.object(s.request,"build_opener",return_value=opener) as factory:
            self.assertEqual(s.fetch(AUTH,days=7).status,"empty")
        req=opener.open.call_args.args[0]
        self.assertEqual(req.get_method(),"GET")
        self.assertTrue(req.full_url.startswith(s.URL+"?"))
        q=parse.parse_qs(parse.urlsplit(req.full_url).query)
        self.assertEqual(q["dataType"],[s.DATA_TYPE]);self.assertNotIn('subDataType',q)
        self.assertEqual(int(q["endTime"][0])-int(q["startTime"][0]),7*86400*1000000000)
        self.assertEqual(opener.open.call_args.kwargs["timeout"],10)
        self.assertEqual(opener.open.call_count,1)
        handlers=factory.call_args.args
        self.assertEqual(next(x for x in handlers if isinstance(x,request.ProxyHandler)).proxies,{})
        self.assertTrue(next(x for x in handlers if isinstance(x,request.HTTPSHandler))._context.check_hostname)
        self.assertTrue(any(isinstance(x,collector.NoRedirect) for x in handlers))

    def test_bad_day_or_limit_is_rejected(self):
        for d in [0,31,True,"7"]:
            with self.assertRaises(app.InvalidArguments):s.collect_once(self.state,days=d)
        for limit in [0,101,True]:
            with self.assertRaises(app.InvalidArguments):s.read(self.state,limit=limit)

    def test_scheduler_pauses_network_until_credentials_change(self):
        self.auth()
        with patch.object(app,"collect_once",return_value={"status":"reauth_required","stored":False}) as activity,patch.object(s,"collect_once") as sleep:
            report,code=sync.run_once(self.state)
            self.assertEqual(code,3);self.assertTrue(report["authentication_required"])
            self.assertEqual(activity.call_count,1);sleep.assert_not_called()
            report,code=sync.run_once(self.state)
            self.assertEqual(code,3);self.assertFalse(report["network_attempted"])
            self.assertEqual(activity.call_count,1)
        p=self.state/"auth.json";old=p.stat().st_mtime_ns
        os.utime(p,ns=(old+1000000,old+1000000))
        with patch.object(app,"collect_once",return_value={"status":"ok","stored":True}),patch.object(s,"collect_once",return_value={"status":"ok","stored_records":1}):
            report,code=sync.run_once(self.state)
        self.assertEqual(code,0);self.assertFalse(report["authentication_required"])
        text=json.dumps(report)
        self.assertNotIn("SYNTHETIC_ONLY",text)
        self.assertNotIn("summary",text)
        self.assertEqual((self.state/"sync-status.json").stat().st_mode & 0o777,0o600)


if __name__ == "__main__":
    unittest.main()
