"""Synthetic integration for read-only CLI, coverage, and bounded catch-up."""
import contextlib
import io
import json
import unittest
from datetime import timedelta
from unittest.mock import Mock, patch

import app
import health as h
import health_history as hist
import health_recovery as recovery
import test_health as fixtures
from test_history import FakeTransport


class RecoveryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fx=fixtures.HealthTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.addCleanup(self.fx.tearDown)
        self.fx.write_auth()
        timer=patch.object(hist,'utc_now',return_value=fixtures.NOW)
        timer.start();self.addCleanup(timer.stop)

    def seed(self):
        with self.fx.fake_http():self.fx.sync()

    def cli(self,*args):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code=h.main(['--state-dir',str(self.fx.state),'--auth-file',str(self.fx.auth),*args])
        return code,json.loads(output.getvalue())

    def make_outage(self,names=('hrv',),days=20):
        self.seed()
        with self.fx.db() as db:
            for name in names:
                db.execute('UPDATE health_source_state SET last_success_time_utc=? WHERE name=?',((fixtures.NOW-timedelta(days=days)).isoformat(),name))
        return recovery.plan_recovery(self.fx.state,now=fixtures.NOW)

    def test_cold_start_is_read_only_and_not_a_full_year_outage(self):
        with patch.object(app,'load_auth',side_effect=AssertionError('no_auth')):
            plan=recovery.plan_recovery(self.fx.state,now=fixtures.NOW)
        self.assertEqual(plan['status'],'not_initialized')
        self.assertFalse(plan['pending_ranges'])
        self.assertFalse(self.fx.state.exists())

    def test_recent_collection_with_missing_samples_is_not_outage(self):
        self.seed()
        with self.fx.db() as db:db.execute("DELETE FROM metric_stats WHERE metric='hrv'")
        plan=recovery.plan_recovery(self.fx.state,now=fixtures.NOW)
        self.assertEqual(plan['status'],'up_to_date')
        self.assertFalse(plan['pending_ranges'])

    def test_budgeted_backlog_survives_new_daily_success_and_resumes(self):
        plan=self.make_outage(('hrv','resting_hr','spo2'))
        self.assertEqual(len(plan['pending_ranges']),3)
        recovery.enqueue(self.fx.state,plan,now=fixtures.NOW)
        self.seed()  # Advances live success but cannot discard queued gaps.
        plan=recovery.plan_recovery(self.fx.state,now=fixtures.NOW)
        self.assertEqual(len(plan['pending_ranges']),3)
        fake=FakeTransport(empty=True)
        result=recovery.run_recovery(self.fx.state,lambda:fixtures.AUTH,plan=plan,max_calls=2,now=fixtures.NOW,transport=fake)
        self.assertEqual(result['network_calls'],2)
        self.assertEqual(len(fake.calls),2)
        self.assertEqual(len(result['pending_ranges']),1)
        second=recovery.run_recovery(self.fx.state,lambda:fixtures.AUTH,max_calls=2,now=fixtures.NOW,transport=fake)
        self.assertEqual(second['network_calls'],1)
        self.assertEqual(second['status'],'up_to_date')
        provider=Mock(side_effect=AssertionError('completed_resume_no_auth'))
        third=recovery.run_recovery(self.fx.state,provider,now=fixtures.NOW)
        self.assertEqual(third['network_calls'],0)
        provider.assert_not_called()

    def test_outage_older_than_allowed_year_is_reported_not_fetched(self):
        plan=self.make_outage(days=500)
        self.assertTrue(plan['outside_supported_range'])
        earliest=(fixtures.NOW.astimezone(hist.sources.LOCAL_ZONE).date()-timedelta(days=364)).isoformat()
        self.assertTrue(all(x['start_day']>=earliest for x in plan['pending_ranges']))

    def test_auth_check_failure_stops_without_new_rejection_marker(self):
        plan=self.make_outage(('hrv','resting_hr'))
        provider=Mock(side_effect=hist.HeadersUnavailable())
        result=recovery.run_recovery(self.fx.state,provider,plan=plan,now=fixtures.NOW)
        self.assertEqual(result['status'],'auth_check_error')
        self.assertEqual(result['network_calls'],0)
        self.assertEqual(provider.call_count,1)
        with self.fx.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM health_history_auth_block').fetchone()[0],0)

    def test_live_coverage_excludes_current_day(self):
        self.seed()
        today=fixtures.NOW.astimezone(hist.sources.LOCAL_ZONE).date()
        result=hist.read_coverage(self.fx.state,start=(today-timedelta(days=6)).isoformat(),end=today.isoformat(),source_names=['hrv'],now=fixtures.NOW)
        self.assertEqual(result['queried_days'],6)
        self.assertEqual(result['missing_intervals']['hrv'],[{'start_day':today.isoformat(),'end_day':today.isoformat()}])

    def test_old_offline_scope_cli_and_finished_resume_need_no_auth(self):
        self.seed()
        old=fixtures.NOW-timedelta(days=500)
        start=(old-timedelta(days=3)).date().isoformat();end=(old-timedelta(days=1)).date().isoformat()
        with self.fx.db() as db:
            hist.record_queried_window(db,'hrv',start,end,old,'empty')
        with patch.object(app,'load_auth',side_effect=AssertionError('offline_no_auth')):
            for command in ('history-status','backfill'):
                code,result=self.cli(command,'--start',start,'--end',end,'--source','hrv')
                self.assertEqual(code,0)
                self.assertTrue(result['requested_scope_queried'])
                self.assertEqual(result['network_calls'],0)

    def test_analysis_cli_paths_before_and_after_are_read_only(self):
        self.seed()
        before=(self.fx.state/app.DATABASE_NAME).read_bytes()
        for prefix in [True,False]:
            args=['--state-dir',str(self.fx.state),'--auth-file',str(self.fx.auth)]
            args= args+['analyze','--days','7'] if prefix else ['analyze','--days','7']+args
            with patch.object(app,'load_auth',side_effect=AssertionError('analysis_no_auth')),contextlib.redirect_stdout(io.StringIO()) as output:
                code=h.main(args)
            result=json.loads(output.getvalue())
            self.assertEqual(code,0)
            self.assertTrue(result['saved_data_only'])
            self.assertFalse(result['scope']['includes_today'])
        self.assertEqual(before,(self.fx.state/app.DATABASE_NAME).read_bytes())

    def test_sync_with_empty_recovery_does_no_historical_network(self):
        self.seed()
        with self.fx.fake_http(),patch.object(hist,'run_backfill',side_effect=AssertionError('no_history_needed')):
            code,result=self.cli('sync','--catch-up')
        self.assertEqual(code,0)
        self.assertEqual(result['catch_up']['status'],'up_to_date')
        self.assertEqual(result['catch_up']['network_calls'],0)

    def test_invalid_budget_fails_before_writes(self):
        for args in [('sync','--catch-up','--catch-up-max-calls','0'),('catchup','--max-calls','25')]:
            code,result=self.cli(*args)
            self.assertEqual((code,result['status']),(2,'invalid_arguments'))
        self.assertFalse(self.fx.state.exists())


if __name__=='__main__':unittest.main()
