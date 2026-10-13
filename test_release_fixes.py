"""Release-blocker regressions; synthetic HTTP/state only, no browser or live paths."""
import contextlib
import io
import json
import shlex
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib import parse

import app
import auth_session
import health as h
import health_history as history
import health_recovery as recovery
import health_sources as sources
import sleep_collector as sleep
import test_health as fixtures
import test_history as history_fixtures


class DeploymentContractTests(unittest.TestCase):
    def test_documented_private_tmpdir_matches_broker(self):
        # Only compare strings. No pwd lookup, directory access or browser launch.
        user = SimpleNamespace(pw_dir=str(auth_session.BROWSER_HOME))
        with patch.object(auth_session.pwd, 'getpwnam', return_value=user) as lookup, \
                patch.object(auth_session.subprocess, 'Popen', side_effect=AssertionError('no_browser')):
            args = auth_session.broker_args('restore', 30)
        lookup.assert_called_once_with('health-browser')
        self.assertEqual(args[:6], ['runuser', '-u', 'health-browser', '--', 'env', '-i'])
        tmpdir = next(arg.split('=', 1)[1] for arg in args if arg.startswith('TMPDIR='))
        self.assertEqual(tmpdir, str(auth_session.BROWSER_HOME / 'runtime-tmp'))
        text = (Path(__file__).parent / 'docs/deployment.md').read_text()
        commands = [shlex.split(line) for line in text.splitlines() if line.startswith('sudo install -d ')]
        for directory in (str(auth_session.BROWSER_HOME), tmpdir):
            matching = [command for command in commands if command[-1] == directory]
            self.assertEqual(matching, [['sudo', 'install', '-d', '-m', '0700',
                                         '-o', 'health-browser', '-g', 'health-browser', directory]])


def fake_opener(raw):
    handle = Mock(status=200, code=200, headers={'Content-Type': 'application/json'})
    handle.read.return_value = json.dumps(raw).encode()
    handle.__enter__ = Mock(return_value=handle)
    handle.__exit__ = Mock(return_value=False)
    opener = Mock()
    opener.open.return_value = handle
    return opener


class ReleaseIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.HealthTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.addCleanup(self.fx.tearDown)
        self.fx.write_auth()
        clock = patch.object(history, 'utc_now', return_value=fixtures.NOW)
        clock.start()
        self.addCleanup(clock.stop)

    def cli(self, *args):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = h.main(['--state-dir', str(self.fx.state), '--auth-file', str(self.fx.auth), *args])
        self.fx.assert_private(output.getvalue())
        return code, json.loads(output.getvalue())

    def seed_outage(self, names=('hrv',)):
        self.capped_items = [fixtures.activity(-index * 1000) for index in range(100)]
        with self.fx.fake_http(items=self.capped_items):
            self.assertEqual(self.fx.sync()['status'], 'coverage_limited')
        with self.fx.db() as db:
            for name in names:
                db.execute('UPDATE health_source_state SET last_success_time_utc=? WHERE name=?',
                           ((fixtures.NOW - timedelta(days=20)).isoformat(), name))

    def assert_activity_not_queried(self):
        with self.fx.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM health_history_coverage WHERE source='activities'").fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM activities').fetchone()[0], 100)

    def test_capped_daily_sync_runs_hrv_catchup(self):
        self.seed_outage()
        fake = history_fixtures.FakeTransport(empty=True)
        with self.fx.fake_http(items=self.capped_items), patch.object(history, 'OfficialTransport', return_value=fake):
            code, result = self.cli('sync', '--catch-up')
        self.assertEqual((code, result['status']), (0, 'coverage_limited'))
        self.assertEqual((result['catch_up']['status'], result['catch_up']['network_calls']), ('up_to_date', 1))
        self.assertEqual([call['source'] for call in fake.calls], ['hrv'])
        self.assertEqual(result['sources']['activities']['received_records'], 100)
        self.assertEqual(result['sources']['activities']['stored_records'], 100)
        self.assert_activity_not_queried()

    def test_capped_sync_preserves_two_call_budget_and_queued_remainder(self):
        self.seed_outage(('resting_hr', 'hrv', 'spo2'))
        fake = history_fixtures.FakeTransport(empty=True)
        with self.fx.fake_http(items=self.capped_items), patch.object(history, 'OfficialTransport', return_value=fake):
            code, first = self.cli('sync', '--catch-up', '--catch-up-max-calls', '2')
            self.assertEqual((code, first['catch_up']['network_calls']), (0, 2))
            self.assertEqual(len(fake.calls), 2)
            self.assertEqual([gap['source'] for gap in first['catch_up']['pending_ranges']], ['spo2'])
            code, second = self.cli('sync', '--catch-up', '--catch-up-max-calls', '2')
            self.assertEqual((code, second['catch_up']['network_calls'], second['catch_up']['status']), (0, 1, 'up_to_date'))
            code, third = self.cli('sync', '--catch-up')
            self.assertEqual((code, third['catch_up']['network_calls']), (0, 0))
        self.assertEqual([call['source'] for call in fake.calls], ['resting_hr', 'hrv', 'spo2'])
        self.assert_activity_not_queried()

    def test_catchup_401_after_capped_sync_stops_all_remaining_requests(self):
        self.seed_outage(('resting_hr', 'hrv', 'spo2'))
        fake = history_fixtures.FakeTransport(lambda call: fixtures.response({}, 401))
        with self.fx.fake_http(items=self.capped_items), patch.object(history, 'OfficialTransport', return_value=fake):
            code, result = self.cli('sync', '--catch-up')
        self.assertEqual((code, result['status']), (3, 'reauth_required'))
        self.assertEqual(result['catch_up']['network_calls'], 1)
        self.assertEqual([call['source'] for call in fake.calls], ['resting_hr'])
        self.assertEqual(len(result['catch_up']['pending_ranges']), 3)
        self.assert_activity_not_queried()
        with self.fx.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM health_history_auth_block').fetchone()[0], 1)
        resumed = recovery.run_recovery(self.fx.state, lambda: fixtures.AUTH, now=fixtures.NOW, transport=fake)
        self.assertEqual((resumed['status'], resumed['network_calls']), ('reauth_required', 0))
        self.assertEqual(len(fake.calls), 1)

    def test_daily_401_after_cap_skips_catchup_and_later_sources(self):
        self.seed_outage(('hrv', 'spo2'))
        fake = history_fixtures.FakeTransport(empty=True)
        with self.fx.fake_http(items=self.capped_items,
                               overrides={sources.HRV_URL: fixtures.response({}, 401)}) as (daily, _, _), \
                patch.object(history, 'OfficialTransport', return_value=fake) as factory:
            code, result = self.cli('sync', '--catch-up')
        self.assertEqual((code, result['status']), (3, 'reauth_required'))
        self.assertEqual(result['catch_up'], {'status': 'skipped_due_to_collection_state', 'network_calls': 0})
        self.assertEqual([call[1] for call in daily.calls],
                         [sources.ACTIVITIES_URL, sources.RESTING_HR_URL, sources.HRV_URL])
        self.assertFalse(result['sources']['spo2']['network_attempted'])
        factory.assert_not_called()
        self.assertEqual(fake.calls, [])
        self.assert_activity_not_queried()

    def test_midnight_source_clock_does_not_certify_unrequested_aug11(self):
        cycle_now = datetime(2026, 8, 17, 15, 59, 59, tzinfo=timezone.utc)
        request_now = cycle_now + timedelta(seconds=2)
        with patch.object(h, 'utc_now', return_value=cycle_now), \
                patch.object(sources, 'utc_now', return_value=request_now), self.fx.fake_http() as (daily, _, _):
            self.assertEqual(self.fx.sync()['status'], 'ok')
        query = next(call[2]['reqs'][0] for call in daily.calls if call[1] == sources.HRV_URL)
        self.assertEqual((query['startDay'], query['endDay']), ('20260812', '20260818'))
        view = history.read_coverage(self.fx.state, start='2026-08-11', end='2026-08-18',
                                     source_names=['hrv'], now=request_now)
        self.assertEqual(view['missing_intervals']['hrv'], [
            {'start_day': '2026-08-11', 'end_day': '2026-08-11'},
            {'start_day': '2026-08-18', 'end_day': '2026-08-18'}])
        self.assertEqual(view['queried_days'], 6)
        fake = history_fixtures.FakeTransport(empty=True)
        result = history.run_backfill(self.fx.state, lambda: fixtures.AUTH, start='2026-08-11', end='2026-08-11',
                                      source_names=['hrv'], now=request_now, transport=fake)
        self.assertEqual((result['network_calls'], result['queried_days']), (1, 1))
        self.assertEqual([(call['start_day'], call['end_day']) for call in fake.calls], [('2026-08-11', '2026-08-11')])
        with self.fx.db() as db:
            row = db.execute("SELECT start_day,end_day,collected_at_utc FROM health_history_coverage WHERE source='hrv' AND start_day='2026-08-12'").fetchone()
        self.assertEqual(row, ('2026-08-12', '2026-08-17', request_now.isoformat()))

    def test_legacy_or_mock_results_without_query_metadata_never_certify_coverage(self):
        # Parsed summaries still store normally, but parsing alone is not proof
        # of which dates a request queried. Legacy adapters may lack the fields.
        metric = sources.analyse_metric(fixtures.stats_response('hrv'), 'hrv', start_day='20260812', end_day='20260818')
        old_sleep = SimpleNamespace(status='ok', records=sleep.analyse(fixtures.sleep_response()).records)
        with patch.object(sleep, 'fetch', return_value=old_sleep):
            sleep_result = h._fetch_source('sleep', fixtures.AUTH, 7, 100)
        self.assertEqual(sleep_result.status, 'ok')
        with app.Store(self.fx.state, create=True) as store:
            h.ensure_schema(store.connection)
            for name, result in [('hrv', metric), ('sleep', sleep_result), ('activities', sources.Result('empty'))]:
                stored = h._store_result(store, name, result, fixtures.NOW.isoformat(), 7, None)
                self.assertEqual(stored, len(result.records))
            self.assertEqual(store.connection.execute('SELECT count(*) FROM health_history_coverage').fetchone()[0], 0)

    def test_incomplete_query_metadata_does_not_fall_back_to_cycle_time(self):
        fields = dict(queried_start_day='2026-08-12', queried_end_day='2026-08-18', queried_at_utc=fixtures.NOW.isoformat())
        with app.Store(self.fx.state, create=True) as store:
            h.ensure_schema(store.connection)
            for missing in fields:
                result = sources.Result('empty')
                for key, value in fields.items():
                    if key != missing:
                        setattr(result, key, value)
                h._store_result(store, 'hrv', result, fixtures.NOW.isoformat(), 7, None)
            self.assertEqual(store.connection.execute('SELECT count(*) FROM health_history_coverage').fetchone()[0], 0)

    def test_metric_clock_is_captured_once_even_when_request_crosses_midnight(self):
        before = datetime(2026, 8, 17, 15, 59, 59, tzinfo=timezone.utc)
        after = before + timedelta(seconds=2)
        for metric in sources.METRICS:
            with self.subTest(metric=metric):
                opener = fake_opener({'results': [], 'groupResults': []})
                with patch.object(sources, 'utc_now', side_effect=[before, after, after]) as clock, \
                        patch.object(sources.request, 'build_opener', return_value=opener):
                    result = sources.fetch_metric(fixtures.AUTH, metric, days=7)
                clock.assert_called_once_with()
                self.assertEqual(result.status, 'empty')
                query = json.loads(opener.open.call_args.args[0].data)['reqs'][0]
                self.assertEqual((str(query['startDay']), str(query['endDay'])), ('20260811', '20260817'))
                self.assertEqual((result.queried_start_day, result.queried_end_day, result.queried_at_utc),
                                 ('2026-08-11', '2026-08-17', before.isoformat()))
                with app.Store(self.fx.state, create=True) as store:
                    h.ensure_schema(store.connection)
                    h._store_result(store, metric, result, after.isoformat(), 7, None)
                view = history.read_coverage(self.fx.state, start='2026-08-11', end='2026-08-18',
                                             source_names=[metric], now=after)
                self.assertEqual(view['queried_days'], 6)
                self.assertEqual(view['missing_intervals'][metric], [{'start_day': '2026-08-17', 'end_day': '2026-08-18'}])

    def test_rolling_queries_only_certify_whole_elapsed_local_days(self):
        midnight = datetime(2026, 8, 17, 16, tzinfo=timezone.utc)
        for source, divisor in [('activities', 1000), ('sleep', 1000000000)]:
            for days in (1, 7, 30):
                # One wire unit after midnight catches nanosecond truncation.
                for offset in (0, 1, 3600 * divisor):
                    with self.subTest(source=source, days=days, offset=offset):
                        end = int(midnight.timestamp()) * divisor + offset
                        opener = fake_opener([] if source == 'activities' else {'healthRecords': []})
                        captured = datetime.fromisoformat(sleep.stamp(end, divisor))
                        with patch.object(sources, 'utc_now', return_value=captured) as clock, \
                                patch.object(sleep.time, 'time_ns', return_value=end) as ns_clock, \
                                patch.object(sleep.request, 'build_opener', return_value=opener):
                            result = h._fetch_source(source, fixtures.AUTH, days, 100)
                        (clock if source == 'activities' else ns_clock).assert_called_once_with()
                        self.assertEqual(result.status, 'empty')
                        req = opener.open.call_args.args[0]
                        query = json.loads(req.data) if source == 'activities' else dict(parse.parse_qsl(parse.urlsplit(req.full_url).query))
                        self.assertEqual((int(query['startTime']), int(query['endTime'])), (end - days * 86400 * divisor, end))
                        first = midnight.astimezone(sources.LOCAL_ZONE).date() - timedelta(days=days) + timedelta(days=bool(offset))
                        last = midnight.astimezone(sources.LOCAL_ZONE).date() - timedelta(days=1)
                        expected = (first.isoformat(), last.isoformat()) if first <= last else (None, None)
                        self.assertEqual((result.queried_start_day, result.queried_end_day), expected)
                        self.assertEqual(result.queried_at_utc, captured.isoformat())
                        with app.Store(self.fx.state, create=True) as store:
                            h.ensure_schema(store.connection)
                            with store.connection:
                                store.connection.execute('DELETE FROM health_history_coverage')
                            h._store_result(store, source, result, fixtures.NOW.isoformat(), days, 100 if source == 'activities' else None)
                        start = (midnight.astimezone(sources.LOCAL_ZONE).date() - timedelta(days=days)).isoformat()
                        today = midnight.astimezone(sources.LOCAL_ZONE).date().isoformat()
                        view = history.read_coverage(self.fx.state, start=start, end=today, source_names=[source], now=fixtures.NOW + timedelta(hours=2))
                        self.assertEqual(view['queried_days'], days - bool(offset))
                        if days > 1 or not offset:
                            self.assertIn({'start_day': today, 'end_day': today}, view['missing_intervals'][source])
                        if offset:
                            self.assertEqual(view['missing_intervals'][source][0]['start_day'], start)


if __name__ == '__main__':
    unittest.main()
