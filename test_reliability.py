"""Synthetic regression tests. Production paths and real network are guarded."""
import unittest
from unittest.mock import patch

import app
import health as h
import health_sources as sources
import health_storage as storage
import auth_session
import test_health as fixtures


class ReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.fx=fixtures.HealthTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.addCleanup(self.fx.tearDown)
        self.fx.write_auth()

    def seed(self):
        with self.fx.fake_http():
            self.fx.sync()

    def test_omitted_metric_retains_value_with_explicit_provenance(self):
        self.seed()
        with self.fx.db() as db:
            before=db.execute("SELECT avg FROM metric_stats WHERE metric='hrv'").fetchone()[0]
        incoming=fixtures.stats_response('hrv',entries=[{'fieldName':'avgHrv','startDay':20260818,'statistics':None}],overall=False)
        with self.fx.fake_http(overrides={sources.HRV_URL:incoming}):
            result=self.fx.sync()
        with self.fx.db() as db:
            self.assertEqual(db.execute("SELECT avg FROM metric_stats WHERE metric='hrv'").fetchone()[0],before)
            flags=storage.quality(db,'hrv',{'day':'2026-08-18'})
        self.assertIn('avg',flags['retained_fields'])
        self.assertIsNotNone(flags['fields']['avg']['last_valid_at_utc'])
        self.assertEqual(result['sources']['hrv']['data_freshness'],'retained')
        self.assertGreater(result['sources']['hrv']['retained_fields'],0)
        self.seed()
        with self.fx.db() as db:
            self.assertNotIn('avg',storage.quality(db,'hrv',{'day':'2026-08-18'})['retained_fields'])

    def test_legacy_value_retained_without_inventing_observation_time(self):
        self.seed()
        with self.fx.db() as db:
            db.execute('DELETE FROM health_record_quality')
            record=h._summaries(db,'hrv',1)[0]
            record['avg']=None
            storage.store_records(db,'hrv',[record],fixtures.NOW.isoformat())
            quality=storage.quality(db,'hrv',record)
        self.assertTrue(quality['fields']['avg']['retained'])
        self.assertIsNone(quality['fields']['avg']['last_valid_at_utc'])

    def test_sleep_and_activity_missing_fields_do_not_delete(self):
        self.seed()
        for source,field in [('sleep','sleep_score'),('activities','distance_m')]:
            with self.fx.db() as db:
                record=h._summaries(db,source,1)[0]
                original=record[field]
                self.assertIsNotNone(original)
                record[field]=None
                storage.store_records(db,source,[record],fixtures.NOW.isoformat())
                saved=h._summaries(db,source,1)[0]
                self.assertEqual(saved[field],original)
                self.assertIn(field,storage.quality(db,source,saved)['retained_fields'])

    def test_all_null_first_measurement_not_recent(self):
        incoming=fixtures.stats_response('hrv',entries=[{'fieldName':'avgHrv','startDay':20260818,'statistics':None}],overall=False)
        with self.fx.fake_http(overrides={sources.HRV_URL:incoming}):
            result=self.fx.sync()
        self.assertEqual(result['sources']['hrv']['data_freshness'],'unknown')

    def test_browser_timeout_not_reauthorization(self):
        app.init_state(self.fx.state)
        self.fx.write_auth(path=self.fx.state/'auth.json')
        temporary={'status':'browser_error','error_type':'TimeoutExpired','vps_auth_verified':False}
        with patch.object(app,'DEFAULT_STATE_DIR',self.fx.state),patch.object(h.auth_session,'ensure_auth',return_value=temporary),self.fx.fake_http() as (transport,fetch,factory):
            result=h.run_once(self.fx.state)
        self.assertEqual(result['status'],'auth_check_error')
        self.assertFalse(result['authentication_required'])
        self.assertFalse(result['authentication']['requires_user'])
        self.assertTrue(result['authentication']['temporary_check_failure'])
        self.assertEqual(transport.calls,[])
        fetch.assert_not_called()
        saved=h.read_view(self.fx.state)
        self.assertEqual(saved['status'],'auth_check_error')

    def test_true_expiration_still_requires_reauthorization(self):
        app.init_state(self.fx.state)
        self.fx.write_auth(path=self.fx.state/'auth.json')
        with patch.object(app,'DEFAULT_STATE_DIR',self.fx.state),patch.object(h.auth_session,'ensure_auth',return_value={'status':'reauth_required','requires_user':True,'vps_auth_verified':False}),self.fx.fake_http() as (transport,fetch,factory):
            result=h.run_once(self.fx.state)
        self.assertEqual(result['status'],'reauth_required')
        self.assertTrue(result['authentication_required'])
        self.assertTrue(result['authentication']['requires_user'])
        self.assertEqual(transport.calls,[])

    def test_401_then_browser_timeout_preserves_rejection_but_not_user_prompt(self):
        app.init_state(self.fx.state)
        self.fx.write_auth(path=self.fx.state/'auth.json')
        controls=[{'status':'ok','vps_auth_verified':True},{'status':'browser_error','vps_auth_verified':False}]
        with patch.object(app,'DEFAULT_STATE_DIR',self.fx.state),patch.object(h.auth_session,'ensure_auth',side_effect=controls),self.fx.fake_http(overrides={sources.ACTIVITIES_URL:fixtures.response({},401)}) as (transport,fetch,factory):
            result=h.run_once(self.fx.state)
        self.assertEqual(result['status'],'auth_check_error')
        self.assertTrue(result['authentication_required'])
        self.assertFalse(result['authentication']['requires_user'])
        self.assertEqual(len(transport.calls),1)
        with self.fx.db() as db:
            self.assertEqual(h._sync_state(db)['blocked_auth_fingerprint'],h._fingerprint(fixtures.AUTH))

    def test_timeout_does_not_unblock_a_genuinely_rejected_token(self):
        self.seed()
        with self.fx.fake_http(overrides={sources.ACTIVITIES_URL:fixtures.response({},401)}):
            rejected=self.fx.sync()
        self.assertEqual(rejected['status'],'reauth_required')
        with patch.object(app,'DEFAULT_STATE_DIR',self.fx.state),patch.object(h.auth_session,'ensure_auth',return_value={'status':'browser_error','vps_auth_verified':False}),self.fx.fake_http() as (transport,fetch,factory):
            # same synthetic credential contents, canonical filename
            self.fx.write_auth(path=self.fx.state/'auth.json')
            result=h.run_once(self.fx.state)
        self.assertEqual(result['status'],'auth_check_error')
        self.assertTrue(result['authentication_required'])
        self.assertFalse(result['authentication']['requires_user'])
        self.assertEqual(transport.calls,[])


if __name__=='__main__':
    unittest.main()
