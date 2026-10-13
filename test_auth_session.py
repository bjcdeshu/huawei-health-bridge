"""Mocked browser/auth coordinator checks. No login, credentials or network."""
import contextlib
import io
import json
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.error import HTTPError

import auth_session as auth
import app


class AuthSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        for target in (patch.object(socket,'create_connection',side_effect=AssertionError('network_forbidden')),
                       patch.object(auth.subprocess,'run',side_effect=AssertionError('real_browser_forbidden')),
                       patch.object(auth.subprocess,'Popen',side_effect=AssertionError('real_browser_forbidden')),
                       patch.object(app,'load_auth',side_effect=AssertionError('credential_read_forbidden')),
                       patch.object(auth,'private_json',side_effect=AssertionError('private_state_forbidden'))):
            target.start();self.addCleanup(target.stop)

    def test_local_pair_needs_no_messaging_credentials(self):
        image=self.root/'login-qr.png'
        image.write_bytes(b'\x89PNG\r\n\x1a\nSYNTHETIC_QR_ONLY')
        image.chmod(0o600)
        os.utime(image,(time.time()+10,time.time()+10))
        process=Mock(returncode=0)
        process.poll.side_effect=[None,0]
        process.communicate.return_value=(json.dumps({'status':'authorized'}),'')
        with patch.object(auth,'BROWSER_HOME',self.root),patch.object(auth,'broker_args',return_value=['synthetic-browser']),patch.object(auth.subprocess,'Popen',return_value=process),patch.object(auth.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=os.geteuid())),patch.object(auth.time,'sleep'),patch.object(auth,'accept_export',return_value={'status':'ok','vps_auth_verified':True}) as accept,patch.object(auth,'Telegram',side_effect=AssertionError('messaging_not_requested')) as telegram,contextlib.redirect_stdout(io.StringIO()) as output:
            result=auth.pair(wait=5)
        self.assertEqual(result['status'],'ok')
        telegram.assert_not_called()
        accept.assert_called_once()
        notification=json.loads(output.getvalue())
        self.assertEqual(notification['qr_file'],str(image))
        self.assertFalse(notification['messaging_used'])

    def test_partial_messaging_destination_rejected_before_browser(self):
        with self.assertRaises(ValueError):auth.pair('1',None,5)
        with self.assertRaises(ValueError):auth.pair(None,'2',5)

    def test_malformed_authinfo_is_not_login_expiration(self):
        response=Mock()
        response.read.return_value=b'{"tokenInfo":{}}'
        response.__enter__=Mock(return_value=response)
        response.__exit__=Mock(return_value=False)
        opener=Mock();opener.open.return_value=response
        with patch.object(auth.urllib.request,'build_opener',return_value=opener):
            result=auth.official_revalidate(self.root,{'Authorization':'SYNTHETIC_ONLY','x-client-id':'SYNTHETIC_CLIENT'})
        self.assertEqual(result['status'],'invalid_response')
        self.assertFalse(result['vps_auth_verified'])

    def test_http_failure_classification(self):
        for code,expected in [(401,'reauth_required'),(403,'reauth_required'),(500,'auth_http_error'),(302,'redirect_rejected')]:
            opener=Mock();opener.open.side_effect=HTTPError('https://example.invalid',code,'synthetic',{},None)
            with patch.object(auth.urllib.request,'build_opener',return_value=opener):
                result=auth.official_revalidate(self.root,{'Authorization':'SYNTHETIC_ONLY','x-client-id':'SYNTHETIC_CLIENT'})
            self.assertEqual(result['status'],expected)


if __name__=='__main__':unittest.main()
