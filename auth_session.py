"""Root-side safe coordinator for the dedicated local official browser.

No passwords, cookies or auth-header values enter logs/model output. The
unprivileged browser keeps its own private profile; only a successful approved
read's minimal headers are copied into root-owned auth.json after a genuine VPS
API check. Pairing photos are sent only to an explicitly supplied destination.
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import shlex
import stat
import subprocess
import time
import urllib.parse
import urllib.request
import uuid
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import app
import collector
import ssl
from urllib import error

PROJECT = Path(__file__).resolve().parent
BROWSER_HOME = Path('/var/lib/huawei-training-camp-browser')
BROWSER_PYTHON = PROJECT / '.browser-venv/bin/python'
VALID_HEADERS = {'Authorization', 'x-client-id', 'x-version'}


def private_json(path, uid):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077 or info.st_size > 32768:
            raise ValueError('unsafe_private_file')
        with os.fdopen(fd, 'r') as stream:
            fd = -1
            data = stream.read(32769)
            if len(data) > 32768:raise ValueError('oversized_private_file')
            return json.loads(data)
    finally:
        if fd >= 0:os.close(fd)


def atomic_json(path, data):
    if path.exists() or path.is_symlink():
        private_json(path, os.geteuid())
    temp = path.with_name('.auth-session-' + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(data,stream,sort_keys=True,allow_nan=False)
        stream.flush();os.fsync(stream.fileno())
    os.replace(temp,path)


def broker_args(mode, wait):
    user = pwd.getpwnam('health-browser')
    env = {'HOME':user.pw_dir, 'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8',
           'TMPDIR':str(BROWSER_HOME/'runtime-tmp'),
           'PLAYWRIGHT_BROWSERS_PATH':str(PROJECT/'.browser-runtime')}
    return ['runuser','-u','health-browser','--','env','-i',
            *[k+'='+v for k,v in env.items()],str(BROWSER_PYTHON),
            str(PROJECT/'browser_session.py'),mode,'--wait',str(wait)]


def accept_export(state_dir, since):
    user = pwd.getpwnam('health-browser')
    data = private_json(BROWSER_HOME/'session-headers.json',user.pw_uid)
    if not isinstance(data,dict) or data.get('verified_browser_read') is not True or not isinstance(data.get('captured_at_epoch'),(int,float)) or data['captured_at_epoch'] < since-5:
        raise ValueError('stale_browser_export')
    headers = data.get('headers')
    if not isinstance(headers,dict) or set(headers)-VALID_HEADERS or not headers.get('Authorization') or not headers.get('x-client-id') or any(not isinstance(v,str) or '\r' in v or '\n' in v for v in headers.values()):
        raise ValueError('invalid_browser_export')
    now=datetime.now(timezone.utc)
    result=collector.latest(collector.OfficialTransport(network_authorized=True),
        str(int((now-timedelta(days=30)).timestamp()*1000)),str(int(now.timestamp()*1000)),
        lambda:headers,dry_run=False)
    if result.status not in {'ok','partial','empty'}:
        return {'status':result.status,'vps_auth_verified':False}
    state_dir=Path(state_dir)
    with app.Store(state_dir,create=True):pass
    atomic_json(state_dir/'auth.json',headers)
    expiry=data.get('expiry_ms')
    if type(expiry) is not int:expiry=None
    metadata={'status':'ok','method':'private_local_official_browser',
        'vps_auth_verified':True,'verified_at_epoch':time.time(),'expiry_ms':expiry,
        'auth_mtime_ns':(state_dir/'auth.json').stat().st_mtime_ns}
    atomic_json(state_dir/'auth-session-status.json',metadata)
    return {k:v for k,v in metadata.items() if k!='auth_mtime_ns'}


def official_revalidate(state_dir, headers):
    """Use the authInfo GET implemented by the official web client.

    No guessed grant, refresh token, password or cookie is submitted. A returned
    access token is accepted only after a real VPS data request verifies it.
    """
    try:
        h=dict(headers);h['x-ts']=str(int(time.time()*1000))
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),collector.NoRedirect())
        req=urllib.request.Request('https://hihealthbase-drcn.things.dbankcloud.cn/healthrunninggroup/v1/authInfo',headers=h,method='GET')
        with opener.open(req,timeout=10) as response:
            body=response.read(32769)
        if len(body)>32768:return {'status':'invalid_response','vps_auth_verified':False}
        raw=json.loads(body)
        info=raw.get('tokenInfo') if isinstance(raw,dict) else None
        if not isinstance(info,dict) or not isinstance(info.get('accessToken'),str) or not info['accessToken'] or '\r' in info['accessToken'] or '\n' in info['accessToken']:
            return {'status':'invalid_response','vps_auth_verified':False}
        candidate=dict(headers);candidate['Authorization']='Bearer '+info['accessToken']
        now=datetime.now(timezone.utc)
        check=collector.latest(collector.OfficialTransport(network_authorized=True),
            str(int((now-timedelta(days=30)).timestamp()*1000)),str(int(now.timestamp()*1000)),
            lambda:candidate,dry_run=False)
        if check.status not in {'ok','partial','empty'}:
            return {'status':check.status,'vps_auth_verified':False}
        expiry=info.get('expireTime')
        if type(expiry) is not int:expiry=None
        state_dir=Path(state_dir)
        atomic_json(state_dir/'auth.json',candidate)
        metadata={'status':'ok','method':'official_authInfo','vps_auth_verified':True,
            'verified_at_epoch':time.time(),'expiry_ms':expiry,
            'auth_mtime_ns':(state_dir/'auth.json').stat().st_mtime_ns}
        atomic_json(state_dir/'auth-session-status.json',metadata)
        return {'status':'ok','method':'official_authInfo','vps_auth_verified':True,
            'renewed':candidate['Authorization']!=headers.get('Authorization'),
            'revalidated':True,'expiry_ms':expiry}
    except error.HTTPError as exc:
        code=exc.code;exc.close()
        return {'status':'reauth_required' if code in (401,403) else 'redirect_rejected' if code in (301,302,303,307,308) else 'auth_http_error','vps_auth_verified':False}
    except Exception as exc:
        return {'status':'auth_revalidation_error','error_type':type(exc).__name__,'vps_auth_verified':False}


def ensure_auth(state_dir=app.DEFAULT_STATE_DIR, *, force=False):
    auth=None
    state_dir=Path(state_dir)
    if state_dir != app.DEFAULT_STATE_DIR:
        return {'status':'auth_not_configured','vps_auth_verified':False}
    try:
        auth=app.load_auth(state_dir/'auth.json')
        cached=private_json(state_dir/'auth-session-status.json',os.geteuid())
        expiry=cached.get('expiry_ms')
        if not force and auth and cached.get('vps_auth_verified') is True and cached.get('auth_mtime_ns')==(state_dir/'auth.json').stat().st_mtime_ns:
            if type(expiry) is int and expiry > int(time.time()*1000)+120000:
                return {'status':'ok','vps_auth_verified':True,'renewed':False,'expiry_ms':expiry}
    except (OSError,ValueError,TypeError):pass
    if auth:
        refreshed = official_revalidate(state_dir, auth)
        if refreshed.get('status')=='ok':
            return refreshed
    start=time.time()
    try:
        r=subprocess.run(broker_args('refresh',45),text=True,capture_output=True,timeout=60)
        if not r.stdout.strip():
            text=r.stderr.lower()
            return {'status':'browser_process_error','vps_auth_verified':False,
                'process_exit':r.returncode,'pam_related':'pam' in text or 'session' in text,
                'permission_related':'permission denied' in text,
                'readonly_related':'read-only' in text,
                'python_error_names':re.findall(r'^([A-Z][A-Za-z]*(?:Error|Exception)):',r.stderr,re.M),
                'missing_modules':re.findall(r"No module named '([a-zA-Z_][a-zA-Z0-9_.]*)'",r.stderr),
                'trace_files':[Path(x).name for x in re.findall(r'File "([^"]+)"',r.stderr)],
                'launcher_errors':[x[:200] for x in r.stderr.splitlines() if x.startswith(('runuser:','env:'))],
                'stderr_length':len(r.stderr)}
        message=json.loads(r.stdout)
        if r.returncode==0 and message.get('status')=='authorized':
            previous = auth.get('Authorization') if auth else None
            result=accept_export(state_dir,start)
            after=app.load_auth(state_dir/'auth.json') if result['status']=='ok' else None
            result['renewed']=bool(after and after.get('Authorization')!=previous)
            result['session_restored']=result['status']=='ok'
            return result
        return {'status':message.get('status','browser_error'),'vps_auth_verified':False,
                'requires_user':message.get('status')=='reauth_required'}
    except Exception as exc:
        return {'status':'browser_error','error_type':type(exc).__name__,'vps_auth_verified':False}


class Telegram:
    def __init__(self,chat_id,topic_id):
        if not str(chat_id).lstrip('-').isdigit() or not str(topic_id).isdigit():
            raise ValueError('invalid_destination')
        token=os.environ.get('HUAWEI_TELEGRAM_BOT_TOKEN')
        home=os.environ.get('HERMES_HOME')
        if not token and home:
            for line in (Path(home)/'.env').read_text().splitlines():
                key,sep,value=line.strip().partition('=')
                if sep and key=='TELEGRAM_BOT_TOKEN':
                    parts=shlex.split(value,comments=True);token=parts[0] if parts else None;break
        if not token:raise ValueError('transport_unavailable')
        self.token=token;self.chat=str(chat_id);self.topic=str(topic_id)
        actual=self.api('getChat',{'chat_id':self.chat})
        if str(actual['id']) != self.chat or actual['type']!='private':
            raise ValueError('destination_mismatch')

    def api(self,method,fields=None,*,data=None,content_type=None):
        if data is None:
            data=urllib.parse.urlencode(fields or {}).encode();content_type='application/x-www-form-urlencoded'
        req=urllib.request.Request('https://api.telegram.org/bot'+self.token+'/'+method,
            data=data,headers={'Content-Type':content_type},method='POST')
        with urllib.request.urlopen(req,timeout=20) as r:obj=json.load(r)
        if not obj.get('ok'):raise ValueError('telegram_rejected')
        return obj['result']

    def photo(self,image):
        boundary='iris-'+uuid.uuid4().hex
        fields={'chat_id':self.chat,'message_thread_id':self.topic,
            'caption':'VPS 私有持久会话的华为官方新码。请现在扫码并确认；这次会保存会话用于后续恢复，不是只留一个临时访问凭据。',
            'disable_notification':'false','protect_content':'false'}
        parts=[('--'+boundary+'\r\nContent-Disposition: form-data; name="'+k+'"\r\n\r\n'+v+'\r\n').encode() for k,v in fields.items()]
        parts.extend([('--'+boundary+'\r\nContent-Disposition: form-data; name="photo"; filename="Huawei-private-session.png"\r\nContent-Type: image/png\r\n\r\n').encode(),image,b'\r\n',('--'+boundary+'--\r\n').encode()])
        result=self.api('sendPhoto',data=b''.join(parts),content_type='multipart/form-data; boundary='+boundary)
        if str(result['chat']['id'])!=self.chat or str(result.get('message_thread_id'))!=self.topic:
            raise ValueError('delivery_destination_mismatch')
        photo=max(result.get('photo',[]),key=lambda x:x.get('width',0)*x.get('height',0))
        stored=self.api('getFile',{'file_id':photo['file_id']})
        return {'message_id':result['message_id'],'telegram_file_verified':stored.get('file_size',0)>0,'sent_at_epoch':time.time()}


def pair(chat_id=None,topic_id=None,wait=240):
    if (chat_id is None) != (topic_id is None):raise ValueError('incomplete_destination')
    # No messaging service is required: without an explicit destination, only
    # the owner-private QR file path is returned for local/SFTP viewing.
    transport=Telegram(chat_id,topic_id) if chat_id is not None else None
    start=time.time();process=subprocess.Popen(broker_args('pair',wait),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    last_qr=0;receipts=[]
    try:
        while process.poll() is None:
            qr=BROWSER_HOME/'login-qr.png'
            if qr.exists() and qr.stat().st_mtime >= start and qr.stat().st_mtime_ns != last_qr:
                info=qr.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=pwd.getpwnam('health-browser').pw_uid or info.st_mode & 0o077 or info.st_size>1000000:
                    raise ValueError('unsafe_qr_file')
                image=qr.read_bytes()
                if not image.startswith(b'\x89PNG\r\n\x1a\n'):raise ValueError('invalid_qr_image')
                last_qr=info.st_mtime_ns
                if transport is not None:
                    receipt=transport.photo(image);receipts.append(receipt)
                    atomic_json(app.DEFAULT_STATE_DIR/'qr-session-delivery.json',{'receipts':receipts})
                    print(json.dumps({'pairing_qr_sent':True,**receipt}),flush=True)
                else:
                    print(json.dumps({'status':'awaiting_official_qr_confirmation','qr_file':str(qr),'messaging_used':False}),flush=True)
            time.sleep(.15)
        stdout,_=process.communicate(timeout=5)
        message=json.loads(stdout)
        if process.returncode==0 and message.get('status')=='authorized':return accept_export(app.DEFAULT_STATE_DIR,start)
        return {'status':message.get('status','browser_error'),'requires_user':True}
    except Exception as exc:
        if process.poll() is None:process.terminate()
        return {'status':'pairing_error','error_type':type(exc).__name__,'requires_user':True}


def main():
    parser=app.SafeArgumentParser()
    parser.add_argument('command',choices=['refresh','pair'])
    parser.add_argument('--chat-id');parser.add_argument('--topic-id')
    parser.add_argument('--wait',type=int,default=240)
    parser.add_argument('--force',action='store_true')
    try:
        args=parser.parse_args()
        if args.command=='pair':
            if (args.chat_id is None)!=(args.topic_id is None) or not 5<=args.wait<=300:raise app.InvalidArguments()
            result=pair(args.chat_id,args.topic_id,args.wait)
        else:result=ensure_auth(force=args.force)
    except Exception as exc:result={'status':'auth_error','error_type':type(exc).__name__}
    print(json.dumps(result,sort_keys=True,allow_nan=False))
    return 0 if result.get('status')=='ok' else 3 if result.get('requires_user') or result.get('status')=='reauth_required' else 1

if __name__=='__main__':raise SystemExit(main())
