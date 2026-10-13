"""Private local browser session; runs only as the health-browser user.

Passwords/codes are never entered here. Pairing uses the official QR and phone
confirmation. Only allowlisted auth headers after an approved 2xx read are
exported to a private file for the root-side session manager; stdout is status
metadata only. No raw health responses or browser stores are exported.
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

HOME = Path('/var/lib/huawei-training-camp-browser')
SITE = 'https://health.cloud.huawei.com/TrainingCamp'
ORIGIN = 'https://health.cloud.huawei.com'
API_ORIGIN = 'https://hihealthbase-drcn.things.dbankcloud.cn'
READS = {
 '/healthrunninggroup/v1/activityRecord:query': 'POST',
 '/healthrunninggroup/v1/healthRecords': 'GET',
 '/healthrunninggroup/v1/sampleSet/periodStatistics:calculate': 'POST',
 '/healthrunninggroup/v1/healthRecords/periodStatistics:calculate': 'POST',
}
HEADERS = {'authorization':'Authorization','x-client-id':'x-client-id','x-version':'x-version'}
SESSION_KEYS = {'accessToken','expireTime','code','site'}


def own_domain(value):
    host = value.lstrip('.') if isinstance(value,str) else ''
    return any(host == domain or host.endswith('.'+domain) for domain in ('huawei.com','dbankcloud.cn'))


def save(name, value):
    path = HOME / name
    temp = HOME / ('.session-' + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(value, out, allow_nan=False)
        out.flush(); os.fsync(out.fileno())
    os.replace(temp, path)


def run(mode, wait):
    assert os.geteuid() == pwd.getpwnam('health-browser').pw_uid
    os.umask(0o077)
    profile = HOME / 'profile'
    profile.mkdir(mode=0o700, exist_ok=True)
    assert not profile.is_symlink()
    session = {}
    path = HOME / 'frontend-session.json'
    if path.exists():
        value = json.loads(path.read_text())
        if isinstance(value, dict):
            session = {k:v for k,v in value.items() if k in SESSION_KEYS and isinstance(v,str)}
    captured = {}
    metadata = dict(status='starting', mode=mode, checked_at_epoch=time.time())
    save('session-status.json', metadata)
    with sync_playwright() as pw:
        context = pw.chromium.launch_persistent_context(str(profile), headless=True,
            chromium_sandbox=True, locale='zh-CN', timezone_id='Asia/Shanghai',
            viewport={'width':1280,'height':900}, service_workers='block',
            args=['--disable-dev-shm-usage'])
        cookie_path = HOME / 'auth-cookies.json'
        if cookie_path.exists():
            saved = json.loads(cookie_path.read_text())
            if isinstance(saved, list):
                allowed = [x for x in saved if isinstance(x,dict) and own_domain(x.get('domain'))]
                context.add_cookies(allowed)
        # Only this site's small auth/session namespace is restored, not stores
        # from other sites. Its contents never enter stdout or model context.
        restore = '(function(){if(location.origin===' + json.dumps(ORIGIN) + '){const s=' + json.dumps(session) + ';for(const [k,v] of Object.entries(s))sessionStorage.setItem(k,v)}})();'
        context.add_init_script(restore)
        page = context.pages[0] if context.pages else context.new_page()
        cdp = context.new_cdp_session(page)
        cdp.send('Network.enable')
        cdp.send('Network.setCacheDisabled', {'cacheDisabled':True})

        def observe(response):
            try:
                u = urlsplit(response.url)
                if u.scheme+'://'+u.netloc != API_ORIGIN or response.request.method != READS.get(u.path) or not 200 <= response.status < 300:
                    return
                values = response.request.all_headers()
                selected = {HEADERS[k]:v for k,v in values.items() if k in HEADERS}
                if not selected.get('Authorization') or not selected.get('x-client-id') or any('\r' in v or '\n' in v for v in selected.values()):
                    return
                captured.update(selected)
            except Exception:
                pass
        context.on('response', observe)
        try:
            page.goto(SITE, wait_until='domcontentloaded', timeout=40000)
            start = time.monotonic()
            qr_sent_at = 0
            clicked_at = 0
            while time.monotonic()-start < wait:
                page.wait_for_timeout(300)
                if captured:
                    stored = page.evaluate('Object.fromEntries(Object.entries(sessionStorage).filter(([k])=>["accessToken","expireTime","code","site"].includes(k)))')
                    save('frontend-session.json', stored)
                    own_cookies = [x for x in context.cookies() if own_domain(x.get('domain'))]
                    save('auth-cookies.json', own_cookies)
                    expiry = None
                    try: expiry = int(stored.get('expireTime',''))
                    except (ValueError,TypeError): pass
                    save('session-headers.json', {'headers':captured,'expiry_ms':expiry,
                        'captured_at_epoch':time.time(),'verified_browser_read':True})
                    metadata.update(status='authorized', expiry_ms=expiry,
                        cookie_count=len(context.cookies()), checked_at_epoch=time.time())
                    save('session-status.json', metadata)
                    return metadata
                url = urlsplit(page.url)
                if url.scheme+'://'+url.netloc == ORIGIN:
                    if time.monotonic()-clicked_at > 4:
                        clicked = page.evaluate('()=>{const b=Array.from(document.querySelectorAll("button,a")).find(x=>/^(Log in|登录|登入)$/i.test(x.innerText.trim()));if(b){b.click();return true}return false}')
                        if clicked:clicked_at=time.monotonic()
                qr = page.locator('img[alt="Scan me!"]')
                if qr.count() and qr.first.is_visible():
                    metadata.update(status='reauth_required', qr_available=True,
                                    origin=url.scheme+'://'+url.netloc, checked_at_epoch=time.time())
                    if mode=='refresh':
                        save('session-status.json', metadata)
                        return metadata
                    expired = page.get_by_text('二维码已失效', exact=False)
                    if expired.count() and expired.first.is_visible():
                        qr.first.click(timeout=2000)
                    if not qr_sent_at or time.monotonic()-qr_sent_at > 65:
                        data = qr.first.evaluate('img=>{if(!img.complete||!img.naturalWidth)return null;const c=document.createElement("canvas"),q=24,s=4;c.width=(img.naturalWidth+2*q)*s;c.height=(img.naturalHeight+2*q)*s;const x=c.getContext("2d");x.fillStyle="#fff";x.fillRect(0,0,c.width,c.height);x.imageSmoothingEnabled=false;x.drawImage(img,q*s,q*s,img.naturalWidth*s,img.naturalHeight*s);return c.toDataURL("image/png")}')
                        if data and data.startswith('data:image/png;base64,'):
                            import base64
                            raw = base64.b64decode(data.split(',',1)[1])
                            target = HOME / 'login-qr.png'
                            temp = HOME / ('.qr-'+uuid.uuid4().hex+'.png')
                            fd = os.open(temp, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                            with os.fdopen(fd,'wb') as out:out.write(raw)
                            os.replace(temp,target)
                            qr_sent_at=time.monotonic()
                            metadata['qr_generated_at_epoch']=time.time()
                            save('session-status.json',metadata)
                else:
                    metadata.update(status='waiting_for_official_session', origin=url.scheme+'://'+url.netloc, checked_at_epoch=time.time())
                    save('session-status.json',metadata)
            metadata.update(status='reauth_required' if metadata.get('qr_available') else 'browser_timeout', checked_at_epoch=time.time())
            save('session-status.json',metadata)
            return metadata
        finally:
            context.close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('mode',choices=['refresh','pair'])
    parser.add_argument('--wait',type=int,default=45)
    args=parser.parse_args()
    if not 5 <= args.wait <= 300:raise SystemExit(2)
    try:
        result=run(args.mode,args.wait)
    except Exception as exc:
        detail=str(exc).lower()
        result={'status':'browser_error','error_type':type(exc).__name__,'checked_at_epoch':time.time(),
            'sandbox_related':any(x in detail for x in ['sandbox','namespace','operation not permitted']),
            'permission_related':'permission denied' in detail,
            'readonly_related':'read-only' in detail,
            'profile_lock_related':any(x in detail for x in ['singleton','profile in use','processsingleton'])}
        try:save('session-status.json',result)
        except Exception:pass
    print(json.dumps(result,allow_nan=False,sort_keys=True))
    return 0 if result['status']=='authorized' else 3 if result['status']=='reauth_required' else 1

if __name__=='__main__':raise SystemExit(main())
