"""Bounded, resumable outage catch-up using the existing history engine.

A missing measurement is not an outage. Gaps are inferred only from collection
success timestamps and then reduced by successfully queried date coverage.
Pending ranges survive a successful daily sync so a small call budget cannot
silently abandon the rest of a longer outage. No messages or new scheduler.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import app
import health_sources as sources
import health_history as history


def _now(now=None):
    now = now or datetime.now(timezone.utc)
    if not isinstance(now,datetime) or now.tzinfo is None:
        raise app.InvalidArguments()
    return now


def _exists(db,name):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone() is not None


def _schema(db):
    db.execute('''CREATE TABLE IF NOT EXISTS health_recovery_queue (
        source TEXT NOT NULL, start_day TEXT NOT NULL, end_day TEXT NOT NULL,
        status TEXT NOT NULL, checked_at_utc TEXT NOT NULL,
        PRIMARY KEY(source,start_day,end_day))''')


def _union(intervals):
    out=[]
    for low,high in sorted(intervals):
        if out and low <= out[-1][1]+timedelta(days=1):
            out[-1]=(out[-1][0],max(high,out[-1][1]))
        else:out.append((low,high))
    return out


def plan_recovery(state_dir, *, now=None, activity_days=30, sleep_days=7, metric_days=7):
    now=_now(now)
    for days in (activity_days,sleep_days,metric_days):sources.bounded_int(days)
    today=now.astimezone(sources.LOCAL_ZONE).date()
    earliest=today-timedelta(days=364)
    candidates={name:[] for name in history.SOURCE_NAMES}
    expired=[]
    try:
        with app.Store(state_dir) as store:
            db=store.connection
            if _exists(db,'health_recovery_queue'):
                for name,start,end in db.execute("SELECT source,start_day,end_day FROM health_recovery_queue WHERE status!='completed'"):
                    if name in candidates:candidates[name].append((date.fromisoformat(start),date.fromisoformat(end)))
            if _exists(db,'health_source_state'):
                for name,last_success in db.execute('SELECT name,last_success_time_utc FROM health_source_state'):
                    if name not in candidates or not last_success:continue
                    stamp=app._utc_timestamp(last_success)
                    if stamp is None:continue
                    last=datetime.fromisoformat(stamp).astimezone(sources.LOCAL_ZONE).date()
                    days=activity_days if name=='activities' else sleep_days if name=='sleep' else metric_days
                    # Current collection already covers the newer window. Use
                    # its first date as the end here as a safe boundary overlap.
                    high=today-timedelta(days=days-1)
                    if last < high:
                        candidates[name].append((last,high))
    except app.NotInitialized:
        return {'status':'not_initialized','pending_ranges':[],'outside_supported_range':[],
                'cold_start_requires_explicit_backfill':True,'network_calls':0}
    pending=[]
    for name,spans in candidates.items():
        for low,high in _union(spans):
            if low<earliest:
                expired.append({'source':name,'start_day':low.isoformat(),'end_day':min(high,earliest-timedelta(days=1)).isoformat()})
            low=max(low,earliest);high=min(high,today-timedelta(days=1))
            if low>high:continue
            coverage=history.read_coverage(state_dir,start=low.isoformat(),end=high.isoformat(),source_names=[name],now=now)
            # The coverage engine distinguishes queried-empty dates from
            # pending dates; do not derive requests from physiological samples.
            for gap in coverage.get('missing_intervals',{}).get(name,[]):
                pending.append({'source':name,'start_day':gap['start_day'],'end_day':gap['end_day']})
    return {'status':'pending' if pending else 'outside_supported_range' if expired else 'up_to_date',
            'pending_ranges':pending,'outside_supported_range':expired,
            'cold_start_requires_explicit_backfill':False,'network_calls':0}


def enqueue(state_dir, plan, *, now=None):
    now=_now(now).isoformat()
    if not plan.get('pending_ranges'):return
    with app.Store(state_dir,create=True) as store:
        with store.connection as db:
            _schema(db)
            for gap in plan['pending_ranges']:
                db.execute('''INSERT INTO health_recovery_queue VALUES (?,?,?,'pending',?)
                    ON CONFLICT(source,start_day,end_day) DO UPDATE SET
                    status='pending',checked_at_utc=excluded.checked_at_utc''',
                    (gap['source'],gap['start_day'],gap['end_day'],now))


def run_recovery(state_dir, headers_provider, *, plan=None, max_calls=2,
                 recover_headers=None, now=None, transport=None):
    now=_now(now)
    if type(max_calls) is not int or not 1<=max_calls<=24:
        raise app.InvalidArguments()
    plan=plan if plan is not None else plan_recovery(state_dir,now=now)
    enqueue(state_dir,plan,now=now)
    used=0;outcomes=[];blocked=False
    for gap in plan['pending_ranges']:
        if used>=max_calls or blocked:break
        result=history.run_backfill(state_dir,headers_provider,start=gap['start_day'],end=gap['end_day'],
            source_names=[gap['source']],max_calls=max_calls-used,resume=True,
            recover_headers=recover_headers,now=now,transport=transport)
        used+=result.get('network_calls',0)
        outcomes.append({'source':gap['source'],'start_day':gap['start_day'],'end_day':gap['end_day'],
                         'status':result.get('status'),'network_calls':result.get('network_calls',0)})
        blocked=result.get('status') in ('reauth_required','auth_check_error','already_running','storage_error')
        done=result.get('pending_windows')==0 and result.get('coverage_limited_windows')==0
        with app.Store(state_dir,create=True) as store:
            with store.connection as db:
                _schema(db)
                db.execute('UPDATE health_recovery_queue SET status=?,checked_at_utc=? WHERE source=? AND start_day=? AND end_day=?',
                    ('completed' if done else result.get('status','pending'),now.isoformat(),gap['source'],gap['start_day'],gap['end_day']))
    remaining=plan_recovery(state_dir,now=now)
    status=next((x['status'] for x in outcomes if x['status'] in ('reauth_required','auth_check_error','storage_error','collection_error','already_running')),remaining['status'])
    return {**remaining,'status':status,'network_calls':used,'call_budget':max_calls,'attempts':outcomes}
