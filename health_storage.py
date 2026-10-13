"""Loss-aware normalized storage; never turn an omitted field into a deletion.

The caller validates/allowlists records and owns the transaction. Provenance is
field-level: a retained value is visible but is not a newly observed value.
Legacy records have unknown observation timestamps until actually fetched.
"""
from __future__ import annotations

import app
import health_sources as sources
import health_points as points
import sleep_collector as sleep


def ensure_schema(db):
    db.execute("""CREATE TABLE IF NOT EXISTS health_record_quality (
        source TEXT NOT NULL, record_key TEXT NOT NULL, field TEXT NOT NULL,
        last_valid_at_utc TEXT, last_seen_at_utc TEXT NOT NULL,
        retained INTEGER NOT NULL CHECK(retained IN (0,1)),
        PRIMARY KEY(source,record_key,field)
    )""")


def record_key(source, record):
    if source in sources.METRICS:
        return record['day']
    if source == 'sleep':
        return record['start_time_utc'] + '|' + str(record['sleep_type'])
    if source == 'activities':
        return record['start_time_utc'] + '|' + str(record['activity_type'])
    if source == points.METRIC:
        return str(record['measured_at_ns'])
    raise app.InvalidArguments()


def _layout(source):
    if source in sources.METRICS:
        return 'metric_stats', sources.METRIC_KEYS, ('metric','day','time_zone'), ('avg','min','max','sum','count')
    if source == 'sleep':
        return 'sleep_records', sleep.KEYS, ('start_time_utc','sleep_type'), tuple(k for k in sleep.KEYS if k not in ('start_time_utc','sleep_type'))
    if source == 'activities':
        return 'activities', app.SUMMARY_KEYS, ('start_time_utc','activity_type'), ('duration_ms','distance_m','training_load')
    if source == points.METRIC:
        # Single point normalization requires its value and timestamps; there
        # are no optional numeric fields whose absence can delete a value.
        return None
    raise app.InvalidArguments()


def store_records(db, source, records, at):
    at = app._utc_timestamp(at)
    if at is None:
        raise app.InvalidArguments()
    ensure_schema(db)
    layout = _layout(source)
    if layout is None:
        for record in records:
            points.upsert(db, record, source)
        return len(records)
    table, columns, keys, measured_fields = layout
    where = ' AND '.join(k+'=?' for k in keys)
    columns = tuple(columns)
    updates = ','.join(k+'=excluded.'+k for k in columns if k not in keys)
    insert = ('INSERT INTO '+table+' ('+','.join(columns)+',source) VALUES ('+
              ','.join('?' for _ in (*columns,'source'))+') ON CONFLICT ('+
              ','.join(keys)+') DO UPDATE SET '+updates)
    for record in records:
        new = {k:record.get(k) for k in columns}
        row = db.execute('SELECT '+','.join(columns)+' FROM '+table+' WHERE '+where,
                         tuple(new[k] for k in keys)).fetchone()
        old = dict(zip(columns,row)) if row else {}
        identity = record_key(source,new)
        for field in measured_fields:
            prior = db.execute('SELECT last_valid_at_utc FROM health_record_quality WHERE source=? AND record_key=? AND field=?',
                               (source,identity,field)).fetchone()
            retained = new[field] is None and old.get(field) is not None
            observed_at = at if new[field] is not None else prior[0] if prior else None
            if retained:
                new[field] = old[field]
            db.execute('''INSERT INTO health_record_quality VALUES (?,?,?,?,?,?)
                ON CONFLICT(source,record_key,field) DO UPDATE SET
                last_valid_at_utc=excluded.last_valid_at_utc,
                last_seen_at_utc=excluded.last_seen_at_utc,retained=excluded.retained''',
                (source,identity,field,observed_at,at,int(retained)))
        db.execute(insert,tuple(new[k] for k in columns)+(app.SOURCE,))
    return len(records)


def quality(db, source, record):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='health_record_quality'").fetchone():
        return {'provenance':'legacy_unknown','retained_fields':[],'fields':{}}
    rows = db.execute('SELECT field,last_valid_at_utc,last_seen_at_utc,retained FROM health_record_quality WHERE source=? AND record_key=?',
                      (source,record_key(source,record))).fetchall()
    return {'provenance':'field_observations' if rows else 'legacy_unknown',
            'retained_fields':sorted(r[0] for r in rows if r[3]),
            'fields':{r[0]:{'last_valid_at_utc':r[1],'last_seen_at_utc':r[2],
                             'retained':bool(r[3])} for r in rows}}


def retained_count(db, source):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='health_record_quality'").fetchone():
        return 0
    return db.execute('SELECT count(*) FROM health_record_quality WHERE source=? AND retained=1',(source,)).fetchone()[0]
