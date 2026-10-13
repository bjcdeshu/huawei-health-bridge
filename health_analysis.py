"""Deterministic descriptive analysis of saved Huawei summaries, never advice.

Public API: build_analysis(state_dir, *, days=7, start=None, end=None,
                          baseline_days=28, include_today=False, now=None).
Dates are inclusive, strict YYYY-MM-DD (or date objects), in fixed UTC+8.
Without an explicit end, yesterday is used unless include_today=True. An end
alone uses `days`; a start alone uses the default end. Explicit dates take
precedence over `days`. Today is always labelled incomplete. days/range lengths
are 1..366; baseline_days is 0..366 (zero disables the comparison). `now` must
be timezone-aware. The baseline ends immediately before the selected start.

Only app.Store(create=False) is used, in one read transaction. No auth file,
auth metadata, network, migration, logging, printing, or report file is used.
health.py is deliberately not imported; it owns CLI integration. Missing stores
return a fully shaped not_initialized result; invalid arguments/storage raise
app.InvalidArguments/app.StorageError with no input or measurement in messages.

Schema v1: scope + collection + sources[name].{collection,current,baseline,
comparison}. Periods contain coverage, daily observations, summary statistics
and provenance counts. Missing dates are not filled with zero. Means over daily
statistics are UNWEIGHTED means of saved daily values, not raw-sample averages.
Unknown provenance is included but counted, never described as verified fresh;
fields marked retained are null in observations and excluded from statistics.
Missing/malformed optional provenance tables remain explicitly unknown.
"""
from __future__ import annotations

import math
import re
import sqlite3
import statistics
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone

import app

LOCAL_ZONE = timezone(timedelta(hours=8))
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
SOURCE_NAMES = ("activities", "sleep", "resting_hr", "hrv", "all_day_heart_rate", "spo2", "vo2max")
METRICS = {
    "resting_hr": ("restBpm", "bpm", ("avg",)),
    "hrv": ("avgHrv", None, ("avg",)),
    "all_day_heart_rate": ("bpm", "bpm", ("min", "max")),
    "spo2": ("spO2", "percent", ("avg", "min", "max")),
}
SLEEP_TIMES = ("start_time_utc", "end_time_utc", "go_bed_time_utc", "fall_asleep_time_utc", "wakeup_time_utc")
SLEEP_MINUTES = ("total_sleep_minutes", "light_sleep_minutes", "deep_sleep_minutes", "rem_sleep_minutes", "awake_minutes", "sleep_latency_minutes")
SLEEP_FIELDS = (*SLEEP_TIMES, *SLEEP_MINUTES, "wakeup_count", "sleep_score", "sleep_efficiency_percent", "sleep_type")
SUCCESS = frozenset(("ok", "partial", "empty", "coverage_limited"))
STATUSES = app.COLLECTION_STATUSES | SUCCESS | {"collection_error", "auth_check_error"}
COVERAGES = frozenset(("bounded_window", "coverage_limited", "legacy_latest_only", "not_collected", "not_assessed", "latest_measurement"))
FRESH_SECONDS = 36 * 3600


def _date(value):
    if type(value) is date:
        return value
    if type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        try:
            return date.fromisoformat(value)
        except ValueError:
            pass
    raise app.InvalidArguments() from None


def _clock(now):
    if now is None:
        return datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise app.InvalidArguments()
    try:
        return now.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise app.InvalidArguments() from None


def _dates(first, last):
    return [(first + timedelta(days=i)).isoformat() for i in range((last - first).days + 1)]


def _scope(days, start, end, baseline_days, include_today, now):
    if (type(days) is not int or not 1 <= days <= 366
            or type(baseline_days) is not int or not 0 <= baseline_days <= 366
            or type(include_today) is not bool):
        raise app.InvalidArguments()
    try:
        today = now.astimezone(LOCAL_ZONE).date()
        last = _date(end) if end is not None else today - timedelta(days=not include_today)
        first = _date(start) if start is not None else last - timedelta(days=days - 1)
        if not first <= last <= today or (last - first).days >= 366:
            raise app.InvalidArguments()
        base_last = first - timedelta(days=1)
        base_first = first - timedelta(days=baseline_days)
        current_dates = _dates(first, last)
        baseline_dates = _dates(base_first, base_last) if baseline_days else []
    except (ValueError, OverflowError):
        raise app.InvalidArguments() from None
    return dict(start=first.isoformat(), end=last.isoformat(), days=len(current_dates),
                dates=current_dates, incomplete_dates=[today.isoformat()] if last == today else [],
                completed_dates=[d for d in current_dates if d != today.isoformat()],
                includes_today=last == today, timezone="+08:00", date_order="ascending",
                baseline=dict(start=baseline_dates[0] if baseline_dates else None,
                              end=baseline_dates[-1] if baseline_dates else None,
                              days=len(baseline_dates), dates=baseline_dates))


def _number(value, maximum=app.SQLITE_MAX_INT):
    if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum:
        return value
    return None


def _integer(value, maximum=app.SQLITE_MAX_INT):
    value = _number(value, maximum)
    return int(value) if value is not None and value == int(value) else None


def _stamp(value):
    normalized = app._utc_timestamp(value)
    return datetime.fromisoformat(normalized) if normalized is not None else None


def _iso(value):
    return value.isoformat() if value is not None else None


def _ns(value):
    delta = value - EPOCH
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


def _ns_stamp(value):
    if type(value) is not int or not 0 < value <= app.SQLITE_MAX_INT:
        return None
    seconds, fraction = divmod(value, 1_000_000_000)
    return (EPOCH + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}+00:00"


def _stats(values, *, unit=None, population, total=False):
    values = [v for v in values if v is not None]
    result = dict(unit=unit, population=population, sample_count=len(values),
                  mean=math.fsum(values) / len(values) if values else None,
                  median=statistics.median(values) if values else None,
                  min=min(values) if values else None, max=max(values) if values else None,
                  range=max(values) - min(values) if values else None)
    if total:
        result["sum"] = math.fsum(values) if values else None
    return result


def _comparison(current, baseline):
    result = {}
    for field, summary in current["summary"].items():
        other = baseline["summary"].get(field, {})
        result[field] = dict(unit=summary["unit"], direction="current_minus_baseline",
                             current_sample_count=summary["sample_count"], baseline_sample_count=other.get("sample_count", 0))
        for key in ("mean", "median", "min", "max"):
            a, b = summary.get(key), other.get(key)
            result[field][key + "_delta"] = a - b if a is not None and b is not None else None
    return result


def _coverage(dates, daily, *, usable_records, observed_records):
    observed = sorted({r["date"] for r in daily})
    usable = sorted({r["date"] for r in daily if r["usable"]})
    return dict(expected_dates=dates, expected_day_count=len(dates), observed_dates=observed,
                usable_dates=usable, missing_dates=sorted(set(dates) - set(observed)),
                unusable_dates=sorted(set(observed) - set(usable)),
                missing_usable_dates=sorted(set(dates) - set(usable)),
                observed_day_count=len(observed), usable_day_count=len(usable),
                observed_record_count=observed_records, usable_record_count=usable_records,
                excluded_record_count=observed_records - usable_records,
                incomplete_dates=[r["date"] for r in daily if r["incomplete"]])


def _columns(db, table):
    if db is None or not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
        return set()
    # table is always an internal constant, never user-controlled SQL.
    return {r[1] for r in db.execute(f'PRAGMA table_info("{table}")')}


def _rows(db, table, columns, *, required=(), where="", params=()):
    available = _columns(db, table)
    if not available or not set(required).issubset(available):
        return []
    select = ",".join('"' + c + '"' if c in available else 'NULL AS "' + c + '"' for c in columns)
    return [dict(zip(columns, r)) for r in db.execute(f'SELECT {select} FROM "{table}" ' + where, params)]


class _Quality:
    def __init__(self, db):
        columns = _columns(db, "health_record_quality")
        required = {"source", "record_key", "field", "retained"}
        self.state = "available" if required.issubset(columns) else "legacy_unknown" if not columns else "unavailable_schema"
        self.entries = {}
        if self.state == "available":
            fields = ("source", "record_key", "field", "retained", "last_valid_at_utc", "last_seen_at_utc")
            for row in _rows(db, "health_record_quality", fields, required=required):
                if row["source"] not in SOURCE_NAMES:
                    continue
                key = (row["source"], row["record_key"], row["field"])
                self.entries[key] = row if key not in self.entries else {"retained": None}

    def apply(self, source, key, values):
        cleaned, provenance = {}, {}
        for field, value in values.items():
            meta = self.entries.get((source, key, field)) if key is not None else None
            status = ("unknown" if meta is None else "retained" if meta["retained"] == 1
                      else "tracked_valid" if meta["retained"] == 0 else "invalid_metadata")
            provenance[field] = status
            cleaned[field] = None if status in ("retained", "invalid_metadata") else value
        return cleaned, provenance


def _quality_counts(records):
    fields, records_retained, unknown = Counter(), 0, 0
    for record in records:
        provenance = record["field_provenance"]
        fields.update(provenance.values())
        records_retained += "retained" in provenance.values()
        unknown += "unknown" in provenance.values()
    return dict(retained_field_count=fields["retained"], records_with_retained_fields=records_retained,
                unknown_provenance_field_count=fields["unknown"], records_with_unknown_provenance=unknown,
                tracked_valid_field_count=fields["tracked_valid"], invalid_metadata_field_count=fields["invalid_metadata"],
                summary_policy="exclude_retained_and_invalid_metadata; include_and_disclose_unknown_provenance")


def _collection(db, name, now):
    fields = ("name", "last_status", "checked_at_utc", "last_success_time_utc", "received_records", "stored_records", "coverage", "quality", "lookback_days", "query_limit")
    rows = _rows(db, "health_source_state", fields, required=("name",), where="WHERE name=?", params=(name,))
    saved = rows[0] if rows else {}
    if not saved and name in ("activities", "sleep"):
        table = "collection_state" if name == "activities" else "sleep_collection_state"
        legacy = _rows(db, table, ("last_status", "collected_at_utc"), required=("singleton",), where="WHERE singleton=1")
        if legacy:
            saved = dict(last_status=legacy[0]["last_status"], checked_at_utc=legacy[0]["collected_at_utc"],
                         last_success_time_utc=legacy[0]["collected_at_utc"] if legacy[0]["last_status"] in SUCCESS else None,
                         coverage="legacy_latest_only" if name == "activities" else "bounded_window")
    last = saved.get("last_status")
    status = last if last in STATUSES else "invalid_response" if last is not None else "not_collected"
    checked, success = _stamp(saved.get("checked_at_utc")), _stamp(saved.get("last_success_time_utc"))
    age = (now - success).total_seconds() if success is not None else None
    freshness = ("collection_failed" if last is not None and status not in SUCCESS else
                 "unknown" if age is None else "future_timestamp" if age < 0 else
                 "fresh" if age <= FRESH_SECONDS else "stale")
    return dict(status=status, last_collection_status=None if last is None else status,
                checked_at_utc=_iso(checked), last_success_time_utc=_iso(success),
                last_success_age_seconds=age, freshness=freshness, freshness_threshold_seconds=FRESH_SECONDS,
                coverage=saved.get("coverage") if saved.get("coverage") in COVERAGES else "not_assessed",
                quality=saved.get("quality") if saved.get("quality") in ("ok", "partial", "empty") else None,
                received_records=_integer(saved.get("received_records")), stored_records=_integer(saved.get("stored_records")),
                lookback_days=_integer(saved.get("lookback_days")), query_limit=_integer(saved.get("query_limit")),
                requested_range_completeness="not_established_by_collection_status")


def _sync_collection(db):
    fields = ("last_status", "checked_at_utc", "last_success_time_utc", "authentication_required")
    rows = _rows(db, "health_sync_state", fields, required=("singleton",), where="WHERE singleton=1")
    saved = rows[0] if rows else {}
    return dict(last_status=saved.get("last_status") if saved.get("last_status") in STATUSES else None,
                checked_at_utc=_iso(_stamp(saved.get("checked_at_utc"))),
                last_success_time_utc=_iso(_stamp(saved.get("last_success_time_utc"))),
                saved_authentication_required=bool(saved["authentication_required"]) if saved.get("authentication_required") in (0, 1) else None,
                authentication="not_checked", metadata_source="database_only")


def _metric_rows(db, name, dates, quality, today):
    field_name, unit, fields = METRICS[name]
    columns = ("day", "time_zone", "field_name", *fields, "count")
    rows = _rows(db, "metric_stats", columns, required=("metric", "day", "source"),
                 where="WHERE metric=? AND source=? AND day>=? AND day<=?", params=(name, app.SOURCE, dates[0], dates[-1])) if dates else []
    by_day = defaultdict(list)
    for row in rows:
        if row["day"] in dates:
            by_day[row["day"]].append(row)
    output = []
    for day, group in sorted(by_day.items()):
        row = group[0]
        values, provenance = quality.apply(name, day, {k: _integer(row[k]) if k == "count" else _number(row[k]) for k in (*fields, "count")})
        reasons = []
        if len(group) != 1:
            reasons.append("duplicate_daily_records")
        else:
            if row["time_zone"] != "+0800" or row["field_name"] != field_name:
                reasons.append("invalid_daily_identity")
            if values["count"] == 0:
                reasons.append("zero_measurement_count")
        if reasons:
            values = {k: None for k in values}
        output.append(dict(date=day, incomplete=day == today, usable=any(values[k] is not None for k in fields),
                           values={k: values[k] for k in fields}, sample_count=values["count"],
                           field_provenance=provenance, missing_fields=[k for k in fields if values[k] is None],
                           exclusion_reasons=reasons, observed_record_count=len(group)))
    return output


def _metric_period(name, dates, rows):
    _, unit, fields = METRICS[name]
    daily = [r for r in rows if r["date"] in dates]
    summary = {}
    for field in fields:
        summary[field] = _stats([r["values"][field] for r in daily], unit=unit, population="unweighted_saved_daily_" + field)
        summary[field]["usable_dates"] = [r["date"] for r in daily if r["values"][field] is not None]
        summary[field]["missing_usable_dates"] = sorted(set(dates) - set(summary[field]["usable_dates"]))
    known = [r["sample_count"] for r in daily if r["usable"] and r["sample_count"] is not None]
    return dict(coverage=_coverage(dates, daily, observed_records=sum(r["observed_record_count"] for r in daily), usable_records=sum(r["usable"] for r in daily)),
                daily=daily, summary=summary, quality=_quality_counts(daily),
                underlying_samples=dict(known_count_sum=sum(known) if known else None, days_with_known_count=len(known),
                                        usable_days_with_unknown_count=sum(r["usable"] and r["sample_count"] is None for r in daily),
                                        counts_are_not_summary_weights=True))


def _mark_overlaps(rows):
    """Exclude every member of an overlapping interval cluster, including duplicates."""
    ordered = sorted((r for r in rows if r.get("_start") is not None and r.get("_end") is not None and r["_start"] < r["_end"]),
                     key=lambda r: (r["_start"], r["_end"]))
    previous, furthest = None, None
    for row in ordered:
        if furthest is not None and row["_start"] < furthest:
            row["exclusion_reasons"].append("overlapping_or_duplicate_session")
            if "overlapping_or_duplicate_session" not in previous["exclusion_reasons"]:
                previous["exclusion_reasons"].append("overlapping_or_duplicate_session")
        if furthest is None or row["_end"] > furthest:
            previous, furthest = row, row["_end"]


def _sleep_rows(db, quality, now):
    rows = _rows(db, "sleep_records", SLEEP_FIELDS, required=("source", "start_time_utc", "end_time_utc"), where="WHERE source=?", params=(app.SOURCE,))
    output, unassigned = [], 0
    for row in rows:
        values = {}
        for field in SLEEP_FIELDS:
            values[field] = _iso(_stamp(row[field])) if field in SLEEP_TIMES else _integer(row[field], 1440 if field in SLEEP_MINUTES else 100 if field in ("sleep_score", "sleep_efficiency_percent") else app.SQLITE_MAX_INT)
        key = str(row["start_time_utc"]) + "|" + str(row["sleep_type"])
        values, provenance = quality.apply("sleep", key, values)
        start, end, wake = (_stamp(values[f]) for f in ("start_time_utc", "end_time_utc", "wakeup_time_utc"))
        # An excluded retained end may still identify its observed (not usable) date.
        observed_end = end or _stamp(row["end_time_utc"])
        if observed_end is None:
            unassigned += 1
            continue
        reasons = []
        if start is None or end is None or end <= start or values["sleep_type"] is None:
            reasons.append("invalid_or_retained_session_identity")
        if wake is not None and start is not None and end is not None and not start <= wake <= end:
            reasons.append("wakeup_outside_session")
            wake = None
        if end is not None and end > now:
            reasons.append("session_not_completed_as_of_now")
        if values["total_sleep_minutes"] is None:
            reasons.append("missing_or_retained_total_sleep_minutes")
        waking = wake or observed_end
        output.append(dict(date=waking.astimezone(LOCAL_ZONE).date().isoformat(),
                           waking_date_basis="wakeup_time_utc" if wake is not None else "end_time_utc_fallback",
                           incomplete=waking.astimezone(LOCAL_ZONE).date() == now.astimezone(LOCAL_ZONE).date(),
                           complete=end is not None and end <= now, fields=values,
                           missing_fields=[k for k, v in values.items() if v is None],
                           field_provenance=provenance, exclusion_reasons=reasons, _start=start, _end=end))
    _mark_overlaps(output)
    return output, unassigned


def _public_record(record):
    return {k: v for k, v in record.items() if not k.startswith("_")}


def _sleep_period(dates, rows):
    selected = [r for r in rows if r["date"] in dates]
    groups = defaultdict(list)
    for row in selected:
        groups[row["date"]].append(row)
    daily, mains, shorts, others = [], [], [], []
    excluded_count = 0
    for day, group in sorted(groups.items()):
        group.sort(key=lambda r: (r["fields"]["start_time_utc"] or "", r["fields"]["sleep_type"] if r["fields"]["sleep_type"] is not None else -1))
        usable = [r for r in group if not r["exclusion_reasons"]]
        long = sorted((r for r in usable if r["fields"]["total_sleep_minutes"] >= 180), key=lambda r: -r["fields"]["total_sleep_minutes"])
        short = [r for r in usable if r["fields"]["total_sleep_minutes"] < 180]
        ambiguous = any("overlapping_or_duplicate_session" in r["exclusion_reasons"] for r in group)
        tied = len(long) > 1 and long[0]["fields"]["total_sleep_minutes"] == long[1]["fields"]["total_sleep_minutes"]
        main = long[0] if long and not ambiguous and not tied else None
        other = [r for r in long if r is not main]
        excluded = [r for r in group if r["exclusion_reasons"]]
        excluded_count += len(excluded)
        if main is not None:
            mains.append(main)
        shorts.extend(short)
        others.extend(other)
        daily.append(dict(date=day, incomplete=any(r["incomplete"] for r in group), usable=bool(usable),
                          main_selection_status="ambiguous_overlap" if ambiguous else "ambiguous_longest_tie" if tied else "selected_by_heuristic" if main else "no_usable_session_at_least_180_minutes",
                          main_sleep=_public_record(main) if main is not None else None,
                          short_additional_sessions=[_public_record(r) for r in short],
                          other_long_sessions=[_public_record(r) for r in other],
                          excluded_sessions=[_public_record(r) for r in excluded]))
    summary = {}
    for name, records in (("main_sleep_minutes", mains), ("short_additional_sleep_minutes", shorts), ("other_long_sleep_minutes", others)):
        summary[name] = _stats([r["fields"]["total_sleep_minutes"] for r in records], unit="minutes", population=name + "_per_session", total=True)
        summary[name]["usable_dates"] = sorted({r["date"] for r in records})
        summary[name]["missing_usable_dates"] = sorted(set(dates) - set(summary[name]["usable_dates"]))
    return dict(coverage=_coverage(dates, daily, observed_records=len(selected), usable_records=len(selected) - excluded_count),
                coverage_usable_definition="any_usable_completed_session; main_sleep_coverage_is_in_its_summary",
                daily=daily, summary=summary, quality=_quality_counts(selected),
                missing_field_counts=dict(sorted(Counter(k for r in selected for k in r["missing_fields"]).items())),
                session_counts=dict(observed=len(selected), main=len(mains), short_additional=len(shorts), other_long=len(others), excluded=excluded_count))


def _activity_rows(db, quality, now):
    fields = ("start_time_utc", "activity_type", "duration_ms", "distance_m")
    rows = _rows(db, "activities", fields, required=("source", "start_time_utc", "activity_type"), where="WHERE source=?", params=(app.SOURCE,))
    output, unassigned = [], 0
    for row in rows:
        observed_start = _stamp(row["start_time_utc"])
        if observed_start is None:
            unassigned += 1
            continue
        values = dict(start_time_utc=_iso(observed_start), activity_type=app._activity_type(row["activity_type"]),
                      duration_ms=_number(row["duration_ms"]), distance_m=_number(row["distance_m"]))
        # Match health_storage's composite identity exactly; do not normalize
        # the saved token before its field-level provenance lookup.
        key = row["start_time_utc"] + "|" + str(row["activity_type"])
        values, provenance = quality.apply("activities", key, values)
        start, end = _stamp(values["start_time_utc"]), None
        reasons = []
        if start is None or values["activity_type"] is None:
            reasons.append("invalid_or_retained_activity_identity")
        if start is not None and values["duration_ms"] is not None:
            try:
                end = start + timedelta(milliseconds=values["duration_ms"])
            except OverflowError:
                reasons.append("invalid_activity_duration")
        if observed_start > now or (end is not None and end > now):
            reasons.append("activity_not_completed_as_of_now")
        output.append(dict(date=observed_start.astimezone(LOCAL_ZONE).date().isoformat(),
                           incomplete=observed_start.astimezone(LOCAL_ZONE).date() == now.astimezone(LOCAL_ZONE).date(),
                           complete=end <= now if end is not None else None, values=values,
                           field_provenance=provenance,
                           missing_fields=[k for k, v in values.items() if v is None], exclusion_reasons=reasons,
                           _start=start, _end=end, _key=key))
    _mark_overlaps(output)
    ids = Counter(r["_key"] for r in output if r["_key"] is not None)
    for row in output:
        if row["_key"] is not None and ids[row["_key"]] > 1:
            row["exclusion_reasons"].append("duplicate_activity_identity")
    return output, unassigned


def _activity_period(dates, rows):
    selected = [r for r in rows if r["date"] in dates]
    usable = [r for r in selected if not r["exclusion_reasons"]]
    groups = defaultdict(list)
    for row in selected:
        groups[row["date"]].append(row)
    daily = [dict(date=day, incomplete=any(r["incomplete"] for r in group), usable=any(not r["exclusion_reasons"] for r in group),
                  observed_workout_count=len(group), usable_workout_count=sum(not r["exclusion_reasons"] for r in group),
                  records=[_public_record(r) for r in sorted(group, key=lambda r: (r["values"]["start_time_utc"] or "", str(r["values"]["activity_type"])))]) for day, group in sorted(groups.items())]
    return dict(coverage=_coverage(dates, daily, observed_records=len(selected), usable_records=len(usable)),
                observed_workout_count=len(selected), usable_workout_count=len(usable), daily=daily,
                summary={field: _stats([r["values"][field] for r in usable], unit=unit, population="saved_nonambiguous_workout_records", total=True)
                         for field, unit in (("duration_ms", "ms"), ("distance_m", "m"))},
                quality=_quality_counts(selected), missing_field_counts=dict(sorted(Counter(k for r in selected for k in r["missing_fields"]).items())))


def _point_rows(db, quality, now):
    fields = ("measured_at_ns", "measured_at_utc", "end_time_ns", "end_time_utc", "value", "field_name", "time_zone")
    rows = _rows(db, "point_measurements", fields, required=("source", "metric", "measured_at_ns"), where="WHERE source=? AND metric=?", params=(app.SOURCE, "vo2max"))
    output, invalid = [], 0
    for row in rows:
        ns, end = row["measured_at_ns"], row["end_time_ns"]
        stamp = _ns_stamp(ns)
        if (stamp is None or ns > _ns(now) or row["measured_at_utc"] != stamp
                or _ns_stamp(end) is None or end < ns or end > _ns(now)
                or row["end_time_utc"] != _ns_stamp(end) or row["field_name"] != "vo2max" or row["time_zone"] != "+0800"):
            invalid += 1
            continue
        day = (EPOCH + timedelta(seconds=ns // 1_000_000_000)).astimezone(LOCAL_ZONE).date().isoformat()
        values, provenance = quality.apply("vo2max", str(ns), {"value": _integer(row["value"])})
        output.append(dict(date=day, incomplete=day == now.astimezone(LOCAL_ZONE).date().isoformat(),
                           measured_at_ns=ns, measured_at_utc=stamp, value=values["value"],
                           field_provenance=provenance, usable=values["value"] is not None))
    output.sort(key=lambda r: r["measured_at_ns"])
    return output, invalid


def _point_period(dates, rows):
    selected = [r for r in rows if r["date"] in dates]
    groups = defaultdict(list)
    for row in selected:
        groups[row["date"]].append(row)
    daily = [dict(date=day, incomplete=any(r["incomplete"] for r in group), usable=any(r["usable"] for r in group), measurements=group) for day, group in sorted(groups.items())]
    return dict(coverage=_coverage(dates, daily, observed_records=len(selected), usable_records=sum(r["usable"] for r in selected)),
                daily=daily, summary=dict(value=_stats([r["value"] for r in selected], unit=None, population="measurements_within_this_date_range")),
                quality=_quality_counts(selected))


def _build(db, scope, now, initialized):
    quality = _Quality(db)
    today = now.astimezone(LOCAL_ZONE).date().isoformat()
    current_dates, baseline_dates = scope["dates"], scope["baseline"]["dates"]
    all_dates = baseline_dates + current_dates
    result = dict(schema_version=1, status="ok" if initialized else "not_initialized", source=app.SOURCE,
                  generated_at_utc=now.isoformat(), as_of_utc=now.isoformat(), as_of_local_date=today, timezone="+08:00",
                  scope=scope, saved_data_only=True, network_attempted=False, complete_history=False,
                  collection=_sync_collection(db), provenance=dict(table_status=quality.state), sources={},
                  methods=dict(missing_dates="no_zero_filling", summary_population="non_retained_values_with_unknown_provenance_disclosed",
                               daily_statistics="unweighted_across_days_not_raw_measurement_average",
                               sleep="longest_usable_completed_session_at_least_180_minutes_by_local_waking_date; heuristic_not_a_type_classification; overlapping_sessions_and_longest_ties_excluded",
                               sleep_type="raw_code_no_stage_or_clinical_classification", workouts="recorded_workouts_not_all_day_exercise_or_steps",
                               vo2max="range_membership_by_measured_at_ns_not_collection_time", interpretation="descriptive_only_no_diagnosis_or_readiness_score"),
                  warnings=["saved_rows_and_recent_collection_do_not_prove_range_completeness",
                            "daily_spo2_minima_do_not_describe_duration", "workout_missing_dates_do_not_mean_no_exercise",
                            "baseline_context_changes_are_not_inferred"])
    if quality.state != "available":
        result["warnings"].append("retention_provenance_unknown")
    for name in SOURCE_NAMES:
        metadata = {}
        if name in METRICS:
            rows = _metric_rows(db, name, all_dates, quality, today)
            current = _metric_period(name, current_dates, rows)
            baseline = _metric_period(name, baseline_dates, rows)
        elif name == "sleep":
            rows, unassigned = _sleep_rows(db, quality, now)
            current, baseline = _sleep_period(current_dates, rows), _sleep_period(baseline_dates, rows)
            metadata["unassignable_saved_record_count"] = unassigned
        elif name == "activities":
            rows, unassigned = _activity_rows(db, quality, now)
            current, baseline = _activity_period(current_dates, rows), _activity_period(baseline_dates, rows)
            metadata["unassignable_saved_record_count"] = unassigned
        else:
            rows, invalid = _point_rows(db, quality, now)
            current, baseline = _point_period(current_dates, rows), _point_period(baseline_dates, rows)
            latest = rows[-1] if rows else None
            metadata["latest_saved_measurement"] = dict(measured_at_ns=latest["measured_at_ns"], measured_at_utc=latest["measured_at_utc"],
                local_date=latest["date"], within_scope=latest["date"] in current_dates, within_baseline=latest["date"] in baseline_dates,
                age_seconds=(_ns(now) - latest["measured_at_ns"]) / 1_000_000_000, value_usable=latest["usable"]) if latest else None
            metadata["invalid_saved_record_count"] = invalid
        entry = dict(collection=_collection(db, name, now), current=current, baseline=baseline,
                     comparison=_comparison(current, baseline), warnings=[], **metadata)
        entry["status"] = entry["collection"]["status"]
        for period in (current, baseline):
            if period["quality"]["retained_field_count"]:
                entry["warnings"].append("retained_values_excluded")
            if period["quality"]["unknown_provenance_field_count"]:
                entry["warnings"].append("some_field_provenance_unknown")
            if period["quality"]["invalid_metadata_field_count"]:
                entry["warnings"].append("invalid_provenance_fields_excluded")
        entry["warnings"] = sorted(set(entry["warnings"]))
        result["sources"][name] = entry
    return result


def build_analysis(state_dir, *, days=7, start=None, end=None, baseline_days=28, include_today=False, now=None):
    """Return only computed JSON-safe data; never create, collect or print anything."""
    clock = _clock(now)
    scope = _scope(days, start, end, baseline_days, include_today, clock)
    try:
        with app.Store(state_dir, create=False) as store:
            store.connection.execute("PRAGMA query_only = ON")
            store.connection.execute("BEGIN")  # Stable data/provenance/status snapshot.
            return _build(store.connection, scope, clock, True)
    except app.NotInitialized:
        return _build(None, scope, clock, False)
    except (app.StorageError, sqlite3.Error, OSError):
        raise app.StorageError() from None
