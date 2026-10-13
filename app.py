"""Private, stdlib-only VPS runner; the original collector CLI stays synthetic.

Usage: python3 -B app.py [--state-dir DIR] [--auth-file FILE] COMMAND
Commands: init, collect [--lookback-days 1..30], status, latest.
Shared options may also follow COMMAND. Only collect loads credentials or uses
HTTP. It makes one official query, without login, refresh, retries or scheduling.
Exit codes: 0 success/partial/empty, 1 operational failure, 2 invalid arguments,
3 reauth_required. collect/status never print a health summary; latest does.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path

import collector

DEFAULT_STATE_DIR = Path("/var/lib/huawei-training-camp")
DEFAULT_AUTH_FILE = DEFAULT_STATE_DIR / "auth.json"
DATABASE_NAME = "health.sqlite3"
SOURCE = "huawei_training_camp"
MAX_AUTH_BYTES = 32 * 1024
SUMMARY_KEYS = ("start_time_utc", "activity_type", "duration_ms", "distance_m", "training_load")
AUTH_KEYS = frozenset(("Authorization", "x-client-id", "x-version", "Cookie"))
COLLECTION_STATUSES = frozenset(("ok", "partial", "empty", "reauth_required",
    "transport_error", "redirect_rejected", "rate_limited", "service_error",
    "http_error", "invalid_response"))
SQLITE_MAX_INT = (1 << 63) - 1


class StorageError(Exception):
    pass


class NotInitialized(Exception):
    pass


class InvalidArguments(Exception):
    pass


def _private_file(info, allowed_mode):
    return (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and not stat.S_IMODE(info.st_mode) & ~allowed_mode)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def load_auth(path):
    """Read a bounded owner-only regular file, without following its symlink.

    Return None for every missing, malformed or unsafe credential case. Neither
    the reason nor any credential value is logged, persisted or printed.
    O_NONBLOCK also prevents a substituted FIFO from hanging the runner.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not _private_file(info, 0o600) or info.st_size > MAX_AUTH_BYTES:
                return None
            raw = handle.read(MAX_AUTH_BYTES + 1)
            info = os.fstat(handle.fileno())
            if (len(raw) > MAX_AUTH_BYTES or info.st_size > MAX_AUTH_BYTES
                    or not _private_file(info, 0o600)):
                return None
        headers = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if (not isinstance(headers, dict) or set(headers) - AUTH_KEYS
                or any(not isinstance(v, str) or "\r" in v or "\n" in v
                       for v in headers.values())
                or any(not headers.get(k, "").strip() for k in ("Authorization", "x-client-id"))):
            return None
        return headers
    except Exception:
        return None


def _utc_timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if (parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0
                or parsed < datetime(1970, 1, 1, tzinfo=timezone.utc)):
            return None
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError, AttributeError):
        return None


def _activity_type(value):
    # Keep raw machine codes, not names, embedded JSON, controls or free text.
    if type(value) is int and 0 <= value <= SQLITE_MAX_INT:
        return value
    if type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", value):
        return value
    return None


def _number(value):
    value = collector.number(value)
    if type(value) is int and value > SQLITE_MAX_INT:
        return None
    return value


def normalize_summary(summary):
    """Re-allowlist the collector boundary and read-back, keeping missing nulls."""
    data = summary if isinstance(summary, dict) else {}
    return dict(start_time_utc=_utc_timestamp(data.get("start_time_utc")),
                activity_type=_activity_type(data.get("activity_type")),
                duration_ms=_number(data.get("duration_ms")),
                distance_m=_number(data.get("distance_m")),
                training_load=_number(data.get("training_load")))


class Store:
    """Owner-only SQLite, anchored to an open private directory on this VPS.

    Existing unsafe paths are refused, not silently chmodded. No raw response,
    headers, credentials, activity name or location column is ever created.
    """
    def __init__(self, state_dir, *, create=False):
        self.connection = None
        self.directory_fd = None
        try:
            if create:
                try:
                    os.mkdir(state_dir, 0o700)
                except FileExistsError:
                    pass
            self.directory_fd = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY
                                         | os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(self.directory_fd)
            if (info.st_uid != os.geteuid() or not stat.S_ISDIR(info.st_mode)
                    or stat.S_IMODE(info.st_mode) & ~0o700):
                raise StorageError()
            flags = (os.O_RDWR if create else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            fd = None
            try:
                if create:
                    try:
                        fd = os.open(DATABASE_NAME, flags | os.O_CREAT | os.O_EXCL,
                                     0o600, dir_fd=self.directory_fd)
                        os.fchmod(fd, 0o600)
                    except FileExistsError:
                        fd = os.open(DATABASE_NAME, flags, dir_fd=self.directory_fd)
                else:
                    fd = os.open(DATABASE_NAME, flags, dir_fd=self.directory_fd)
                info = os.fstat(fd)
                if not _private_file(info, 0o600) or info.st_nlink != 1:
                    raise StorageError()
            finally:
                if fd is not None:
                    os.close(fd)
            for suffix in ("-journal", "-wal", "-shm"):
                try:
                    info = os.stat(DATABASE_NAME + suffix, dir_fd=self.directory_fd,
                                   follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not _private_file(info, 0o600) or info.st_nlink != 1:
                    raise StorageError()
            # /proc/self/fd keeps the private parent anchored if it is renamed.
            path = f"/proc/self/fd/{self.directory_fd}/{DATABASE_NAME}"
            self.connection = (sqlite3.connect(path) if create else
                               sqlite3.connect(f"file:{path}?mode=ro", uri=True))
            self.connection.execute("PRAGMA trusted_schema = OFF")
            if create:
                self.connection.execute("PRAGMA journal_mode = DELETE")
                self.connection.executescript("""
                    CREATE TABLE IF NOT EXISTS activities (
                        start_time_utc TEXT NOT NULL,
                        activity_type NOT NULL,
                        duration_ms,
                        distance_m,
                        training_load,
                        source TEXT NOT NULL CHECK(source = 'huawei_training_camp'),
                        UNIQUE(start_time_utc, activity_type)
                    );
                    CREATE TABLE IF NOT EXISTS collection_state (
                        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                        last_status TEXT NOT NULL,
                        collected_at_utc TEXT NOT NULL
                    );
                """)
        except FileNotFoundError:
            self.close()
            if not create:
                raise NotInitialized() from None
            raise StorageError() from None
        except Exception:
            self.close()
            raise StorageError() from None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        try:
            if self.connection is not None:
                self.connection.close()
        finally:
            self.connection = None
            if self.directory_fd is not None:
                os.close(self.directory_fd)
                self.directory_fd = None

    def count(self):
        return self.connection.execute("SELECT count(*) FROM activities").fetchone()[0]

    def record(self, status, collected_at_utc, summary):
        # The activity and last-attempt marker commit atomically, including on an
        # empty/error response. Empty/error responses never delete prior rows.
        with self.connection:
            if summary is not None:
                self.connection.execute("""
                    INSERT INTO activities
                        (start_time_utc, activity_type, duration_ms, distance_m, training_load, source)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(start_time_utc, activity_type) DO UPDATE SET
                        duration_ms=excluded.duration_ms, distance_m=excluded.distance_m,
                        training_load=excluded.training_load, source=excluded.source
                    """, tuple(summary[k] for k in SUMMARY_KEYS) + (SOURCE,))
            self.connection.execute("""
                INSERT INTO collection_state (singleton, last_status, collected_at_utc)
                VALUES (1, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    last_status=excluded.last_status, collected_at_utc=excluded.collected_at_utc
                """, (status, collected_at_utc))

    def operational_status(self):
        row = self.connection.execute(
            "SELECT last_status, collected_at_utc FROM collection_state WHERE singleton=1").fetchone()
        status = row[0] if row and row[0] in COLLECTION_STATUSES else ("invalid_response" if row else None)
        return dict(status=status or "ready", source=SOURCE, count=self.count(),
                    last_collection_status=status,
                    last_collection_time_utc=_utc_timestamp(row[1]) if row else None)

    def latest(self):
        row = self.connection.execute("""
            SELECT start_time_utc, activity_type, duration_ms, distance_m, training_load
            FROM activities ORDER BY start_time_utc DESC, activity_type DESC LIMIT 1
            """).fetchone()
        if row is None:
            return dict(status="empty", source=SOURCE, summary=None)
        summary = normalize_summary(dict(zip(SUMMARY_KEYS, row)))
        if summary["start_time_utc"] is None or summary["activity_type"] is None:
            return dict(status="partial", source=SOURCE, summary=None)
        return dict(status="partial" if any(v is None for v in summary.values()) else "ok",
                    source=SOURCE, summary=summary)


def init_state(state_dir=DEFAULT_STATE_DIR):
    with Store(state_dir, create=True) as store:
        return dict(status="initialized", source=SOURCE, count=store.count())


def collect_once(state_dir=DEFAULT_STATE_DIR, auth_file=None, *, lookback_days=30):
    if type(lookback_days) is not int or not 1 <= lookback_days <= 30:
        raise InvalidArguments()
    now = datetime.now(timezone.utc)
    collected_at = now.isoformat()
    headers = load_auth(auth_file if auth_file is not None else Path(state_dir) / "auth.json")
    payload = dict(status="reauth_required" if headers is None else "storage_error",
                   source=SOURCE, stored=False, collected_at_utc=collected_at)
    try:
        with Store(state_dir, create=True) as store:
            status, summary = "reauth_required", None
            if headers is not None:
                # Integer subtraction keeps even a 30-day window within the
                # collector's exact millisecond bound; the end is actual UTC now.
                end_ms = int(now.timestamp() * 1000)
                start_ms = end_ms - lookback_days * 86400 * 1000
                try:
                    transport = collector.OfficialTransport(network_authorized=True)
                    result = collector.latest(transport, str(start_ms), str(end_ms),
                                              lambda: headers, dry_run=False)
                    status = result.status if result.status in COLLECTION_STATUSES else "invalid_response"
                    if status in ("ok", "partial"):
                        summary = normalize_summary(result.summary)
                        if any(v is None for v in summary.values()):
                            status = "partial"
                        if summary["start_time_utc"] is None or summary["activity_type"] is None:
                            summary = None
                except Exception:
                    status = "transport_error"
            store.record(status, collected_at, summary)
            payload.update(status=status, stored=summary is not None)
    except Exception:
        # Preserve an explicit reauth_required even if its local status marker
        # cannot be saved. No HTTP was attempted for unsafe/missing credentials.
        payload["storage_status"] = "storage_error"
        if headers is not None:
            payload["status"] = "storage_error"
        payload["stored"] = False
    return payload


def read_status(state_dir=DEFAULT_STATE_DIR):
    try:
        with Store(state_dir) as store:
            return store.operational_status()
    except NotInitialized:
        return dict(status="not_initialized", source=SOURCE, count=0,
                    last_collection_status=None, last_collection_time_utc=None)


def read_latest(state_dir=DEFAULT_STATE_DIR):
    try:
        with Store(state_dir) as store:
            return store.latest()
    except NotInitialized:
        return dict(status="not_initialized", source=SOURCE, summary=None)


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal message can echo an arbitrary secret-bearing value.
        raise InvalidArguments()


def _lookback(value):
    try:
        days = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("invalid_lookback") from None
    if not 1 <= days <= 30:
        raise argparse.ArgumentTypeError("invalid_lookback")
    return days


def build_parser():
    common = SafeArgumentParser(add_help=False)
    common.add_argument("--state-dir", default=argparse.SUPPRESS,
                        help="private directory (default: /var/lib/huawei-training-camp)")
    common.add_argument("--auth-file", default=argparse.SUPPRESS,
                        help="private auth JSON (default: STATE_DIR/auth.json; collect only)")
    parser = SafeArgumentParser(description=__doc__, parents=[common])
    # Do not set shared action defaults: subparsers would then overwrite
    # explicit options placed before the command with production defaults.
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "collect", "status", "latest"):
        command = commands.add_parser(name, parents=[common])
        if name == "collect":
            command.add_argument("--lookback-days", type=_lookback, default=30,
                                 help="query window 1..30 days, ending at actual UTC now (default: 30)")
    return parser


def main(argv=None):
    try:
        args = build_parser().parse_args(argv, namespace=argparse.Namespace(
            state_dir=str(DEFAULT_STATE_DIR), auth_file=None))
        if args.command == "init":
            payload = init_state(args.state_dir)
        elif args.command == "collect":
            payload = collect_once(args.state_dir, args.auth_file, lookback_days=args.lookback_days)
        elif args.command == "status":
            payload = read_status(args.state_dir)
        else:
            payload = read_latest(args.state_dir)
    except InvalidArguments:
        payload = dict(status="invalid_arguments")
    except (StorageError, OSError, sqlite3.Error):
        payload = dict(status="storage_error", source=SOURCE)
    except Exception:
        payload = dict(status="internal_error", source=SOURCE)
    print(json.dumps(payload, allow_nan=False, sort_keys=True))
    status = payload["status"]
    if status == "reauth_required":
        return 3
    if status == "invalid_arguments":
        return 2
    return 0 if status in ("initialized", "ready", "ok", "partial", "empty") else 1


if __name__ == "__main__":
    raise SystemExit(main())
