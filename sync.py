"""One scheduled read-only collection cycle; no health values enter logs.

Authentication failure pauses further network calls until auth.json changes.
No retry, password login, token guessing or external health-data forwarding.
"""
from __future__ import annotations

import fcntl
import json
import os
import stat
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import app
import sleep_collector

SUCCESS = {"ok", "partial", "empty"}


def read_state(path):
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 32768:
            return {}
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_state(path, payload):
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise app.StorageError()
    temp = path.with_name(".sync-" + uuid.uuid4().hex + ".json")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(payload, out, sort_keys=True, allow_nan=False)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def run_once(state_dir=app.DEFAULT_STATE_DIR):
    state_dir = Path(state_dir)
    with app.Store(state_dir, create=True):
        pass
    lock_path = state_dir / "sync.lock"
    fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        os.close(fd)
        raise app.StorageError()
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return dict(status="already_running", network_attempted=False), 0
        path = state_dir / "sync-status.json"
        previous = read_state(path)
        auth = state_dir / "auth.json"
        try:
            auth_mtime = auth.lstat().st_mtime_ns
        except FileNotFoundError:
            auth_mtime = None
        report = dict(source=app.SOURCE, checked_at_utc=datetime.now(timezone.utc).isoformat(),
                      auth_mtime_ns=auth_mtime, authentication_required=False)
        if previous.get("authentication_required") is True and previous.get("auth_mtime_ns") == auth_mtime:
            report.update(status="reauth_required", authentication_required=True, network_attempted=False,
                          last_success_time_utc=previous.get("last_success_time_utc"))
            write_state(path, report)
            return report, 3
        activity = app.collect_once(state_dir, lookback_days=30)
        report["activity"] = activity
        if activity["status"] == "reauth_required":
            report.update(status="reauth_required", authentication_required=True,
                          last_success_time_utc=previous.get("last_success_time_utc"))
            write_state(path, report)
            return report, 3
        sleep = sleep_collector.collect_once(state_dir, days=7)
        report["sleep"] = sleep
        if sleep["status"] == "reauth_required":
            report.update(status="reauth_required", authentication_required=True)
            code = 3
        elif activity["status"] in SUCCESS and sleep["status"] in SUCCESS:
            report.update(status="ok", last_success_time_utc=report["checked_at_utc"])
            code = 0
        else:
            report.update(status="collection_error", last_success_time_utc=previous.get("last_success_time_utc"))
            code = 1
        write_state(path, report)
        return report, code
    finally:
        os.close(fd)


def main():
    try:
        report, code = run_once()
    except Exception:
        report, code = dict(source=app.SOURCE, status="storage_error"), 1
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
