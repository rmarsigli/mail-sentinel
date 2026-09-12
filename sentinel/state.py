"""Persist everything between cycles in one JSON file, written atomically.

A half-written state file after a crash would make the next cycle re-read
logs from zero and re-alert on everything; os.replace guarantees readers see
either the old file or the new one, never a torn one.
"""
import json
import os
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

STATE_VERSION = 1


def empty_state(now: datetime) -> dict:
    return {"version": STATE_VERSION, "meta": {"first_run": now.isoformat()},
            "offsets": {}, "auth": {}, "sends": {}, "sent": {}}


def load_state(path: str, now: datetime) -> Tuple[dict, Optional[str]]:
    if not os.path.exists(path):
        return empty_state(now), None
    try:
        with open(path) as fh:
            state = json.load(fh)
        if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
            raise ValueError("unexpected state layout")
        for key in ("meta", "offsets", "auth", "sends", "sent"):
            state.setdefault(key, {} if key != "meta" else {"first_run": now.isoformat()})
        return state, None
    except (ValueError, OSError) as exc:
        quarantine = "%s.corrupt-%s" % (path, now.strftime("%Y%m%d%H%M%S"))
        os.replace(path, quarantine)
        return empty_state(now), "state file corrupt (%s); moved to %s and started empty" % (exc, quarantine)


def save_state(path: str, state: dict) -> None:
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh, separators=(",", ":"), sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def history_hours(state: dict, now: datetime) -> float:
    first = datetime.fromisoformat(state["meta"]["first_run"])
    return (now - first).total_seconds() / 3600.0


def is_suppressed(state: dict, key: str, now: datetime, hours: int) -> bool:
    stamp = state.get("sent", {}).get(key)
    if not stamp:
        return False
    return now - datetime.fromisoformat(stamp) < timedelta(hours=hours)


def mark_sent(state: dict, keys: List[str], now: datetime) -> None:
    for key in keys:
        state.setdefault("sent", {})[key] = now.isoformat()


def prune_sent(state: dict, now: datetime, max_hours: int) -> None:
    cutoff = now - timedelta(hours=max_hours)
    sent = state.get("sent", {})
    for key in [k for k, v in sent.items() if datetime.fromisoformat(v) < cutoff]:
        del sent[key]
