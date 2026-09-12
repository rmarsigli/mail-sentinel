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


def load_state(path: str, now: datetime, quarantine: bool = True) -> Tuple[dict, Optional[str]]:
    """The state and a warning, or None. quarantine=False leaves the file alone.

    A dry-run is a diagnostic and must not be able to throw away the state a
    real cycle depends on.
    """
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
        if not quarantine:
            return empty_state(now), "state file corrupt (%s); left in place, a real run would quarantine it" % exc
        moved = "%s.corrupt-%s" % (path, now.strftime("%Y%m%d%H%M%S"))
        os.replace(path, moved)
        return empty_state(now), "state file corrupt (%s); moved to %s and started empty" % (exc, moved)


def save_state(path: str, state: dict) -> None:
    tmp = path + ".tmp"
    # Drop any leftover temporary first, then create it with O_EXCL|O_NOFOLLOW:
    # together they guarantee we are writing to a regular file we just created,
    # never through a symlink or hardlink somebody planted at that name. unlink
    # itself never follows a symlink, and if the name is re-planted between the
    # two calls the open fails instead of writing through it. fchmod works on
    # the descriptor we own, so the umask cannot leave the file looser than 0600
    # and no path lookup happens after the file exists.
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh, separators=(",", ":"), sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
        os.fchmod(fh.fileno(), 0o600)
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
