"""Fold events into fixed time buckets held inside the state dict.

Two resolutions: 15-minute slots for authentication (kept 24 h) and hourly
buckets for sends (kept 7 days). Keys are ISO strings so the state stays
readable JSON and sorts lexically in time order.
"""
from datetime import datetime, timedelta
from typing import Dict

from sentinel.parse import Event

AUTH_RETENTION = timedelta(hours=24)
SENDS_RETENTION = timedelta(days=7)


def slot_key(ts: datetime) -> str:
    return "%s:%02d" % (ts.strftime("%Y-%m-%dT%H"), (ts.minute // 15) * 15)


def hour_key(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H")


def _clock(ts: datetime) -> str:
    return ts.strftime("%H:%M:%S")


def _touch(rec: dict, clock: str) -> None:
    if rec["first"] is None or clock < rec["first"]:
        rec["first"] = clock
    if rec["last"] is None or clock > rec["last"]:
        rec["last"] = clock


def _ip_rec(slot: dict, ip: str) -> dict:
    return slot["ip"].setdefault(ip, {"fail": 0, "ok": 0, "accounts": {}, "first": None, "last": None})


def _acct_rec(slot: dict, acct: str) -> dict:
    return slot["acct"].setdefault(acct, {"fail": 0, "ok": 0, "ips": {}, "first": None, "last": None})


def add_event(state: dict, ev: Event) -> None:
    if ev.kind == "send":
        hour = state.setdefault("sends", {}).setdefault(hour_key(ev.ts), {})
        rec = hour.setdefault(ev.account, {"count": 0, "ips": {}})
        rec["count"] += ev.count
        rec["ips"][ev.ip] = rec["ips"].get(ev.ip, 0) + ev.count
        return
    slot = state.setdefault("auth", {}).setdefault(slot_key(ev.ts), {"ip": {}, "acct": {}})
    clock = _clock(ev.ts)
    ip_rec = _ip_rec(slot, ev.ip)
    acct_rec = _acct_rec(slot, ev.account)
    if ev.kind == "login_ok":
        ip_rec["ok"] += ev.count
        acct_rec["ok"] += ev.count
    elif ev.kind == "login_fail":
        ip_rec["fail"] += ev.count
        ip_rec["accounts"][ev.account] = ip_rec["accounts"].get(ev.account, 0) + ev.count
        acct_rec["fail"] += ev.count
        acct_rec["ips"][ev.ip] = acct_rec["ips"].get(ev.ip, 0) + ev.count
    else:
        raise ValueError("unknown event kind %r" % ev.kind)
    _touch(ip_rec, clock)
    _touch(acct_rec, clock)


def prune(state: dict, now: datetime) -> None:
    auth_min = slot_key(now - AUTH_RETENTION)
    sends_min = hour_key(now - SENDS_RETENTION)
    for key in [k for k in state.get("auth", {}) if k < auth_min]:
        del state["auth"][key]
    for key in [k for k in state.get("sends", {}) if k < sends_min]:
        del state["sends"][key]


def _slots_between(state: dict, since: datetime, until: datetime):
    lo, hi = slot_key(since), slot_key(until)
    for key in sorted(state.get("auth", {})):
        if lo <= key <= hi:
            yield key, state["auth"][key]


def _merge_extremes(out: dict, key: str, rec: dict) -> None:
    # "<slot> <clock>" sorts correctly across slots and stays human-readable.
    if rec["first"] is not None:
        stamp = "%s %s" % (key, rec["first"])
        if out["first"] is None or stamp < out["first"]:
            out["first"] = stamp
    if rec["last"] is not None:
        stamp = "%s %s" % (key, rec["last"])
        if out["last"] is None or stamp > out["last"]:
            out["last"] = stamp


def ip_totals(state: dict, ip: str, since: datetime, until: datetime) -> dict:
    out = {"fail": 0, "ok": 0, "accounts": {}, "first": None, "last": None}
    for key, slot in _slots_between(state, since, until):
        rec = slot["ip"].get(ip)
        if not rec:
            continue
        out["fail"] += rec["fail"]
        out["ok"] += rec["ok"]
        for acct, n in rec["accounts"].items():
            out["accounts"][acct] = out["accounts"].get(acct, 0) + n
        _merge_extremes(out, key, rec)
    return out


def account_totals(state: dict, account: str, since: datetime, until: datetime) -> dict:
    out = {"fail": 0, "ok": 0, "ips": {}, "first": None, "last": None}
    for key, slot in _slots_between(state, since, until):
        rec = slot["acct"].get(account)
        if not rec:
            continue
        out["fail"] += rec["fail"]
        out["ok"] += rec["ok"]
        for ip, n in rec["ips"].items():
            out["ips"][ip] = out["ips"].get(ip, 0) + n
        _merge_extremes(out, key, rec)
    return out


def all_ips_in_window(state: dict, since: datetime, until: datetime) -> set:
    ips = set()
    for _, slot in _slots_between(state, since, until):
        ips.update(slot["ip"])
    return ips


def all_accounts_in_window(state: dict, since: datetime, until: datetime) -> set:
    accts = set()
    for _, slot in _slots_between(state, since, until):
        accts.update(slot["acct"])
    return accts


def sends_for_hour(state: dict, hour: str) -> Dict[str, dict]:
    return dict(state.get("sends", {}).get(hour, {}))


def hourly_mean(state: dict, account: str, end_hour: str, hours: int) -> float:
    """Mean sends per hour over the `hours` buckets strictly before end_hour."""
    end = datetime.strptime(end_hour, "%Y-%m-%dT%H")
    total = 0
    for h in range(1, hours + 1):
        key = hour_key(end - timedelta(hours=h))
        total += state.get("sends", {}).get(key, {}).get(account, {}).get("count", 0)
    return total / float(hours) if hours else 0.0
