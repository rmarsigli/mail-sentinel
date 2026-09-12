"""The three v1 signals. Pure functions over the state dict; no I/O.

Severity order matters for the email and for dedup keys; keep the tuple below
as the single source of truth.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from sentinel.config import Config
from sentinel.state import history_hours, is_suppressed
from sentinel.window import (account_totals, all_accounts_in_window, all_ips_in_window, hour_key,
                             hourly_mean, ip_totals, sends_for_hour)

SEVERITY_ORDER = ("critical", "high", "medium")
BASELINE_HOURS = 168  # 7 days

# cPanel authenticates its own services as __cpanel__service__auth__<svc>__<token>.
# That identity is not a mailbox the operator can open, and the token is
# regenerated, so it is not a stable key for [overrides] either. The
# account-keyed signals skip it; the IP-keyed one does not, so a brute force
# aimed at these names is still counted and reported in full.
SERVICE_IDENTITY_PREFIX = "__cpanel__"


def is_service_identity(account: str) -> bool:
    return bool(account) and account.startswith(SERVICE_IDENTITY_PREFIX)


@dataclass
class Alert:
    signal: str
    severity: str
    subject: str
    count: int
    details: Dict = field(default_factory=dict)
    key: str = ""


def _top(counter: Dict[str, int], n: int) -> List[list]:
    return [[k, v] for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]


def brute_force_alerts(state: dict, cfg: Config, now: datetime) -> List[Alert]:
    since = now - timedelta(minutes=cfg.brute_force.window_minutes)
    day_ago = now - timedelta(hours=24)
    out = []
    for ip in sorted(all_ips_in_window(state, since, now)):
        recent = ip_totals(state, ip, since, now)
        if recent["fail"] < cfg.brute_force.min_failures:
            continue
        if ip_totals(state, ip, day_ago, now)["ok"] > 0:
            continue  # a real user with a stale password somewhere; different signal
        out.append(Alert("brute_force", "high", ip, recent["fail"], {
            "accounts_targeted": len(recent["accounts"]),
            "top_accounts": _top(recent["accounts"], 5),
            "first": recent["first"], "last": recent["last"],
            "window_minutes": cfg.brute_force.window_minutes,
        }, "brute_force:%s" % ip))
    return out


def locked_out_alerts(state: dict, cfg: Config, now: datetime) -> List[Alert]:
    since = now - timedelta(minutes=cfg.locked_out.window_minutes)
    day_ago = now - timedelta(hours=24)
    out = []
    for account in sorted(all_accounts_in_window(state, since, now)):
        if is_service_identity(account):
            continue
        recent = account_totals(state, account, since, now)
        if recent["fail"] < cfg.locked_out.min_failures:
            continue
        if account_totals(state, account, day_ago, now)["ok"] > 0:
            continue
        out.append(Alert("locked_out", "medium", account, recent["fail"], {
            "source_ips": len(recent["ips"]),
            "top_ips": _top(recent["ips"], 3),
            "first": recent["first"], "last": recent["last"],
            "window_minutes": cfg.locked_out.window_minutes,
        }, "locked_out:%s" % account))
    return out


def abnormal_sending_alerts(state: dict, cfg: Config, now: datetime) -> List[Alert]:
    hour = hour_key(now - timedelta(hours=1))  # the hour that just closed
    history = history_hours(state, now)
    out = []
    for account, rec in sorted(sends_for_hour(state, hour).items()):
        if is_service_identity(account):
            continue
        thresholds = cfg.sending_for(account)
        mean = hourly_mean(state, account, hour, BASELINE_HOURS)
        rule = None
        threshold = float(thresholds.ceiling_per_hour)
        if rec["count"] > thresholds.ceiling_per_hour:
            rule = "ceiling"
        elif (history >= thresholds.baseline_min_hours and mean >= thresholds.baseline_floor
              and rec["count"] > thresholds.baseline_multiplier * mean):
            rule, threshold = "baseline", thresholds.baseline_multiplier * mean
        if rule is None:
            continue
        out.append(Alert("abnormal_sending", "critical", account, rec["count"], {
            "hour": hour, "rule": rule, "threshold": threshold, "mean_7d": mean,
            "top_ips": _top(rec["ips"], 3),
        }, "abnormal_sending:%s:%s" % (account, hour)))
    return out


def evaluate(state: dict, cfg: Config, now: datetime) -> List[Alert]:
    alerts = abnormal_sending_alerts(state, cfg, now) + brute_force_alerts(state, cfg, now) \
        + locked_out_alerts(state, cfg, now)
    alerts.sort(key=lambda a: (SEVERITY_ORDER.index(a.severity), a.subject))
    return alerts


def suppression_hours(alert: Alert, cfg: Config) -> int:
    if alert.signal == "brute_force":
        return cfg.dedup.brute_force_hours
    if alert.signal == "locked_out":
        return cfg.dedup.locked_out_hours
    return 0  # abnormal_sending carries the hour in its key; a new hour is a new alert


def dedup(alerts: List[Alert], state: dict, cfg: Config, now: datetime) -> Tuple[List[Alert], int]:
    kept, suppressed = [], 0
    for alert in alerts:
        hours = suppression_hours(alert, cfg)
        # hours == 0 means "never repeat the same key": any prior send suppresses.
        if is_suppressed(state, alert.key, now, hours if hours else 10 ** 6):
            suppressed += 1
        else:
            kept.append(alert)
    return kept, suppressed
