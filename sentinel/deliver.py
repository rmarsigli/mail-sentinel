"""Format one email per cycle and push it through Brevo or Resend.

Plain text only, and nothing from user mail (subjects, bodies, recipients)
ever reaches an alert: accounts, IPs, counts and timestamps are all it takes
to act, and all we are allowed to leak.
"""
import json
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Callable, List, Optional

from sentinel import __version__
from sentinel.config import Config
from sentinel.rules import SEVERITY_ORDER, Alert

TIMEOUT_SECONDS = 20
RETRY_DELAY_SECONDS = 5
# Both provider APIs sit behind Cloudflare, which answers urllib's default agent
# with HTTP 403 (error 1010) on some endpoints. Identify the client so a bot filter
# never silences the alerts.
USER_AGENT = "mail-sentinel/%s (+https://github.com/rmarsigli/mail-sentinel)" % __version__

_PROVIDERS = {
    "brevo": {"url": "https://api.brevo.com/v3/smtp/email", "ok": 201},
    "resend": {"url": "https://api.resend.com/emails", "ok": 200},
}


class DeliveryError(Exception):
    pass


def read_api_key(path: str) -> str:
    with open(path) as fh:
        key = fh.read().strip()
    if not key:
        raise DeliveryError("api key file %s is empty" % path)
    return key


def format_subject(server_name: str, alerts: List[Alert]) -> str:
    n = len(alerts)
    highest = min(alerts, key=lambda a: SEVERITY_ORDER.index(a.severity)).severity
    return "[mail-sentinel %s] %d %s: %s" % (server_name, n, "alert" if n == 1 else "alerts", highest)


def _details(alert: Alert) -> List[str]:
    d = alert.details
    if alert.signal == "brute_force":
        return ["%d failed logins from %s in the last %d minutes, no successful login from it in 24 h"
                % (alert.count, alert.subject, d["window_minutes"]),
                "accounts targeted: %d" % d["accounts_targeted"],
                "top accounts: " + ", ".join("%s: %d" % (a, n) for a, n in d["top_accounts"]),
                "first %s, last %s" % (d["first"], d["last"])]
    if alert.signal == "locked_out":
        return ["%d failed logins for %s in the last %d minutes, no successful login in 24 h"
                % (alert.count, alert.subject, d["window_minutes"]),
                "source IPs: %d" % d["source_ips"],
                "top IPs: " + ", ".join("%s: %d" % (ip, n) for ip, n in d["top_ips"]),
                "first %s, last %s" % (d["first"], d["last"])]
    if alert.signal == "abnormal_sending":
        return ["%s sent %d messages in hour %s" % (alert.subject, alert.count, d["hour"]),
                "rule: %s %g (7-day hourly mean %.2f)" % (d["rule"], d["threshold"], d["mean_7d"]),
                "top source IPs: " + ", ".join("%s: %d" % (ip, n) for ip, n in d["top_ips"])]
    return []


def format_body(server_name: str, alerts: List[Alert], now: datetime) -> str:
    lines = ["mail-sentinel on %s, %s" % (server_name, now.strftime("%Y-%m-%d %H:%M")), ""]
    for alert in alerts:
        lines.append("%s %s %s %d" % (alert.severity, alert.signal, alert.subject, alert.count))
        lines.extend("  " + line for line in _details(alert))
        lines.append("")
    lines.append("This tool only reports. Blocking is up to cPHulk and you.")
    return "\n".join(lines)


def recipients_for(alerts: List[Alert], cfg: Config) -> List[str]:
    out = set()
    for alert in alerts:
        out.update(cfg.recipients.for_severity(alert.severity))
    return sorted(out)


def _build_request(cfg: Config, to: List[str], subject: str, body: str, api_key: str) -> urllib.request.Request:
    kind = cfg.provider.kind
    if kind == "brevo":
        payload = {"sender": {"email": cfg.provider.sender}, "to": [{"email": t} for t in to],
                   "subject": subject, "textContent": body}
        headers = {"api-key": api_key}
    else:
        payload = {"from": cfg.provider.sender, "to": list(to), "subject": subject, "text": body}
        headers = {"Authorization": "Bearer " + api_key}
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"
    headers["User-Agent"] = USER_AGENT
    return urllib.request.Request(_PROVIDERS[kind]["url"], data=json.dumps(payload).encode(),
                                  headers=headers, method="POST")


def send_email(cfg: Config, to: List[str], subject: str, body: str, api_key: str,
               opener: Optional[Callable] = None, sleep: Callable[[float], None] = time.sleep) -> int:
    opener = opener or urllib.request.urlopen
    expected = _PROVIDERS[cfg.provider.kind]["ok"]
    last_error = None
    for attempt in (1, 2):
        try:
            with opener(_build_request(cfg, to, subject, body, api_key), timeout=TIMEOUT_SECONDS) as resp:
                status = int(resp.status)
            if status != expected:
                raise DeliveryError("%s returned HTTP %d, expected %d" % (cfg.provider.kind, status, expected))
            return status
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            if 400 <= exc.code < 500:
                raise DeliveryError("%s rejected the message: HTTP %d %s" % (cfg.provider.kind, exc.code, detail))
            last_error = "HTTP %d %s" % (exc.code, detail)
        except urllib.error.URLError as exc:
            last_error = "connection error: %s" % exc.reason
        if attempt == 1:
            sleep(RETRY_DELAY_SECONDS)
    raise DeliveryError("%s unreachable after retry: %s" % (cfg.provider.kind, last_error))
