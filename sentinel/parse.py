"""Turn one log line into one Event, or None.

Only the four line shapes documented in the spec (section 4) are recognised.
Everything else is None on purpose: a parser that guesses produces counts
nobody can explain.
"""
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}

_SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2}) ")
_EXIM_TS = re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2}) ")

_DOVECOT_OK = re.compile(
    r" (?:imap|pop3)-login: Logged in: user=<(?P<user>[^>]*)>.*?, rip=(?P<ip>[0-9a-fA-F.:]+)")
_DOVECOT_FAIL = re.compile(
    r" (?:imap|pop3)-login: Login aborted: .*?\(auth failed, (?P<n>\d+) attempts? in \d+ secs\).*?"
    r"user=<(?P<user>[^>]*)>.*?, rip=(?P<ip>[0-9a-fA-F.:]+)")
_EXIM_AUTH_FAIL = re.compile(
    r" authenticator failed for .*?\[(?P<ip>[0-9a-fA-F.:]+)\]:\d+: 535 .*?\(set_id=(?P<user>[^)]+)\)")
_EXIM_SEND = re.compile(
    r" <= \S+ .*?\[(?P<ip>[0-9a-fA-F.:]+)\]:\d+ .*? A=dovecot_[a-z]+:(?P<user>\S+) ")


@dataclass(frozen=True)
class Event:
    kind: str          # login_ok | login_fail | send
    ts: datetime
    account: Optional[str]
    ip: Optional[str]
    count: int = 1


def parse_syslog_ts(text: str, now: datetime) -> Optional[datetime]:
    """None for anything this function cannot turn into a date.

    It must never raise. A single line it chokes on would abort the cycle
    before the offsets are saved, so the same line is re-read and the same
    exception is raised every 15 minutes until logrotate carries it away.
    """
    m = _SYSLOG_TS.match(text + " ")
    if not m:
        return None
    try:
        ts = datetime(now.year, _MONTHS[m.group("mon")], int(m.group("day")),
                      int(m.group("h")), int(m.group("m")), int(m.group("s")))
        # maillog carries no year; a line "from the future" was written last year.
        if ts - now > timedelta(days=1):
            ts = ts.replace(year=now.year - 1)
    except (KeyError, ValueError):
        # Feb 29 read in a non-leap year, or a month abbreviation we do not know.
        return None
    return ts


def _exim_ts(line: str) -> Optional[datetime]:
    m = _EXIM_TS.match(line)
    if not m:
        return None
    return datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")


def parse_line(line: str, source: str, now: datetime, stats: Optional[dict] = None) -> Optional[Event]:
    """One Event or None. `stats` collects counters the caller wants to report."""
    if source == "maillog":
        return _parse_maillog(line, now, stats)
    if source == "exim":
        return _parse_exim(line)
    raise ValueError("unknown source %r" % source)


def _malformed(stats: Optional[dict]) -> None:
    if stats is not None:
        stats["malformed"] = stats.get("malformed", 0) + 1


def _parse_maillog(line: str, now: datetime, stats: Optional[dict] = None) -> Optional[Event]:
    if "-login: " not in line:
        return None
    m = _DOVECOT_OK.search(line)
    kind, count = "login_ok", 1
    if not m:
        m = _DOVECOT_FAIL.search(line)
        if not m:
            return None
        kind, count = "login_fail", int(m.group("n"))
    ts = parse_syslog_ts(line, now)
    if ts is None:
        # A login line we recognise but cannot date: rsyslog is writing a
        # timestamp format we do not read. Counted, never fatal.
        _malformed(stats)
        return None
    return Event(kind, ts, m.group("user"), m.group("ip"), count)


def _parse_exim(line: str) -> Optional[Event]:
    ts = _exim_ts(line)
    if ts is None:
        return None
    m = _EXIM_AUTH_FAIL.search(line)
    if m:
        return Event("login_fail", ts, m.group("user"), m.group("ip"), 1)
    m = _EXIM_SEND.search(line)
    if m:
        return Event("send", ts, m.group("user"), m.group("ip"), 1)
    return None
