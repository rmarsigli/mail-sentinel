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


def parse_syslog_ts(text: str, now: datetime) -> datetime:
    m = _SYSLOG_TS.match(text + " ")
    if not m:
        raise ValueError("not a syslog timestamp: %r" % text)
    ts = datetime(now.year, _MONTHS[m.group("mon")], int(m.group("day")),
                  int(m.group("h")), int(m.group("m")), int(m.group("s")))
    # maillog carries no year; a line "from the future" was written last year.
    if ts - now > timedelta(days=1):
        ts = ts.replace(year=now.year - 1)
    return ts


def _exim_ts(line: str) -> Optional[datetime]:
    m = _EXIM_TS.match(line)
    if not m:
        return None
    return datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")


def parse_line(line: str, source: str, now: datetime) -> Optional[Event]:
    if source == "maillog":
        return _parse_maillog(line, now)
    if source == "exim":
        return _parse_exim(line)
    raise ValueError("unknown source %r" % source)


def _parse_maillog(line: str, now: datetime) -> Optional[Event]:
    if "-login: " not in line:
        return None
    m = _DOVECOT_OK.search(line)
    if m:
        return Event("login_ok", parse_syslog_ts(line, now), m.group("user"), m.group("ip"), 1)
    m = _DOVECOT_FAIL.search(line)
    if m:
        return Event("login_fail", parse_syslog_ts(line, now), m.group("user"), m.group("ip"), int(m.group("n")))
    return None


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
