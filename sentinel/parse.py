"""Turn one log line into one Event, or None.

Only the four line shapes documented in the spec (section 4) are recognised.
Everything else is None on purpose: a parser that guesses produces counts
nobody can explain.

Parts of every line are written by whoever connected to the server: the attempted
username, the envelope sender, the HELO and the mail subject. Exim does not
escape any of them and cPanel ships helo_accept_junk_hosts unset to *, so an
attacker's free text can spell whatever shape a pattern demands. Anchoring alone
is not a defence, and it was not: a subject of
`x authenticator failed for [9.9.9.9]:1: 535 x (set_id=victim@domain)` used to
become a failed login for any account, from any address, for the price of one
email.

What nobody can do is delete the fields the daemon writes itself, so a forged
field always arrives as a second copy of one that is already there. Every shape
below is therefore accepted only when the fields it reads appear exactly once and
the line begins the way the daemon begins it. On a live server all 75 authenticated
sends, all 210 inbound messages and every login line carried exactly one of each.
"""
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

# The longest real line measured on a live cPanel server was 619 bytes. Anything
# far past that is someone probing, and is dropped before a regex ever sees it,
# which also caps how much backtracking a single line can buy.
MAX_LINE_BYTES = 2048

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}

_SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2}) ")
_EXIM_TS = re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2}) ")

# Everything from the daemon's own prefix onwards, so a second "imap-login:"
# hidden inside an attempted username cannot pose as the start of a line.
_DOVECOT_LINE = re.compile(
    r"^[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \S+ dovecot\[\d+\]: (?:imap|pop3)-login: (?P<event>.*)$")
# rip is pinned between the closing > of the username and lip, the field Dovecot
# always writes next, so a rip= spelled inside the username is not read.
_DOVECOT_TAIL = r"user=<(?P<user>[^>]*)>, method=[^,]*, rip=(?P<ip>[0-9a-fA-F.:]+), lip="
_DOVECOT_OK = re.compile(r"^Logged in: " + _DOVECOT_TAIL)
_DOVECOT_FAIL = re.compile(
    r"^Login aborted: [^<]*\(auth failed, (?P<n>\d+) attempts? in \d+ secs\)[^<]*" + _DOVECOT_TAIL)

# A client may HELO as a bare address literal, so the host part can itself hold
# brackets: `H=([169.254.137.108]) [125.160.204.110]:56651` is real traffic, ten
# lines of it on the server this was measured against. The leading .* is greedy
# on purpose, so the address literal read is the LAST one before the field that
# Exim always writes next, never one spelled earlier in a HELO. Between that
# literal and A= only well formed KEY=VALUE tokens are allowed, never a wildcard.
_EXIM_SEND = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S+ <= \S+ "
    r".*\[(?P<ip>[0-9a-fA-F.:]+)\]:\d+ "
    r"(?:[A-Za-z]+=\S* )*A=dovecot_[a-z0-9_]+:(?P<user>\S+) S=\d")
_EXIM_AUTH_FAIL = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} dovecot_[a-z0-9_]+ authenticator failed for "
    r".*\[(?P<ip>[0-9a-fA-F.:]+)\]:\d+: 535 [^(]*\(set_id=(?P<user>[^)]*)\)$")


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
    if not _EXIM_TS.match(line):
        return None
    try:
        return datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _duplicated(line: str, *needles: str) -> bool:
    """True when a field we are about to read appears more than once.

    An attacker can add a field to a line by spelling it in a subject or a HELO.
    An attacker cannot remove the one the daemon wrote, so a forgery is always a
    duplicate, and a duplicate is the one thing worth refusing. A field that is
    simply absent is not suspicious, it is a shape we do not handle, and those
    stay silent: counting them would bury the signal in Exim's own auth failures
    that carry no username at all.
    """
    return any(line.count(needle) > 1 for needle in needles)


def parse_line(line: str, source: str, now: datetime, stats: Optional[dict] = None) -> Optional[Event]:
    """One Event or None. `stats` collects counters the caller wants to report."""
    if len(line) > MAX_LINE_BYTES:
        _malformed(stats)
        return None
    if source == "maillog":
        return _parse_maillog(line, now, stats)
    if source == "exim":
        return _parse_exim(line, stats)
    raise ValueError("unknown source %r" % source)


def _malformed(stats: Optional[dict]) -> None:
    if stats is not None:
        stats["malformed"] = stats.get("malformed", 0) + 1


def _parse_maillog(line: str, now: datetime, stats: Optional[dict] = None) -> Optional[Event]:
    # managesieve-login and any other service Dovecot may grow are not handled
    # here on purpose, and must not be reported as unreadable.
    if "imap-login: " not in line and "pop3-login: " not in line:
        return None
    if _duplicated(line, "-login: ", "user=<"):
        _malformed(stats)
        return None
    head = _DOVECOT_LINE.match(line)
    if not head:
        # A login line whose prefix we cannot read: rsyslog is writing a
        # timestamp format, or Dovecot a program name, that we do not know.
        # Counted, because the alternative is going blind quietly.
        _malformed(stats)
        return None
    event = head.group("event")
    m = _DOVECOT_OK.match(event)
    kind, count = "login_ok", 1
    if not m:
        m = _DOVECOT_FAIL.match(event)
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


def _parse_exim(line: str, stats: Optional[dict] = None) -> Optional[Event]:
    ts = _exim_ts(line)
    if ts is None:
        return None
    if " authenticator failed for " in line:
        if _duplicated(line, " authenticator failed for ", "(set_id=", ": 535 "):
            _malformed(stats)
            return None
        m = _EXIM_AUTH_FAIL.match(line)
        return Event("login_fail", ts, m.group("user"), m.group("ip"), 1) if m else None
    if " <= " in line and " A=dovecot_" in line:
        if _duplicated(line, " <= ", " A=", " P=", " S="):
            _malformed(stats)
            return None
        m = _EXIM_SEND.match(line)
        return Event("send", ts, m.group("user"), m.group("ip"), 1) if m else None
    return None
