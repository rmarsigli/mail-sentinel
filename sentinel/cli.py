"""Command line: run, run --dry-run, test-delivery, status.

Exit codes are part of the contract, one number per failure class (1 config,
2 log access, 3 delivery, 4 internal). cron does not mail on the exit code, it
mails on output, so anything that sets a non-zero code also writes to stderr.
"""
import argparse
import fcntl
import os
import sys
import time
import traceback
from datetime import datetime, timedelta
from typing import Callable, List, Tuple

from sentinel import __version__
from sentinel.config import Config, ConfigError, load_config
from sentinel.deliver import (DeliveryError, format_body, format_subject, read_api_key,
                              recipients_for, send_email)
from sentinel.parse import parse_line
from sentinel.rules import dedup, evaluate
from sentinel.state import load_state, mark_sent, prune_sent, save_state
from sentinel.tail import read_new
from sentinel.window import add_event, prune

EXIT_OK, EXIT_CONFIG, EXIT_LOGS, EXIT_DELIVERY, EXIT_INTERNAL = 0, 1, 2, 3, 4
FUTURE_TOLERANCE = timedelta(hours=1)
LOG_MODE = 0o640
STATE_DIR_MODE = 0o700


def _log(cfg: Config, message: str, stream=None, error: bool = False) -> None:
    line = "%s %s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message)
    try:
        # O_NOFOLLOW: never append through a symlink planted at the log path.
        # The resulting OSError is swallowed below like any other write failure.
        fd = os.open(cfg.server.log_file,
                     os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, LOG_MODE)
        with os.fdopen(fd, "a") as fh:
            fh.write(line)
    except OSError:
        pass
    if stream is not None:
        stream.write(line)
    elif error:
        # cron mails when the job writes something, not when it exits non-zero.
        # An error that only reaches the log file is an error nobody reads.
        sys.stderr.write(line)


def _sources(cfg: Config) -> List[Tuple[str, str]]:
    return [(cfg.server.maillog, "maillog"), (cfg.server.exim_mainlog, "exim")]


def run_cycle(cfg: Config, now: datetime, dry_run: bool, opener=None, sleep=time.sleep,
              stderr=None, stdout=None) -> Tuple[int, dict]:
    started = time.monotonic()
    os.makedirs(cfg.server.state_dir, mode=STATE_DIR_MODE, exist_ok=True)
    state_path = os.path.join(cfg.server.state_dir, "state.json")
    state, warning = load_state(state_path, now, quarantine=not dry_run)
    if warning:
        _log(cfg, "warning: " + warning, stderr, error=True)
    summary = {"lines": 0, "ignored": 0, "malformed": 0, "future_dropped": 0, "rotated": [],
               "events": {}, "raised": 0, "suppressed": 0, "sent": 0, "exit": EXIT_OK}

    for path, source in _sources(cfg):
        record = state["offsets"].setdefault(path, {})
        try:
            lines, rotated = read_new(path, record)
        except OSError as exc:
            _log(cfg, "error: cannot read %s: %s" % (path, exc), stderr, error=True)
            summary["exit"] = EXIT_LOGS
            continue
        if rotated:
            summary["rotated"].append(path)
        for line in lines:
            summary["lines"] += 1
            ev = parse_line(line, source, now, summary)
            if ev is None:
                summary["ignored"] += 1
                continue
            if ev.ts - now > FUTURE_TOLERANCE:
                summary["future_dropped"] += 1
                continue
            summary["events"][ev.kind] = summary["events"].get(ev.kind, 0) + ev.count
            add_event(state, ev)

    prune(state, now)
    prune_sent(state, now, max(cfg.dedup.brute_force_hours, cfg.dedup.locked_out_hours, 24 * 8))
    candidates = evaluate(state, cfg, now)
    alerts, suppressed = dedup(candidates, state, cfg, now)
    summary["raised"], summary["suppressed"] = len(candidates), suppressed

    # An alert whose severity has no recipient list would go out as "to": [],
    # which the provider rejects, and that rejection takes every other alert in
    # the same email with it. load_config rejects that config; this is the belt.
    deliverable, orphaned = [], []
    for alert in alerts:
        (deliverable if cfg.recipients.for_severity(alert.severity) else orphaned).append(alert)
    if orphaned:
        _log(cfg, "error: %d alert(s) not sent, no recipient configured for severity %s"
             % (len(orphaned), ", ".join(sorted({a.severity for a in orphaned}))), stderr, error=True)
        summary["exit"] = EXIT_CONFIG if summary["exit"] == EXIT_OK else summary["exit"]

    if dry_run:
        # The alerts are the operator's payload and belong on stdout; the run
        # summary is diagnostics and goes to stderr with every other log line.
        out = stdout or sys.stdout
        out.write(format_body(cfg.server.name, alerts, now) + "\n" if alerts else "no alerts\n")
    elif deliverable:
        try:
            api_key = read_api_key(cfg.provider.api_key_file)
            send_email(cfg, recipients_for(deliverable, cfg), format_subject(cfg.server.name, deliverable),
                       format_body(cfg.server.name, deliverable, now), api_key, opener=opener, sleep=sleep)
            mark_sent(state, [a.key for a in deliverable], now)
            summary["sent"] = len(deliverable)
        except (DeliveryError, OSError) as exc:
            _log(cfg, "error: delivery failed: %s" % exc, stderr, error=True)
            summary["exit"] = EXIT_DELIVERY if summary["exit"] == EXIT_OK else summary["exit"]

    if not dry_run:
        save_state(state_path, state)
    summary["seconds"] = round(time.monotonic() - started, 2)
    _log(cfg, "run%s lines=%d ignored=%d malformed=%d future_dropped=%d rotated=%d events=%s raised=%d suppressed=%d sent=%d seconds=%s exit=%d"
         % (" (dry-run)" if dry_run else "", summary["lines"], summary["ignored"], summary["malformed"],
            summary["future_dropped"], len(summary["rotated"]),
            ",".join("%s:%d" % kv for kv in sorted(summary["events"].items())) or "-",
            summary["raised"], summary["suppressed"], summary["sent"], summary["seconds"], summary["exit"]), stderr)
    return summary["exit"], summary


def _with_lock(cfg: Config, fn: Callable[[], int], stderr) -> int:
    os.makedirs(cfg.server.state_dir, mode=STATE_DIR_MODE, exist_ok=True)
    lock_path = os.path.join(cfg.server.state_dir, "lock")
    # O_NOFOLLOW: a symlink at the lock path would let another user pick the
    # file root opens; refusing to run is better than writing where told.
    lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            _log(cfg, "previous cycle still running; skipping", stderr)
            return EXIT_OK
        return fn()


def cmd_test_delivery(cfg: Config, now: datetime, opener, sleep, stdout) -> int:
    to = sorted({r for s in ("critical", "high", "medium") for r in cfg.recipients.for_severity(s)})
    try:
        status = send_email(cfg, to, "[mail-sentinel %s] test message" % cfg.server.name,
                            "This is a test from mail-sentinel on %s at %s. If you can read this, "
                            "provider, sender domain and API key are correct." % (cfg.server.name, now.strftime("%Y-%m-%d %H:%M")),
                            read_api_key(cfg.provider.api_key_file), opener=opener, sleep=sleep)
    except (DeliveryError, OSError) as exc:
        stdout.write("delivery failed: %s\n" % exc)
        return EXIT_DELIVERY
    stdout.write("sent to %s (HTTP %d)\n" % (", ".join(to), status))
    return EXIT_OK


def cmd_status(cfg: Config, stdout) -> int:
    stdout.write("mail-sentinel %s\n\n%s\n\n" % (__version__, cfg.redacted()))
    state_path = os.path.join(cfg.server.state_dir, "state.json")
    if os.path.exists(state_path):
        age = time.time() - os.stat(state_path).st_mtime
        stdout.write("state: %s (updated %d min ago)\n" % (state_path, int(age // 60)))
    else:
        stdout.write("state: none yet\n")
    try:
        with open(cfg.server.log_file) as fh:
            lines = fh.read().strip().splitlines()
        stdout.write("last run: %s\n" % (lines[-1] if lines else "none"))
    except OSError:
        stdout.write("last run: no log file\n")
    return EXIT_OK


def main(argv: List[str], opener=None, sleep=time.sleep, stdout=None, stderr=None) -> int:
    stdout = stdout or sys.stdout
    parser = argparse.ArgumentParser(prog="mail-sentinel")
    parser.add_argument("--config", default="/etc/mail-sentinel/config.ini")
    parser.add_argument("--now", help="override the clock (ISO 8601); for tests")
    parser.add_argument("--no-permission-check", action="store_true", help="for tests only")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--dry-run", action="store_true")
    sub.add_parser("test-delivery")
    sub.add_parser("status")
    args = parser.parse_args(argv)

    now = datetime.fromisoformat(args.now) if args.now else datetime.now()
    try:
        cfg = load_config(args.config, check_permissions=not args.no_permission_check)
    except ConfigError as exc:
        (stderr or sys.stderr).write("config error: %s\n" % exc)
        return EXIT_CONFIG

    try:
        if args.command == "run":
            err_stream = stderr or (sys.stderr if args.dry_run else None)
            return _with_lock(cfg, lambda: run_cycle(cfg, now, args.dry_run, opener, sleep,
                                                     err_stream, stdout)[0], err_stream)
        if args.command == "test-delivery":
            return cmd_test_delivery(cfg, now, opener, sleep, stdout)
        return cmd_status(cfg, stdout)
    except Exception as exc:
        # Anything unexpected gets its own exit code and, above all, output:
        # a bare traceback with no log line leaves the operator guessing.
        _log(cfg, "error: unhandled %s: %s" % (type(exc).__name__, exc), stderr, error=True)
        traceback.print_exc(file=stderr or sys.stderr)
        return EXIT_INTERNAL
