#!/bin/sh
# One cycle, then tell the optional heartbeat monitor how it went.
#
# This exists so the crontab holds a single command. Shell logic inside a
# crontab line is unreadable and carries a trap of its own: an unescaped % there
# is turned into a newline and everything after it is fed to the job as stdin.
#
# The ping is chained to the run on purpose, rather than being a second cron
# entry. A heartbeat on its own schedule would keep reporting "alive" while the
# tool is dead, which is the one thing it exists to prevent.
#
# No heartbeat URL file means no ping. That is the whole of the opt-in.
set -eu

PYTHON="${PYTHON:-/usr/bin/python3}"
HEARTBEAT_URL_FILE="${HEARTBEAT_URL_FILE:-/etc/mail-sentinel/heartbeat.url}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

set +e
"$PYTHON" "$ROOT/mail-sentinel.py" run "$@"
rc=$?
set -e

if [ -s "$HEARTBEAT_URL_FILE" ]; then
    # -f turns an HTTP error into a non-zero exit and -sS prints it, so a typo in
    # the URL or blocked egress shows up as cron output instead of silence.
    curl -fsS -m 10 "$(cat "$HEARTBEAT_URL_FILE")/$rc" > /dev/null || true
fi

exit "$rc"
