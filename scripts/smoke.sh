#!/usr/bin/env bash
# Local smoke test: run the whole suite and a dry run against the fixtures.
set -euo pipefail
cd "$(dirname "$0")/.."
# Override to prove the suite on the interpreter the server actually runs.
PY="${PYTHON:-python3}"
"$PY" -m unittest discover -s tests
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf 'fake-key\n' > "$tmp/api.key"; chmod 0600 "$tmp/api.key"
cat > "$tmp/config.ini" <<CONF
[server]
name = smoke.example.com
maillog = tests/fixtures/maillog.log
exim_mainlog = tests/fixtures/exim_mainlog.log
state_dir = $tmp/state
log_file = $tmp/sentinel.log
[provider]
kind = brevo
api_key_file = $tmp/api.key
from = alerts@example.com
[recipients]
critical = ops@example.com
high = ops@example.com
medium = ops@example.com
[brute_force]
min_failures = 3
CONF
chmod 0600 "$tmp/config.ini"
"$PY" mail-sentinel.py --config "$tmp/config.ini" --now 2026-09-11T20:30:00 run --dry-run

# The wrapper is the only shell that runs in production, so prove it here: the
# ping must carry the tool's exit code, must not happen without a URL file, and
# must never change the status cron sees.
stub="$tmp/stub"; mkdir -p "$stub"
cat > "$stub/fake-python" <<'STUB'
#!/bin/sh
exit "${STUB_RC:-0}"
STUB
cat > "$stub/curl" <<'STUB'
#!/bin/sh
for arg in "$@"; do case "$arg" in http*) printf '%s\n' "$arg" >> "$CURL_LOG";; esac; done
sed -n 's/^url = "\(.*\)"$/\1/p' >> "$CURL_LOG"
STUB
chmod +x "$stub/fake-python" "$stub/curl"

check_wrapper() {  # exit code, heartbeat on/off, expected ping
    CURL_LOG="$tmp/curl.log"; export CURL_LOG; : > "$CURL_LOG"
    if [ "$2" = on ]; then printf 'https://example/ping\n' > "$tmp/hb.url"; else rm -f "$tmp/hb.url"; fi
    set +e
    PATH="$stub:$PATH" PYTHON="$stub/fake-python" HEARTBEAT_URL_FILE="$tmp/hb.url" \
        STUB_RC="$1" scripts/run-cycle.sh
    got=$?
    set -e
    [ "$got" = "$1" ] || { echo "wrapper: exit $got, expected $1"; exit 1; }
    ping=$(cat "$CURL_LOG"); [ -n "$ping" ] || ping="-"
    [ "$ping" = "$3" ] || { echo "wrapper: pinged '$ping', expected '$3'"; exit 1; }
}
check_wrapper 0 on  https://example/ping/0
check_wrapper 3 on  https://example/ping/3
check_wrapper 0 off -
check_wrapper 3 off -
echo "wrapper ok"

# The CI lints this shell; run the same check here when the tool is around, so a
# finding shows up before a push rather than in a red build.
if command -v shellcheck > /dev/null; then
    shellcheck scripts/*.sh
    echo "shellcheck ok"
else
    echo "shellcheck not installed, skipped"
fi

echo "smoke ok"
