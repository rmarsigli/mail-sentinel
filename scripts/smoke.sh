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
echo "smoke ok"
