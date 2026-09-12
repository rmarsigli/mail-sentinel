#!/usr/bin/env bash
# Refuse to publish anything that belongs in /etc/mail-sentinel or in local/.
#
# This project keeps every deployment-specific value out of the tree on purpose:
# the provider key, the recipient lists, the heartbeat URL. A key has already
# been leaked once in this project's history, so the rule gets a guard rather
# than a paragraph in a README.
set -euo pipefail
cd "$(dirname "$0")/.."

self=scripts/check-no-secrets.sh
fail=0
report() { printf 'leak: %s\n' "$1" >&2; fail=1; }

# 1. Files that must never be tracked at all.
while IFS= read -r path; do
    [ -z "$path" ] && continue
    report "tracked file that must stay local: $path"
done < <(git ls-files -- 'local/*' '*.key' '*.env' 'config.ini')

# 2. Strings that only exist in a real deployment. The guard excludes itself,
#    otherwise the patterns below would match this file.
scan() {  # description, extended regex
    if git grep -nIE "$2" -- . ":(exclude)$self" >&2; then
        report "$1"
    fi
}
# Patterns are deliberately narrow. A guard that cries wolf is a guard someone
# disables: "re_" followed by sixteen word characters matches half the test
# names in this repository, so the Resend pattern forbids the underscores that
# snake_case is made of and demands a key-length run.
scan "provider API key"   'xkeysib-[A-Za-z0-9]{32,}|\bre_[A-Za-z0-9]{24,}\b'
scan "heartbeat ping URL" '(hc-ping\.com|/ping)/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-'

if [ "$fail" -ne 0 ]; then
    echo "check-no-secrets: failed" >&2
    exit 1
fi
echo "check-no-secrets: clean"
