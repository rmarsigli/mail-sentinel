#!/usr/bin/env bash
# Refuse to publish anything that belongs in /etc/mail-sentinel or in local/.
#
# This project keeps every deployment-specific value out of the tree on purpose:
# the provider key, the recipient lists, the heartbeat URL. A key has already
# been leaked once in this project's history, so the rule gets a guard rather
# than a paragraph in a README.
#
# The guard looks at the whole history, not just the checked-out tree: deleting
# a key in the next commit removes it from HEAD and leaves it in the clone
# everybody can download. It also never prints the text it matched, because it
# runs in Actions on a public repository and the log is the last place a live
# key should end up. File, line and the name of the finding are enough to go
# and look.
set -euo pipefail
cd "$(dirname "$0")/.."

self=scripts/check-no-secrets.sh
fail=0
report() { printf 'leak: %s\n' "$1" >&2; fail=1; }

# A shallow clone has no history to read, and a guard that quietly checked one
# commit while claiming to have checked them all is worse than no guard.
if [ "$(git rev-parse --is-shallow-repository)" = true ]; then
    echo "check-no-secrets: shallow clone, only the fetched commits are readable" >&2
    echo "                  (use actions/checkout with fetch-depth: 0)" >&2
fi

# 1. Files that must never be tracked at all, in the index or in any commit.
forbidden=('local/*' '*.key' '*.env' 'config.ini')
while IFS= read -r path; do
    [ -z "$path" ] && continue
    report "file that must stay local, tracked at: $path"
done < <(
    {
        git ls-files -- "${forbidden[@]}"
        git log --all --pretty=format: --name-only -- "${forbidden[@]}"
    } | sed '/^$/d' | sort -u
)

# 2. Strings that only exist in a real deployment. The guard excludes itself,
#    otherwise the patterns below would match this file, at every revision of it.
# Every commit reachable from every ref, in batches: the revisions have to sit
# in front of the "--", so they cannot be fed through xargs, and a long history
# must not reach the argument limit either. One git grep per batch keeps the
# whole sweep to a handful of processes.
grep_history() {  # extended regex
    local re=$1 rev
    local -a batch=()
    while IFS= read -r rev; do
        batch+=("$rev")
        if [ "${#batch[@]}" -ge 500 ]; then
            git grep -nIzE -e "$re" "${batch[@]}" -- . ":(exclude)$self" || true
            batch=()
        fi
    done < <(git rev-list --all)
    if [ "${#batch[@]}" -gt 0 ]; then
        git grep -nIzE -e "$re" "${batch[@]}" -- . ":(exclude)$self" || true
    fi
    return 0
}

scan() {  # description, extended regex
    local desc=$1 re=$2 hits
    # -z makes the output "location NUL line NUL text", so the location can be
    #  cut off the match without ever quoting the match itself; -I skips
    #  binaries.
    hits=$(
        {
            git grep -nIzE -e "$re" -- . ":(exclude)$self" || true
            grep_history "$re"
        } | awk -F '\0' 'NF >= 3 { print $1 " line " $2 }' | sort -u
    )
    [ -n "$hits" ] || return 0
    while IFS= read -r where; do
        report "$desc at $where"
    done <<< "$hits"
}
# Patterns are deliberately narrow. A guard that cries wolf is a guard someone
# disables. The Resend key has two shapes, "re_" plus one long run and the newer
# "re_<id>_<secret>"; both are anchored on \b, which is what keeps them off the
# snake_case identifiers in this tree. Every "re_" in this repository and in its
# history is preceded by a word character (require_key_file, store_true,
# test_..._are_dropped), so no \bre_ pattern can reach them, and the second
# shape still demands run lengths no identifier here comes close to.
scan "provider API key"   'xkeysib-[A-Za-z0-9]{32,}|\bre_[A-Za-z0-9]{24,}\b|\bre_[A-Za-z0-9]{6,}_[A-Za-z0-9]{16,}\b'
scan "heartbeat ping URL" '(hc-ping\.com|/ping)/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-'

if [ "$fail" -ne 0 ]; then
    echo "check-no-secrets: failed" >&2
    exit 1
fi
echo "check-no-secrets: clean, index and every commit"
