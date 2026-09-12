#!/usr/bin/env bash
# Deploy to a mail server from a workstation. Never from CI: see docs/install.md.
#
#   scripts/deploy.sh mega-model-mail          show what would change, touch nothing
#   scripts/deploy.sh mega-model-mail --apply  do it
set -euo pipefail
cd "$(dirname "$0")/.."

host=${1:-}
[ -n "$host" ] || { echo "usage: $0 <ssh-host> [--apply]" >&2; exit 2; }
apply=${2:-}

# Deployment-specific files live on the server, never in this tree; tests, notes
# and history have no business on a production mail server.
excludes=(--exclude .git --exclude tests --exclude local --exclude __pycache__
          --exclude .github --exclude 'CLAUDE.md' --exclude 'AGENTS.md')

# What is not tracked is not deployed, but it is worth a word: an api.key, a
# config.ini or a heartbeat.url left in the root is precisely the file this tree
# must never carry, and a source file forgotten before a commit would silently
# not reach the server.
if [ -n "$(git ls-files --others --exclude-standard)" ]; then
    {
        echo "note: these files are not tracked by git, so they will NOT be deployed:"
        git ls-files --others --exclude-standard | sed 's/^/        /'
    } >&2
fi

# rsync used to read the working directory, which meant anything sitting in it
# rode along to the server. It now copies the tracked files into a staging
# directory first and ships that, so an untracked key cannot be deployed by
# accident. The exclude list still applies to the staging directory, exactly as
# it did to the working one: it keeps tests and notes off the server and, as
# before, protects those paths on the server from --delete.
stage=$(mktemp -d)
list="$stage.files"
trap 'rm -rf "$stage" "$list"' EXIT
# A tracked file deleted in the working tree is not there to copy; skipping it
# keeps a dry run against a dirty tree readable instead of an rsync error.
git ls-files -z | while IFS= read -r -d '' f; do
    if [ -e "$f" ]; then printf '%s\0' "$f"; fi
done > "$list"
rsync -a --from0 --files-from="$list" ./ "$stage/"

if [ "$apply" != "--apply" ]; then
    echo "== dry run against $host, nothing will be written =="
    rsync -an --delete --itemize-changes "${excludes[@]}" "$stage/" "$host:/opt/mail-sentinel/"
    echo "== re-run with --apply to deploy =="
    exit 0
fi

# Refuse to ship what was never proven, or what is not committed.
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "working tree is dirty" >&2
    exit 1
fi
bash scripts/check-no-secrets.sh
bash scripts/smoke.sh > /dev/null && echo "suite and smoke: ok"

rsync -a --delete "${excludes[@]}" "$stage/" "$host:/opt/mail-sentinel/"

ssh "$host" 'bash -s' <<'REMOTE'
set -eu
chown -R root:root /opt/mail-sentinel
chmod -R go-w /opt/mail-sentinel
chmod 0755 /opt/mail-sentinel/scripts/*.sh
install -m 0644 -o root -g root /opt/mail-sentinel/cron.d/mail-sentinel /etc/cron.d/mail-sentinel
install -m 0644 -o root -g root /opt/mail-sentinel/logrotate.d/mail-sentinel /etc/logrotate.d/mail-sentinel
[ -d /var/lib/mail-sentinel ] && chmod 0700 /var/lib/mail-sentinel
[ -f /var/log/mail-sentinel.log ] && chmod 0640 /var/log/mail-sentinel.log
echo "== installed =="
diff /opt/mail-sentinel/cron.d/mail-sentinel /etc/cron.d/mail-sentinel && echo "cron: repo and /etc identical"
echo "== one cycle, exactly as cron runs it =="
/opt/mail-sentinel/scripts/run-cycle.sh
echo "cycle exit=$?"
tail -1 /var/log/mail-sentinel.log
REMOTE
echo "== deployed to $host =="
