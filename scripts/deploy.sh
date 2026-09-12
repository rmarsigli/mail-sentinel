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

if [ "$apply" != "--apply" ]; then
    echo "== dry run against $host, nothing will be written =="
    rsync -an --delete --itemize-changes "${excludes[@]}" ./ "$host:/opt/mail-sentinel/"
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

rsync -a --delete "${excludes[@]}" ./ "$host:/opt/mail-sentinel/"

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
