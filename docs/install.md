# Install

Everything runs as root on the mail server. Nothing is installed system-wide and nothing comes from pip; the tree lives in `/opt/mail-sentinel`.

1. Copy the repository to the server, then make root own it:

       rsync -a --delete --exclude .git --exclude tests --exclude local --exclude __pycache__ \
             --exclude 'CLAUDE.md' --exclude 'AGENTS.md' --exclude docs/decisions.md \
             ./ root@mx1.example.com:/opt/mail-sentinel/
       ssh root@mx1.example.com 'chown -R root:root /opt/mail-sentinel && chmod -R go-w /opt/mail-sentinel'

   Both details matter. `--exclude .git` keeps the repository history off a production mail server, and `--delete` keeps notes and scratch files from an earlier copy from lingering there. The `chown` is not cosmetic: `rsync -a` preserves the numeric uid from your workstation, so without it the tree that cron executes as root ends up owned by whatever local user id you happen to have. On cPanel that id gets handed to the next account created, which would give that account write access to code running as root.

2. Create the config and key, both readable only by root:

       install -d -m 0700 /etc/mail-sentinel
       cp /opt/mail-sentinel/config.example.ini /etc/mail-sentinel/config.ini
       chmod 0600 /etc/mail-sentinel/config.ini
       printf '%s\n' 'YOUR-API-KEY' > /etc/mail-sentinel/api.key
       chmod 0600 /etc/mail-sentinel/api.key

   Edit `config.ini` and set `server.name`, `provider.kind`, `provider.from` and the `[recipients]` lists. The sender must be on a domain you have verified with the provider, otherwise the provider accepts the call and the message never lands. The tool refuses to start if either file is not mode 0600.

   With Brevo, use an API key (the string starting with `xkeysib-`), not an SMTP key. Despite the `/v3/smtp/email` path, delivery is a REST call, not an SMTP session.

3. Check the recipient addresses actually exist before you send anything to them. A wrong address costs you a hard bounce, and hard bounces damage the sending reputation of the domain you will depend on later. For a mailbox on this same server:

       cut -d: -f1 /home/*/etc/example.com/shadow | grep -x alerts

4. Prove the provider works:

       python3 /opt/mail-sentinel/mail-sentinel.py test-delivery

   A `201` from Brevo or a `200` from Resend means the provider accepted the message, not that anyone received it. Confirm the message arrived in every recipient inbox before going further, spam folders included. Most providers also expose the delivery result through their API, which is a stronger answer than asking someone to look.

   Some providers restrict API access to an allowlist of source IPs. If `test-delivery` returns HTTP 401 naming your server address, authorise it in the provider dashboard and run the command again. Keep this in mind for later: if the server ever changes IP, delivery stops. It stops loudly, with exit code 3 and a line on stderr that cron turns into mail, but it stops.

5. Do one dry run and read it. The first run reads the whole current log files, which is intended and gives you a one-time baseline:

       python3 /opt/mail-sentinel/mail-sentinel.py run --dry-run

   Alerts go to stdout and the run summary to stderr, so `run --dry-run > alerts.txt` keeps the two apart. Read every alert. On a server that has been running for a while the first dry run usually surfaces accounts that have been failing for months, which is the point rather than a defect.

6. Install the cron file and watch two cycles:

       cp /opt/mail-sentinel/cron.d/mail-sentinel /etc/cron.d/mail-sentinel
       chmod 0644 /etc/cron.d/mail-sentinel
       tail -f /var/log/mail-sentinel.log

   The second cycle is the one that proves deduplication: it should report `suppressed` greater than zero and `sent=0` for alerts already delivered in the first.

   Set `MAILTO` in that file to an address someone reads. A clean cycle prints nothing, so cron stays silent; anything that fails writes to stderr and cron turns it into mail. `MAILTO=root` only works if root's mail is aliased somewhere a human looks, which on a fresh cPanel box it usually is not:

       grep -E '^root:' /etc/aliases

7. Optional, and the only thing that notices when the tool itself stops running. Every
   cycle can ping an external monitor; if the ping stops arriving, that monitor tells
   you. It is the only way a stopped cron, a removed `python3` or a dead host gets
   reported, because a process cannot announce its own death. The exit code rides on the
   URL, so a delivery failure also reaches a channel that does not depend on the local
   Exim.

   The cron file already carries the call. It does nothing until the URL file exists:

       printf '%s\n' 'https://example-monitor/ping/YOUR-UUID' > /etc/mail-sentinel/heartbeat.url
       chmod 0600 /etc/mail-sentinel/heartbeat.url

   Any heartbeat service that accepts `<url>/<exit-code>` works; healthchecks.io is one,
   and is self-hostable. Set the expected period to your cron interval and the grace to
   a little over twice it, so one missed cycle does not page you.

   The URL is a credential: anyone holding it can fake a heartbeat. That is why it lives
   in `/etc/mail-sentinel/` beside `api.key`, which the install steps never overwrite,
   and never in this repository.

   Prove it once, including the part everyone skips: comment the cron line out, wait
   past the grace period, confirm the alert fires, then restore it. A monitor you have
   never seen fire is a monitor you only believe you have.

8. Rotate the tool's own log, which nothing else rotates:

       cp /opt/mail-sentinel/logrotate.d/mail-sentinel /etc/logrotate.d/mail-sentinel
       chmod 0644 /etc/logrotate.d/mail-sentinel
       logrotate -d /etc/logrotate.d/mail-sentinel

9. `python3 /opt/mail-sentinel/mail-sentinel.py status` shows the effective config with the key redacted, the age of the state file and the last run summary.

Step 6 is safe to repeat on a later deploy: nothing in `cron.d/mail-sentinel` is specific
to one server. If you ever hand-edit the installed file anyway, `diff` it against the
repository copy before overwriting.

## Uninstall

    rm /etc/cron.d/mail-sentinel /etc/logrotate.d/mail-sentinel
    rm -rf /opt/mail-sentinel /var/lib/mail-sentinel /etc/mail-sentinel /var/log/mail-sentinel.log

`/etc/mail-sentinel` holds `heartbeat.url` too, so the monitor stops being pinged and
reports the tool as down. Delete the check on its dashboard as well.

## Tuning

Start with the defaults for a week, then read `/var/log/mail-sentinel.log`. If `raised` is high and you have started ignoring the emails, raise the thresholds. If something got compromised and the tool stayed quiet, lower them. Per-account sending overrides go in `[overrides]`, which is where the newsletter address that legitimately sends in bursts belongs.

One subtlety worth knowing before you tune. Counting happens over fixed time buckets of fifteen minutes, and a window includes the whole bucket its start falls into. A "15 minute" window therefore sweeps between 15 and 30 minutes of history, and the 60 minute window sweeps between 60 and 75. Counts are always equal to or higher than a literal reading of the threshold, so the tool alerts slightly earlier than the numbers suggest and never later. Read `min_failures` as "within the last one to two windows".

If you change how often cron runs, change `brute_force.window_minutes` to match. The rule only evaluates the window ending now, so running hourly while leaving the window at fifteen minutes leaves the brute force signal blind for forty five minutes of every hour.

The baseline half of the sending rule needs history. It stays off until `baseline_min_hours` have passed since the first run, and the mean it compares against is divided by the hours of history that actually exist, never by the full seven days. That matters because dividing three days of data by a seven day window understates the mean by up to 2.3x and fires `critical` at a bit over twice the normal rate instead of five times it.
