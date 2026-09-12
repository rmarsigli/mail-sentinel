# Install

Everything runs as root on the mail server. Nothing is installed system-wide and nothing comes from pip; the tree lives in `/opt/mail-sentinel`.

1. Copy the repository to the server, then make root own it:

       rsync -a --exclude .git --exclude tests --exclude local --exclude __pycache__ \
             ./ root@mx1.example.com:/opt/mail-sentinel/
       ssh root@mx1.example.com 'chown -R root:root /opt/mail-sentinel && chmod -R go-w /opt/mail-sentinel'

   Both details matter. `--exclude .git` keeps the repository history off a production mail server. The `chown` is not cosmetic: `rsync -a` preserves the numeric uid from your workstation, so without it the tree that cron executes as root ends up owned by whatever local user id you happen to have. On cPanel that id gets handed to the next account created, which would give that account write access to code running as root.

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

   Some providers restrict API access to an allowlist of source IPs. If `test-delivery` returns HTTP 401 naming your server address, authorise it in the provider dashboard and run the command again. Keep this in mind for later: if the server ever changes IP, delivery stops. It stops loudly, with exit code 3 and mail to root, but it stops.

5. Do one dry run and read it. The first run reads the whole current log files, which is intended and gives you a one-time baseline:

       python3 /opt/mail-sentinel/mail-sentinel.py run --dry-run

   Alerts go to stdout and the run summary to stderr, so `run --dry-run > alerts.txt` keeps the two apart. Read every alert. On a server that has been running for a while the first dry run usually surfaces accounts that have been failing for months, which is the point rather than a defect.

6. Install the cron file and watch two cycles:

       cp /opt/mail-sentinel/cron.d/mail-sentinel /etc/cron.d/mail-sentinel
       chmod 0644 /etc/cron.d/mail-sentinel
       tail -f /var/log/mail-sentinel.log

   The second cycle is the one that proves deduplication: it should report `suppressed` greater than zero and `sent=0` for alerts already delivered in the first.

7. `python3 /opt/mail-sentinel/mail-sentinel.py status` shows the effective config with the key redacted, the age of the state file and the last run summary.

## Uninstall

    rm /etc/cron.d/mail-sentinel
    rm -rf /opt/mail-sentinel /var/lib/mail-sentinel /etc/mail-sentinel /var/log/mail-sentinel.log

## Tuning

Start with the defaults for a week, then read `/var/log/mail-sentinel.log`. If `raised` is high and you have started ignoring the emails, raise the thresholds. If something got compromised and the tool stayed quiet, lower them. Per-account sending overrides go in `[overrides]`, which is where the newsletter address that legitimately sends in bursts belongs.

One subtlety worth knowing before you tune. Counting happens over fixed time buckets of fifteen minutes, and a window includes the whole bucket its start falls into. A "15 minute" window therefore sweeps between 15 and 30 minutes of history, and the 60 minute window sweeps between 60 and 75. Counts are always equal to or higher than a literal reading of the threshold, so the tool alerts slightly earlier than the numbers suggest and never later. Read `min_failures` as "within the last one to two windows".

If you change how often cron runs, change `brute_force.window_minutes` to match. The rule only evaluates the window ending now, so running hourly while leaving the window at fifteen minutes leaves the brute force signal blind for forty five minutes of every hour.
