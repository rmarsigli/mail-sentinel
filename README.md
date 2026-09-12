# mail-sentinel

Anomaly alerts for small cPanel mail servers. One Python script, run by cron every fifteen minutes, that reads the Dovecot and Exim logs already on the box and emails you when something is wrong. No agents, no database, no daemon, no dependencies beyond the Python 3.9 standard library.

cPHulk blocks brute force, and it does that well. What it does not do is tell you that `sales@` has collected four thousand failed logins this week, or that `intern@` started sending three hundred messages an hour at three in the morning. Everything needed to know both is already sitting in `/var/log/maillog` and `/var/log/exim_mainlog`. This reads it and tells you.

## What it detects

**Brute force** (severity `high`). An IP with at least 20 authentication failures in the last 15 minutes and zero successful logins in the last 24 hours. The "zero successes" clause is the important half: an IP with both failures and successes is a real person with a stale password on one device, which is a different problem with a different fix. Mixing the two is how alert email becomes email nobody reads.

**Locked-out account** (severity `medium`). An account with at least 10 failures in the last 60 minutes and no successful login in 24 hours. Usually a phone still trying an old password. Sometimes the early part of a takeover.

**Abnormal sending** (severity `critical`). An account that, in the hour that just closed, sent more than a hard ceiling (100 messages by default) or more than five times its own hourly average over the previous seven days. The baseline rule only applies once the tool has watched for 72 hours and the account's average is at least 2 messages an hour, so a mailbox that sends one message a week does not trip the multiplier on its third message. This is the signal that catches a hijacked mailbox.

Every threshold is a config key. Sending thresholds can be overridden per account, for the newsletter address that legitimately sends in bursts.

## What it will not do

It only reads and only alerts. It never blocks an IP, never suspends a mailbox, never edits Exim, Dovecot, cPHulk or firewall configuration. Two systems deciding independently to block things is how you lock out real users at two in the morning. Blocking stays cPHulk's job; this ends the silence around it.

Alerts leave through a transactional email API (Brevo or Resend) over HTTPS, not through the local Exim. That is deliberate: the day the mail server breaks is exactly the day the warning about it has to arrive anyway.

Nothing from your users' mail is read, stored or sent. Message subjects, bodies and recipients are never parsed beyond the account name, IP, timestamp and message count that an alert needs. The account names and IPs that do appear in an alert leave the server, through the provider you configured: if that matters to your data policy, it belongs in the contract with them.

Three blind spots worth knowing. Mail injected locally by PHP `mail()` or `sendmail` is not counted, so a compromised website sending spam through the web stack does not trip the sending signal. Password spraying, one or two attempts against many accounts from many addresses, reaches no threshold by design. And the tool watches only the mail logs: it says nothing about the web, SSH or FTP.

## What an alert looks like

One email per cycle, plain text, every alert that survived deduplication, ordered by severity. Subject line carries the server name and the worst severity in the batch.

```
[mail-sentinel mx1.example.com] 2 alerts: critical

mail-sentinel on mx1.example.com, 2026-09-11 21:30

critical abnormal_sending user@example.com 250
  user@example.com sent 250 messages in hour 2026-09-11T20
  rule: ceiling 100 (7-day hourly mean 1.50)
  top source IPs: 203.0.113.10: 250

high brute_force 203.0.113.99 40
  40 failed logins from 203.0.113.99 in the last 15 minutes, no successful login from it in 24 h
  accounts targeted: 3
  top accounts: b@example.com: 30, c@example.com: 10
  first 2026-09-11T20:15 20:16:01, last 2026-09-11T20:15 20:29:59

This tool only reports. Blocking is up to cPHulk and you.
```

The first line of each block is machine readable on purpose: `<severity> <signal> <subject> <count>`.

Repeats are suppressed. The same brute-forcing IP or the same locked-out account will not mail you again for 24 hours. An abnormal sending alert carries the hour in its deduplication key, so a new bad hour is a new alert and the same bad hour never repeats.

## Requirements

- cPanel with Dovecot 2.4 and Exim. Tested on cPanel 134, AlmaLinux 9, Dovecot 2.4, Exim 4.99. The Dovecot
  parser reads the 2.4 wording (`Logged in:`, `Login aborted:`); on 2.3 those lines are counted as ignored.
- Exim with `log_selector` including `+incoming_port`, which cPanel sets by default. Without it the send
  lines carry no port and the abnormal sending signal sees nothing.
- Python 3.9 or newer at `/usr/bin/python3`. Nothing from pip.
- Outbound HTTPS to `api.brevo.com` or `api.resend.com`.
- A Brevo or Resend account, an API key, and a sender address on a domain verified with that provider.
- Root, because `/var/log/maillog` is readable only by root.

## Install

Full steps in [docs/install.md](docs/install.md). The short version: copy the tree to `/opt/mail-sentinel`, write `/etc/mail-sentinel/config.ini` and `api.key` with mode 0600, prove delivery with `test-delivery`, read one `run --dry-run` before trusting it, then install `cron.d/mail-sentinel`.

## Configuration

A single INI file at `/etc/mail-sentinel/config.ini`, mode 0600. `config.example.ini` documents every key with its default. Unknown sections and unknown keys are rejected at startup, so a typo fails immediately instead of silently disabling a signal.

```ini
[server]
name = mx1.example.com

[provider]
kind = brevo
api_key_file = /etc/mail-sentinel/api.key
from = alerts@example.com

[recipients]
critical = ops@example.com, owner@example.com
high = ops@example.com
medium = ops@example.com

[overrides]
newsletter@example.com = ceiling_per_hour=2000
```

An alert goes to the recipient list of its own severity. There is no cascade to the lists below it. The API key lives in its own file, never in the config, and is read only at the moment of sending.

## Commands

```
mail-sentinel.py run                 one cycle: read, evaluate, deduplicate, send
mail-sentinel.py run --dry-run       print the alerts that would be sent, send nothing, keep the state
mail-sentinel.py test-delivery       send one message to every recipient and print the HTTP status
mail-sentinel.py status              effective config with the key redacted, state age, last run summary
```

Exit codes are part of the contract: 0 success, 1 config error, 2 log access error, 3 delivery failure, 4 anything unexpected.

cron does not mail on the exit code, it mails when the job writes something. So every failure also writes its line to stderr, and a clean cycle writes nothing at all. Set `MAILTO` in `/etc/cron.d/mail-sentinel` to an address someone actually reads.

## Heartbeat

The tool tells you when your mail server misbehaves. Nothing tells you when the tool
itself stops running, and a process cannot announce its own death: a stopped cron, a
`python3` removed by an upgrade or a host that is simply gone all fail by producing
nothing at all, which is indistinguishable from a quiet week.

So every cycle can report to an outside monitor. Write the ping URL and it starts; delete
the file and it stops.

```
printf '%s\n' 'https://example-monitor/ping/YOUR-UUID' > /etc/mail-sentinel/heartbeat.url
chmod 0600 /etc/mail-sentinel/heartbeat.url
```

The exit code of the cycle is appended to the URL, so the monitor learns both that the
tool ran and how it ended. That gives failures a second route out of the machine, one
that does not depend on the local Exim or on anyone reading root's mail. Any service
taking `<url>/<exit-code>` works; healthchecks.io is one, and can be self-hosted. Set the
period to the cron interval and the grace to a little over twice it.

Be precise about what a green heartbeat means: a mail-sentinel cycle finished recently.
It is not a health check for the server. Some machine failures do stop the ping, because
they stop the job, but the box can be up and the tool green while Exim refuses every
message. This watches the watcher, nothing more.

The ping is chained to the run inside `scripts/run-cycle.sh` rather than scheduled on its
own. A heartbeat with its own schedule would keep reporting that all is well while the
tool is dead, which is the single failure it exists to catch.

## How it works

Each cycle takes an exclusive lock, so a slow run is skipped rather than overlapped. It reads only what was appended to each log since the previous cycle, tracked by inode and byte offset, and restarts at zero when logrotate replaces the file. Parsed events are folded into time buckets held in a JSON state file: fifteen-minute slots kept for 24 hours for authentication, hourly buckets kept for seven days for sending. The rules read those buckets, never the files. State is written atomically, so a crash mid-write cannot leave a half file that would make the next cycle re-read everything and re-alert on all of it.

If delivery fails, nothing is marked as sent and the same alerts are evaluated again next cycle. A corrupt state file is quarantined with a timestamp and the tool starts clean rather than refusing to run.

Every cycle appends one summary line to `/var/log/mail-sentinel.log`:

```
run lines=10110 ignored=9273 malformed=0 future_dropped=0 rotated=0 events=login_fail:197,login_ok:650,send:8 raised=2 suppressed=0 sent=2 seconds=0.59 exit=0
```

A cycle over ten thousand log lines takes well under a second.

## Releases

Tags are `vX.Y.Z` and each one publishes a tarball. [CHANGELOG.md](CHANGELOG.md) says
what changed and carries the upgrade notes; read them before installing, because a
release that changes the state file format makes the tool start over, re-reading the logs
and re-sending alerts it had already sent. `mail-sentinel.py status` prints the version
installed. Updating is in [docs/install.md](docs/install.md).

## Development

```
python3 -m unittest discover -s tests -v
./scripts/smoke.sh
```

The suite needs no root, no network and no server: delivery is tested against a mocked opener, and the log fixtures are sanitized lines using `user@example.com` and `203.0.113.10`. Real log lines, real addresses and real IPs never enter this repository.

`scripts/smoke.sh` runs the suite and then a full dry run against the fixtures. Set `PYTHON=python3.9` to prove it on the interpreter your server actually runs.

## License

MIT. See [LICENSE](LICENSE).
