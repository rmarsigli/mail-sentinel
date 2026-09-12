# Changelog

Versions follow [semantic versioning](https://semver.org). Every release is a git tag `vX.Y.Z` and a tarball; see "Updating" in [docs/install.md](docs/install.md).

**Read the Upgrade notes of a release before installing it.** The state file carries a version of its own, and a release that changes it makes the tool start from an empty state: it re-reads the logs from the beginning and re-sends alerts it had already sent.

## 0.2.1 - 2026-09-12

### Security

- The parser read attacker text as if the server had written it. Exim logs the envelope sender, the HELO and the mail subject, escapes none of them, and cPanel ships helo_accept_junk_hosts set to *, so anyone able to send one email could spell a field the tool trusted. A forged event could raise an alert naming any account or address, and worse, silence a real one: a forged successful login cancels brute force and locked out for that account for 24 hours, and a forged alert marks its own deduplication key as already sent. Lines are now anchored at the prefix the daemon itself writes, an address literal is read from the position the daemon writes next rather than the first one that appears, and any line where a field we read appears twice is refused, because an attacker can add a field but can never remove the one already there.
- Regular expression backtracking. One crafted line of a few kilobytes cost seconds of processor time, and enough of them meant a cycle no longer finished inside its fifteen minutes, the lock made the next one skip, and the tool went quiet without saying so. Lines longer than 2048 bytes are dropped as malformed now; the longest real line measured on a live server was 619 bytes.
- Files created as root followed a symlink planted at their path. They are created with O_NOFOLLOW now, the state file additionally with O_EXCL after an unlink so a hardlink is no good either, and the config and key files have to be owned by the user running the tool rather than merely being mode 0600: 0600 owned by somebody else means that somebody else rewrites what we are about to trust.
- The heartbeat URL was a curl argument, so it was readable in /proc by any local user for a few seconds every cycle. It reaches curl on standard input now.

### Fixed

- dovecot_cram_md5, and any authenticator with a digit in its name, was never counted. The pattern allowed letters only.
- malformed in the run summary counted shapes the tool does not handle, such as managesieve logins and Exim authentication failures that carry no username at all. It counts only unreadable or suspicious lines now, so a number above zero is worth looking at.

### Added

- scripts/check-no-secrets.sh scans every commit rather than the checkout alone, and reports the file and line without ever printing what matched, which would have published the secret in a public Actions log.
- scripts/deploy.sh sends only the files git tracks, so a key or a config left in the working tree cannot reach a server.
- GitHub Actions pinned by commit SHA instead of a moving tag.

### Upgrade notes

- The state file format is unchanged. Upgrading keeps offsets, buckets and the deduplication registry: no re-reading of the logs, no repeated alerts.
- Detection is unchanged. Both parsers were run over 36381 real lines from a production server: identical counts, identical accounts, identical addresses, zero divergences.
- The config file and the API key file must now be owned by the user running the tool. The documented setup, root reading root-owned files, is unaffected.

## 0.2.0 - 2026-09-12

First tagged release. Everything below was found by an audit of 0.1.0 after a week in production on one cPanel server.

### Fixed

- The parser raised on a log line it could not date, and the exception escaped the cycle before the offsets were saved, so every later run re-read the same line and died the same way until logrotate carried it away. rsyslog configured for high precision timestamps, or a `Feb 29` read in a non-leap year, was enough to blind the tool for days. Those lines are now counted as `malformed` in the run summary.
- Failures of the tool itself were silent. cron mails when a job writes something, not when it exits non-zero, and in cron mode nothing was written: a revoked API key or an unreadable `maillog` failed every fifteen minutes in a log file nobody tails. Errors now reach stderr; a clean cycle still prints nothing.
- The baseline rule divided by the full 168 hour window regardless of how much history existed, understating the mean by up to 2.3x and firing `critical` at a bit over twice an account's normal rate instead of five times it. Worst in the days right after an install.
- `abnormal_sending` only looked at the hour that had just closed, so a delivery outage lasting that hour lost the alert permanently. It now re-checks the last six closed hours, which the hour in the dedup key makes idempotent.
- An alert whose severity had no recipient list went out as `"to": []`, which a provider rejects, and that one rejection lost every other alert in the same email. All three severities are now required at startup.
- `run --dry-run` could quarantine a corrupt state file, so a diagnostic could reset the tool. It now leaves the file alone.
- A failed login with `user=<>`, which Dovecot writes when the client offered no username, raised a `locked_out` alert with an empty subject.
- Unhandled exceptions exited 1, the same code as a config error. They now exit 4 and write a line to the log.

### Added

- Optional heartbeat. Every cycle can ping an external monitor with its exit code, which is the only way a stopped cron, a removed `python3` or a dead host gets reported. Off unless `/etc/mail-sentinel/heartbeat.url` exists.
- `scripts/run-cycle.sh`, the single command cron calls.
- `scripts/deploy.sh`, dry by default, refusing a dirty tree or a failing suite.
- `logrotate.d/mail-sentinel`; nothing was rotating the tool's own log.
- Continuous integration on 3.9, 3.11 and 3.13, shellcheck, and a guard that refuses to publish anything belonging in `/etc/mail-sentinel`.

### Changed

- The alert email body is bounded. An attacker picking a fresh username per attempt raised one alert per name; three hundred of them made a 75 KB body, a likely rejection, and the loss of any real `critical` travelling in the same message.
- `state_dir` is 0700, the lock 0600 and the log 0640.
- The cron file carries nothing deployment-specific and no `MAILTO`, so reinstalling it is idempotent.

### Upgrade notes

- The state file format is unchanged. Upgrading keeps offsets, buckets and the dedup registry; no re-read, no re-alerting.
- `[recipients]` now requires `critical`, `high` and `medium`. A config with only some of them, which used to load, now fails at startup with exit 1.
- Run summaries gained a `malformed=N` field. Anything parsing that line needs updating.

## 0.1.0 - 2026-09-11

Initial implementation, never tagged. Brute force, locked out and abnormal sending signals over the Dovecot and Exim logs, alerts through Brevo or Resend.
