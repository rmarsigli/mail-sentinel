import os
import unittest
from datetime import datetime

from sentinel.parse import Event, parse_line, parse_syslog_ts

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
NOW = datetime(2026, 9, 11, 20, 30, 0)


def lines(name):
    with open(os.path.join(FIX, name)) as fh:
        return [l.rstrip("\n") for l in fh]


class SyslogTimestampTest(unittest.TestCase):
    def test_current_year_is_assumed(self):
        self.assertEqual(parse_syslog_ts("Sep 11 20:24:06", NOW), datetime(2026, 9, 11, 20, 24, 6))

    def test_future_date_means_previous_year(self):
        now = datetime(2027, 1, 2, 0, 0, 0)
        self.assertEqual(parse_syslog_ts("Dec 31 23:59:00", now), datetime(2026, 12, 31, 23, 59, 0))

    def test_single_digit_day_with_double_space(self):
        self.assertEqual(parse_syslog_ts("Sep  1 00:00:01", NOW), datetime(2026, 9, 1, 0, 0, 1))


class MaillogParseTest(unittest.TestCase):
    def setUp(self):
        self.l = lines("maillog.log")

    def test_imap_login_ok(self):
        ev = parse_line(self.l[0], "maillog", NOW)
        self.assertEqual(ev, Event("login_ok", datetime(2026, 9, 11, 20, 24, 6), "user@example.com", "203.0.113.10", 1))

    def test_pop3_login_ok(self):
        ev = parse_line(self.l[1], "maillog", NOW)
        self.assertEqual(ev.kind, "login_ok")
        self.assertEqual(ev.account, "pop@example.com")
        self.assertEqual(ev.ip, "203.0.113.11")

    def test_auth_failed_single_attempt(self):
        ev = parse_line(self.l[2], "maillog", NOW)
        self.assertEqual(ev, Event("login_fail", datetime(2026, 9, 11, 20, 23, 10), "user@example.com", "203.0.113.10", 1))

    def test_auth_failed_counts_attempts(self):
        ev = parse_line(self.l[3], "maillog", NOW)
        self.assertEqual(ev.kind, "login_fail")
        self.assertEqual(ev.count, 3)
        self.assertEqual(ev.account, "victim@example.com")
        self.assertEqual(ev.ip, "203.0.113.99")

    def test_no_auth_attempts_is_ignored(self):
        self.assertIsNone(parse_line(self.l[4], "maillog", NOW))

    def test_post_login_session_line_is_ignored(self):
        self.assertIsNone(parse_line(self.l[5], "maillog", NOW))

    def test_unrelated_line_is_ignored(self):
        self.assertIsNone(parse_line(self.l[6], "maillog", NOW))


class EximParseTest(unittest.TestCase):
    def setUp(self):
        self.l = lines("exim_mainlog.log")

    def test_smtp_auth_failure(self):
        ev = parse_line(self.l[0], "exim", NOW)
        self.assertEqual(ev, Event("login_fail", datetime(2026, 9, 11, 19, 40, 22), "user@example.com", "203.0.113.10", 1))

    def test_authenticated_send_uses_auth_account_not_envelope(self):
        ev = parse_line(self.l[1], "exim", NOW)
        self.assertEqual(ev, Event("send", datetime(2026, 9, 11, 19, 48, 18), "user@example.com", "203.0.113.10", 1))

    def test_forged_envelope_still_attributed_to_authenticated_account(self):
        ev = parse_line(self.l[2], "exim", NOW)
        self.assertEqual(ev.kind, "send")
        self.assertEqual(ev.account, "webmail@example.com")
        self.assertEqual(ev.count, 1)  # one message, two recipients

    def test_local_submission_is_ignored(self):
        self.assertIsNone(parse_line(self.l[3], "exim", NOW))

    def test_delivery_line_is_ignored(self):
        self.assertIsNone(parse_line(self.l[4], "exim", NOW))

    def test_connection_line_is_ignored(self):
        self.assertIsNone(parse_line(self.l[5], "exim", NOW))

    def test_unknown_source_raises(self):
        with self.assertRaises(ValueError):
            parse_line(self.l[0], "syslog", NOW)


class MalformedTest(unittest.TestCase):
    """A line the parser cannot date must be counted, never raised.

    An exception here aborts the cycle before the offsets are saved, so the
    same line is re-read and blows up again every 15 minutes.
    """

    def test_rfc3339_timestamp_is_counted_not_raised(self):
        line = ("2026-09-11T20:24:06.123456-03:00 mx1 dovecot[1]: imap-login: Logged in: "
                "user=<a@example.com>, method=PLAIN, rip=203.0.113.5")
        stats = {}
        self.assertIsNone(parse_line(line, "maillog", NOW, stats))
        self.assertEqual(stats["malformed"], 1)

    def test_feb_29_in_a_non_leap_year_is_counted_not_raised(self):
        line = ("Feb 29 10:00:00 mx1 dovecot[1]: imap-login: Logged in: "
                "user=<a@example.com>, rip=203.0.113.5")
        stats = {}
        self.assertIsNone(parse_line(line, "maillog", datetime(2029, 3, 1), stats))
        self.assertEqual(stats["malformed"], 1)

    def test_unknown_month_is_counted_not_raised(self):
        line = ("Foo 11 20:24:06 mx1 dovecot[1]: imap-login: Logged in: "
                "user=<a@example.com>, rip=203.0.113.5")
        self.assertIsNone(parse_line(line, "maillog", NOW))

    def test_parse_syslog_ts_returns_none_instead_of_raising(self):
        self.assertIsNone(parse_syslog_ts("2026-09-11T20:24:06", NOW))

    def test_a_good_line_does_not_count_as_malformed(self):
        stats = {}
        line = ("Sep 11 20:24:06 mx1 dovecot[1]: imap-login: Logged in: "
                "user=<a@example.com>, method=PLAIN, rip=203.0.113.5")
        self.assertIsNotNone(parse_line(line, "maillog", NOW, stats))
        self.assertEqual(stats, {})


if __name__ == "__main__":
    unittest.main()
