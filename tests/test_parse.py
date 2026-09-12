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


class ForgeryTest(unittest.TestCase):
    """Every field below is written by whoever connected to the server.

    Exim escapes none of them and cPanel leaves helo_accept_junk_hosts at *, so
    a subject or a HELO can spell any shape a pattern demands. Each line here
    used to become a real event; each must now be refused.
    """

    def parse(self, line, source="exim"):
        return parse_line(line, source, NOW, {})

    def test_a_subject_cannot_forge_a_failed_login(self):
        self.assertIsNone(self.parse(
            '2026-09-12 16:04:03 1x-0-0 <= s@evil.tld H=mx.evil.tld [1.2.3.4]:25 P=esmtps S=10 '
            'T="x authenticator failed for [9.9.9.9]:1: 535 x (set_id=victim@example.com)" for v@example.com'))

    def test_a_subject_cannot_forge_a_send(self):
        self.assertIsNone(self.parse(
            '2026-09-12 16:04:03 1x-0-0 <= s@evil.tld H=mx.evil.tld [1.2.3.4]:25 P=esmtps S=10 '
            'T="x A=dovecot_login:victim@example.com S=1 y" for v@example.com'))

    def test_a_helo_cannot_forge_a_send(self):
        self.assertIsNone(self.parse(
            '2026-09-12 16:04:03 1x-0-0 <= s@evil.tld H=mx.evil.tld (x) [9.9.9.9]:1 P=esmtpsa '
            'A=dovecot_login:victim@example.com S=1 (y) [1.2.3.4]:25 P=esmtps S=10 for v@example.com'))

    def test_a_helo_cannot_forge_a_failed_login(self):
        self.assertIsNone(self.parse(
            '2026-09-12 17:11:51 dovecot_plain authenticator failed for '
            'H=x ([9.9.9.9]:1: 535 z (set_id=victim@example.com)) [1.2.3.4]:12608: 535 '
            'Incorrect authentication data (set_id=real@example.com)'))

    def test_a_quoted_sender_cannot_forge_a_send(self):
        self.assertIsNone(self.parse(
            '2026-09-12 16:04:03 1x-0-0 <= "a [9.9.9.9]:1 P=esmtpsa A=dovecot_login:victim@example.com S=1"@evil.tld '
            'H=mx.evil.tld [1.2.3.4]:25 P=esmtps S=10 for v@example.com'))

    def test_a_username_cannot_forge_a_successful_login(self):
        # a forged login_ok is the worst of the set: it cancels brute_force and
        # locked_out for that account for 24 hours
        self.assertIsNone(self.parse(
            "Sep 12 14:24:06 mx20 dovecot[1]: imap-login: Login aborted: Logged out "
            "(auth failed, 1 attempts in 2 secs): user=<x> imap-login: Logged in: "
            "user=<victim@example.com>, method=PLAIN, rip=203.0.113.99, lip=10.0.0.1>, "
            "method=PLAIN, rip=198.51.100.7, lip=10.0.0.1", "maillog"))

    def test_a_line_far_longer_than_any_real_one_is_dropped(self):
        stats = {}
        line = "2026-09-12 16:04:03 1x-0-0 <= a@b " + ("[1.1.1.1]:1 " * 500)
        self.assertIsNone(parse_line(line, "exim", NOW, stats))
        self.assertEqual(stats["malformed"], 1)


class RealShapeTest(unittest.TestCase):
    """Shapes copied from a live cPanel server, sanitised. The forgery guards
    above are worthless if they also refuse the traffic they exist to count."""

    def parse(self, line, source="exim"):
        return parse_line(line, source, NOW, {})

    def test_authenticated_send(self):
        ev = self.parse(
            '2026-09-12 16:04:03 1x5T19-0000-0MhN <= app@example.com H=(FIN) [198.51.100.7]:52477 '
            'P=esmtpsa X=TLS1.2:ECDHE-RSA-AES256-GCM-SHA384:256 A=dovecot_login:app@example.com '
            'S=34503 id=x@example.com T="assunto" for b@example.com')
        self.assertEqual((ev.kind, ev.account, ev.ip), ("send", "app@example.com", "198.51.100.7"))

    def test_authenticator_with_a_digit_in_its_name(self):
        # dovecot_cram_md5 never matched before: the old pattern allowed no digits
        ev = self.parse(
            '2026-09-12 16:04:03 1x-0-0 <= app@example.com H=(FIN) [198.51.100.7]:52477 P=esmtpsa '
            'A=dovecot_cram_md5:app@example.com S=34503 T="a" for b@example.com')
        self.assertEqual((ev.kind, ev.account), ("send", "app@example.com"))

    def test_helo_that_is_an_address_literal(self):
        # ten real lines on the measured server; an earlier version of the fix
        # silently stopped counting these
        ev = self.parse(
            '2026-09-11 22:06:14 dovecot_plain authenticator failed for H=([169.254.137.108]) '
            '[203.0.113.9]:56651: 535 Incorrect authentication data (set_id=sel@example.com)')
        self.assertEqual((ev.kind, ev.account, ev.ip), ("login_fail", "sel@example.com", "203.0.113.9"))

    def test_dovecot_logged_in_with_full_tail(self):
        ev = self.parse(
            "Sep 10 00:07:06 vpsbr dovecot[52217]: imap-login: Logged in: user=<ceo@example.com>, "
            "method=PLAIN, rip=198.51.100.7, lip=10.0.0.1, mpid=88721, secured, session=<x>", "maillog")
        self.assertEqual((ev.kind, ev.account, ev.ip), ("login_ok", "ceo@example.com", "198.51.100.7"))

    def test_dovecot_login_aborted_with_full_tail(self):
        ev = self.parse(
            "Sep 11 19:07:04 vpsbr dovecot[302953]: imap-login: Login aborted: Logged out "
            "(auth failed, 3 attempts in 2 secs) (auth_failed): user=<ceo@example.com>, "
            "method=PLAIN, rip=198.51.100.7, lip=10.0.0.1, TLS, session=<x>", "maillog")
        self.assertEqual((ev.kind, ev.account, ev.count), ("login_fail", "ceo@example.com", 3))


class MalformedTest(unittest.TestCase):
    """A line the parser cannot date must be counted, never raised.

    An exception here aborts the cycle before the offsets are saved, so the
    same line is re-read and blows up again every 15 minutes.
    """

    def test_rfc3339_timestamp_is_counted_not_raised(self):
        line = ("2026-09-11T20:24:06.123456-03:00 mx1 dovecot[1]: imap-login: Logged in: "
                "user=<a@example.com>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1, secured")
        stats = {}
        self.assertIsNone(parse_line(line, "maillog", NOW, stats))
        self.assertEqual(stats["malformed"], 1)

    def test_feb_29_in_a_non_leap_year_is_counted_not_raised(self):
        line = ("Feb 29 10:00:00 mx1 dovecot[1]: imap-login: Logged in: "
                "user=<a@example.com>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1, secured")
        stats = {}
        self.assertIsNone(parse_line(line, "maillog", datetime(2029, 3, 1), stats))
        self.assertEqual(stats["malformed"], 1)

    def test_unknown_month_is_counted_not_raised(self):
        line = ("Foo 11 20:24:06 mx1 dovecot[1]: imap-login: Logged in: "
                "user=<a@example.com>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1, secured")
        self.assertIsNone(parse_line(line, "maillog", NOW))

    def test_parse_syslog_ts_returns_none_instead_of_raising(self):
        self.assertIsNone(parse_syslog_ts("2026-09-11T20:24:06", NOW))

    def test_a_login_line_with_an_unreadable_prefix_is_counted(self):
        # rsyslog reconfigured, or a different program name: the tool must say
        # so in the run summary instead of reporting zero events forever
        stats = {}
        line = ("2026-09-11T20:24:06+00:00 mx1 dovecot: imap-login: Logged in: "
                "user=<a@example.com>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1")
        self.assertIsNone(parse_line(line, "maillog", NOW, stats))
        self.assertEqual(stats["malformed"], 1)

    def test_a_good_line_does_not_count_as_malformed(self):
        stats = {}
        line = ("Sep 11 20:24:06 mx1 dovecot[1]: imap-login: Logged in: "
                "user=<a@example.com>, method=PLAIN, rip=203.0.113.5, lip=10.0.0.1, secured")
        self.assertIsNotNone(parse_line(line, "maillog", NOW, stats))
        self.assertEqual(stats, {})


if __name__ == "__main__":
    unittest.main()
