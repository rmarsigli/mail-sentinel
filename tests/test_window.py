import unittest
from datetime import datetime, timedelta

from sentinel.parse import Event
from sentinel.window import (account_totals, add_event, hour_key, hourly_mean, ip_totals,
                             prune, sends_for_hour, slot_key)

T = datetime(2026, 9, 11, 20, 23, 10)


def fresh():
    return {"auth": {}, "sends": {}}


class KeysTest(unittest.TestCase):
    def test_slot_key_floors_to_quarter_hour(self):
        self.assertEqual(slot_key(T), "2026-09-11T20:15")
        self.assertEqual(slot_key(T.replace(minute=59)), "2026-09-11T20:45")
        self.assertEqual(slot_key(T.replace(minute=0)), "2026-09-11T20:00")

    def test_hour_key(self):
        self.assertEqual(hour_key(T), "2026-09-11T20")


class AddEventTest(unittest.TestCase):
    def test_login_fail_counts_for_ip_and_account(self):
        s = fresh()
        add_event(s, Event("login_fail", T, "u@example.com", "203.0.113.10", 3))
        slot = s["auth"]["2026-09-11T20:15"]
        self.assertEqual(slot["ip"]["203.0.113.10"]["fail"], 3)
        self.assertEqual(slot["ip"]["203.0.113.10"]["accounts"], {"u@example.com": 3})
        self.assertEqual(slot["acct"]["u@example.com"]["fail"], 3)
        self.assertEqual(slot["acct"]["u@example.com"]["ips"], {"203.0.113.10": 3})
        self.assertEqual(slot["acct"]["u@example.com"]["first"], "20:23:10")

    def test_login_ok_counts_ok_only(self):
        s = fresh()
        add_event(s, Event("login_ok", T, "u@example.com", "203.0.113.10", 1))
        slot = s["auth"]["2026-09-11T20:15"]
        self.assertEqual(slot["ip"]["203.0.113.10"], {"fail": 0, "ok": 1, "accounts": {}, "first": "20:23:10", "last": "20:23:10"})
        self.assertEqual(slot["acct"]["u@example.com"]["ok"], 1)

    def test_send_counts_per_hour_and_ip(self):
        s = fresh()
        add_event(s, Event("send", T, "u@example.com", "203.0.113.10", 1))
        add_event(s, Event("send", T + timedelta(minutes=30), "u@example.com", "203.0.113.11", 1))
        self.assertEqual(s["sends"]["2026-09-11T20"]["u@example.com"], {"count": 2, "ips": {"203.0.113.10": 1, "203.0.113.11": 1}})

    def test_first_and_last_track_extremes(self):
        s = fresh()
        add_event(s, Event("login_fail", T, "u@example.com", "203.0.113.10", 1))
        add_event(s, Event("login_fail", T - timedelta(minutes=5), "u@example.com", "203.0.113.10", 1))
        add_event(s, Event("login_fail", T + timedelta(minutes=5), "u@example.com", "203.0.113.10", 1))
        rec = s["auth"]["2026-09-11T20:15"]["acct"]["u@example.com"]
        self.assertEqual((rec["first"], rec["last"]), ("20:18:10", "20:28:10"))


class PruneTest(unittest.TestCase):
    def test_auth_older_than_24h_and_sends_older_than_7d_are_dropped(self):
        s = fresh()
        now = T
        add_event(s, Event("login_fail", now - timedelta(hours=25), "u@example.com", "1.1.1.1", 1))
        add_event(s, Event("login_fail", now - timedelta(hours=23), "u@example.com", "1.1.1.1", 1))
        add_event(s, Event("send", now - timedelta(days=8), "u@example.com", "1.1.1.1", 1))
        add_event(s, Event("send", now - timedelta(days=6), "u@example.com", "1.1.1.1", 1))
        prune(s, now)
        self.assertEqual(list(s["auth"]), [slot_key(now - timedelta(hours=23))])
        self.assertEqual(list(s["sends"]), [hour_key(now - timedelta(days=6))])


class QueryTest(unittest.TestCase):
    def setUp(self):
        self.s = fresh()
        base = T.replace(minute=0, second=0)
        for i in range(4):  # 4 slots of 5 fails each from one IP against two accounts
            ts = base + timedelta(minutes=15 * i)
            add_event(self.s, Event("login_fail", ts, "a@example.com", "203.0.113.10", 3))
            add_event(self.s, Event("login_fail", ts, "b@example.com", "203.0.113.10", 2))
        add_event(self.s, Event("login_ok", base - timedelta(hours=2), "a@example.com", "203.0.113.10", 1))
        self.base = base

    def test_ip_totals_over_window(self):
        tot = ip_totals(self.s, "203.0.113.10", self.base + timedelta(minutes=30), self.base + timedelta(hours=1))
        self.assertEqual(tot["fail"], 10)
        self.assertEqual(tot["accounts"], {"a@example.com": 6, "b@example.com": 4})
        self.assertEqual(tot["ok"], 0)

    def test_ip_totals_including_ok(self):
        tot = ip_totals(self.s, "203.0.113.10", self.base - timedelta(hours=3), self.base + timedelta(hours=1))
        self.assertEqual(tot["ok"], 1)
        self.assertEqual(tot["fail"], 20)

    def test_account_totals(self):
        tot = account_totals(self.s, "a@example.com", self.base, self.base + timedelta(hours=1))
        self.assertEqual(tot["fail"], 12)
        self.assertEqual(tot["ips"], {"203.0.113.10": 12})
        self.assertEqual(tot["first"], "2026-09-11T20:00 20:00:00")

    def test_unknown_ip_is_all_zero(self):
        tot = ip_totals(self.s, "9.9.9.9", self.base, self.base + timedelta(hours=1))
        self.assertEqual(tot, {"fail": 0, "ok": 0, "accounts": {}, "first": None, "last": None})


class SendsTest(unittest.TestCase):
    def test_sends_for_hour_and_hourly_mean(self):
        s = fresh()
        end = datetime(2026, 9, 11, 19, 0, 0)
        for h in range(1, 169):  # 168 hours of history: 2 sends per hour
            ts = end - timedelta(hours=h)
            add_event(s, Event("send", ts, "u@example.com", "1.1.1.1", 1))
            add_event(s, Event("send", ts, "u@example.com", "1.1.1.1", 1))
        add_event(s, Event("send", end, "u@example.com", "1.1.1.1", 1))
        self.assertEqual(sends_for_hour(s, "2026-09-11T19")["u@example.com"]["count"], 1)
        self.assertEqual(hourly_mean(s, "u@example.com", "2026-09-11T19", 168), 2.0)
        self.assertEqual(hourly_mean(s, "nobody@example.com", "2026-09-11T19", 168), 0.0)

    def test_hourly_mean_divides_by_requested_hours_even_when_sparse(self):
        s = fresh()
        add_event(s, Event("send", datetime(2026, 9, 11, 18, 0, 0), "u@example.com", "1.1.1.1", 1))
        self.assertAlmostEqual(hourly_mean(s, "u@example.com", "2026-09-11T19", 4), 0.25)


if __name__ == "__main__":
    unittest.main()
