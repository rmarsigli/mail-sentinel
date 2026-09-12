import unittest
from datetime import datetime, timedelta

from sentinel.config import (BruteForceCfg, Config, DedupCfg, LockedOutCfg, ProviderCfg,
                             RecipientsCfg, SendingCfg, ServerCfg)
from sentinel.parse import Event
from sentinel.rules import dedup, evaluate, suppression_hours
from sentinel.state import empty_state, mark_sent
from sentinel.window import add_event

NOW = datetime(2026, 9, 11, 20, 30, 0)


def cfg(**overrides):
    return Config(server=ServerCfg(name="mx"), provider=ProviderCfg(sender="a@example.com"),
                  recipients=RecipientsCfg(critical=["o@example.com"]),
                  brute_force=BruteForceCfg(), locked_out=LockedOutCfg(), sending=SendingCfg(),
                  dedup=DedupCfg(), overrides=overrides)


def state_started(hours_ago):
    return empty_state(NOW - timedelta(hours=hours_ago))


def fails(state, ip, account, n, minutes_ago):
    add_event(state, Event("login_fail", NOW - timedelta(minutes=minutes_ago), account, ip, n))


def ok(state, ip, account, minutes_ago):
    add_event(state, Event("login_ok", NOW - timedelta(minutes=minutes_ago), account, ip, 1))


def sends(state, account, ip, n, hours_ago):
    for _ in range(n):
        add_event(state, Event("send", NOW - timedelta(hours=hours_ago), account, ip, 1))


def by_signal(alerts, signal):
    return [a for a in alerts if a.signal == signal]


class BruteForceTest(unittest.TestCase):
    def test_below_threshold_no_alert(self):
        s = state_started(1)
        fails(s, "203.0.113.10", "a@example.com", 19, 5)
        self.assertEqual(by_signal(evaluate(s, cfg(), NOW), "brute_force"), [])

    def test_at_threshold_alerts_with_details(self):
        s = state_started(1)
        fails(s, "203.0.113.10", "a@example.com", 12, 10)
        fails(s, "203.0.113.10", "b@example.com", 8, 3)
        alerts = by_signal(evaluate(s, cfg(), NOW), "brute_force")
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual((a.severity, a.subject, a.count, a.key), ("high", "203.0.113.10", 20, "brute_force:203.0.113.10"))
        self.assertEqual(a.details["accounts_targeted"], 2)
        self.assertEqual(a.details["top_accounts"][0], ["a@example.com", 12])

    def test_failures_outside_window_do_not_count(self):
        s = state_started(1)
        fails(s, "203.0.113.10", "a@example.com", 15, 40)
        fails(s, "203.0.113.10", "a@example.com", 10, 5)
        self.assertEqual(by_signal(evaluate(s, cfg(), NOW), "brute_force"), [])

    def test_success_from_same_ip_in_24h_cancels(self):
        s = state_started(1)
        fails(s, "203.0.113.10", "a@example.com", 50, 5)
        ok(s, "203.0.113.10", "a@example.com", 600)
        self.assertEqual(by_signal(evaluate(s, cfg(), NOW), "brute_force"), [])


class LockedOutTest(unittest.TestCase):
    def test_at_threshold_alerts(self):
        s = state_started(1)
        fails(s, "203.0.113.10", "a@example.com", 6, 50)
        fails(s, "203.0.113.11", "a@example.com", 4, 5)
        alerts = by_signal(evaluate(s, cfg(), NOW), "locked_out")
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0].severity, alerts[0].subject, alerts[0].count), ("medium", "a@example.com", 10))
        self.assertEqual(alerts[0].details["source_ips"], 2)

    def test_below_threshold_no_alert(self):
        s = state_started(1)
        fails(s, "203.0.113.10", "a@example.com", 9, 5)
        self.assertEqual(by_signal(evaluate(s, cfg(), NOW), "locked_out"), [])

    def test_recent_success_cancels(self):
        s = state_started(1)
        fails(s, "203.0.113.10", "a@example.com", 30, 5)
        ok(s, "203.0.113.12", "a@example.com", 300)
        self.assertEqual(by_signal(evaluate(s, cfg(), NOW), "locked_out"), [])


class AbnormalSendingTest(unittest.TestCase):
    # NOW is 20:30, so the last closed hour is 19:00-19:59, i.e. hours_ago=1.

    def test_ceiling_fires_without_history(self):
        s = state_started(1)
        sends(s, "a@example.com", "203.0.113.10", 101, 1)
        alerts = by_signal(evaluate(s, cfg(), NOW), "abnormal_sending")
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual((a.severity, a.subject, a.count), ("critical", "a@example.com", 101))
        self.assertEqual(a.details["rule"], "ceiling")
        self.assertEqual(a.details["hour"], "2026-09-11T19")
        self.assertEqual(a.key, "abnormal_sending:a@example.com:2026-09-11T19")

    def test_ceiling_not_exceeded_and_no_history_no_alert(self):
        s = state_started(1)
        sends(s, "a@example.com", "203.0.113.10", 100, 1)
        self.assertEqual(by_signal(evaluate(s, cfg(), NOW), "abnormal_sending"), [])

    def test_baseline_needs_min_history(self):
        s = state_started(71)
        for h in range(2, 72):
            sends(s, "a@example.com", "203.0.113.10", 2, h)
        sends(s, "a@example.com", "203.0.113.10", 50, 1)
        self.assertEqual(by_signal(evaluate(s, cfg(), NOW), "abnormal_sending"), [])

    def test_baseline_fires_with_history(self):
        s = state_started(200)
        for h in range(2, 170):
            sends(s, "a@example.com", "203.0.113.10", 2, h)  # mean 2.0
        sends(s, "a@example.com", "203.0.113.10", 11, 1)     # > 5 x 2
        alerts = by_signal(evaluate(s, cfg(), NOW), "abnormal_sending")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].details["rule"], "baseline")
        self.assertAlmostEqual(alerts[0].details["mean_7d"], 2.0)
        self.assertAlmostEqual(alerts[0].details["threshold"], 10.0)

    def test_baseline_floor_protects_quiet_accounts(self):
        s = state_started(200)
        sends(s, "a@example.com", "203.0.113.10", 1, 100)  # mean ~0.006
        sends(s, "a@example.com", "203.0.113.10", 3, 1)
        self.assertEqual(by_signal(evaluate(s, cfg(), NOW), "abnormal_sending"), [])

    def test_current_open_hour_is_not_evaluated(self):
        s = state_started(1)
        sends(s, "a@example.com", "203.0.113.10", 500, 0)
        self.assertEqual(by_signal(evaluate(s, cfg(), NOW), "abnormal_sending"), [])

    def test_override_raises_ceiling(self):
        s = state_started(1)
        sends(s, "news@example.com", "203.0.113.10", 150, 1)
        c = cfg(**{"news@example.com": {"ceiling_per_hour": 2000}})
        self.assertEqual(by_signal(evaluate(s, c, NOW), "abnormal_sending"), [])


class ServiceIdentityTest(unittest.TestCase):
    # cPanel authenticates its own services as __cpanel__service__auth__<svc>__<token>.
    SERVICE = "__cpanel__service__auth__imap__abc123token"

    def test_service_identity_never_locks_out(self):
        s = state_started(1)
        fails(s, "203.0.113.10", self.SERVICE, 50, 5)
        self.assertEqual(by_signal(evaluate(s, cfg(), NOW), "locked_out"), [])

    def test_service_identity_never_alerts_on_sending(self):
        s = state_started(1)
        sends(s, self.SERVICE, "203.0.113.10", 500, 1)
        self.assertEqual(by_signal(evaluate(s, cfg(), NOW), "abnormal_sending"), [])

    def test_service_identity_failures_still_count_for_brute_force(self):
        s = state_started(1)
        fails(s, "203.0.113.10", self.SERVICE, 25, 5)
        alerts = by_signal(evaluate(s, cfg(), NOW), "brute_force")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].count, 25)

    def test_real_mailbox_is_unaffected(self):
        s = state_started(1)
        fails(s, "203.0.113.10", "a@example.com", 15, 5)
        self.assertEqual(len(by_signal(evaluate(s, cfg(), NOW), "locked_out")), 1)


class DedupTest(unittest.TestCase):
    def test_suppression_hours_per_signal(self):
        s = state_started(1)
        fails(s, "203.0.113.10", "a@example.com", 25, 5)
        sends(s, "b@example.com", "203.0.113.10", 200, 1)
        alerts = evaluate(s, cfg(), NOW)
        hours = {a.signal: suppression_hours(a, cfg()) for a in alerts}
        self.assertEqual(hours["brute_force"], 24)
        self.assertEqual(hours["locked_out"], 24)
        self.assertEqual(hours["abnormal_sending"], 0)

    def test_dedup_drops_recently_sent(self):
        s = state_started(1)
        fails(s, "203.0.113.10", "a@example.com", 25, 5)
        alerts = evaluate(s, cfg(), NOW)
        mark_sent(s, ["brute_force:203.0.113.10"], NOW - timedelta(hours=1))
        kept, suppressed = dedup(alerts, s, cfg(), NOW)
        self.assertEqual([a.signal for a in kept], ["locked_out"])
        self.assertEqual(suppressed, 1)

    def test_empty_account_never_raises_locked_out(self):
        # Dovecot writes user=<> when the client offered no username; there is
        # no mailbox to warn about, but the IP is still brute forcing
        s = state_started(1)
        fails(s, "203.0.113.10", "", 25, 5)
        alerts = evaluate(s, cfg(), NOW)
        self.assertEqual(by_signal(alerts, "locked_out"), [])
        self.assertEqual(len(by_signal(alerts, "brute_force")), 1)

    def test_abnormal_sending_rechecks_earlier_closed_hours(self):
        # delivery was down for the hour the burst happened; the alert has to
        # survive into the next cycles instead of ageing out after four tries
        s = state_started(1)
        sends(s, "b@example.com", "203.0.113.10", 200, 4)
        alerts = by_signal(evaluate(s, cfg(), NOW), "abnormal_sending")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].details["hour"], "2026-09-11T16")

    def test_an_hour_already_delivered_is_not_raised_again(self):
        s = state_started(1)
        sends(s, "b@example.com", "203.0.113.10", 200, 4)
        mark_sent(s, ["abnormal_sending:b@example.com:2026-09-11T16"], NOW - timedelta(hours=2))
        kept, suppressed = dedup(evaluate(s, cfg(), NOW), s, cfg(), NOW)
        self.assertEqual(by_signal(kept, "abnormal_sending"), [])
        self.assertEqual(suppressed, 1)

    def test_evaluate_orders_by_severity(self):
        s = state_started(1)
        fails(s, "203.0.113.10", "a@example.com", 25, 5)
        sends(s, "b@example.com", "203.0.113.10", 200, 1)
        self.assertEqual([a.severity for a in evaluate(s, cfg(), NOW)], ["critical", "high", "medium"])


if __name__ == "__main__":
    unittest.main()
