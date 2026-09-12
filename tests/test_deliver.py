import io
import json
import unittest
import urllib.error
from datetime import datetime

from sentinel.config import (BruteForceCfg, Config, DedupCfg, LockedOutCfg, ProviderCfg,
                             RecipientsCfg, SendingCfg, ServerCfg)
from sentinel.deliver import (MAX_DETAILED_ALERTS, MAX_LISTED_ALERTS, DeliveryError, format_body,
                              format_subject, recipients_for, send_email)
from sentinel.rules import Alert

NOW = datetime(2026, 9, 11, 20, 30, 0)
KEY = "fake-key-0000"


def cfg(kind="brevo"):
    return Config(server=ServerCfg(name="mx1.example.com"),
                  provider=ProviderCfg(kind=kind, sender="alerts@example.com"),
                  recipients=RecipientsCfg(critical=["ops@example.com", "boss@example.com"],
                                           high=["ops@example.com"], medium=["ops@example.com"]),
                  brute_force=BruteForceCfg(), locked_out=LockedOutCfg(), sending=SendingCfg(),
                  dedup=DedupCfg(), overrides={})


ALERTS = [
    Alert("abnormal_sending", "critical", "a@example.com", 250,
          {"hour": "2026-09-11T19", "rule": "ceiling", "threshold": 100.0, "mean_7d": 1.5,
           "top_ips": [["203.0.113.10", 250]]}, "abnormal_sending:a@example.com:2026-09-11T19"),
    Alert("brute_force", "high", "203.0.113.99", 40,
          {"accounts_targeted": 3, "top_accounts": [["b@example.com", 30], ["c@example.com", 10]],
           "first": "2026-09-11T20:15 20:16:01", "last": "2026-09-11T20:15 20:29:59", "window_minutes": 15},
          "brute_force:203.0.113.99"),
    Alert("locked_out", "medium", "d@example.com", 12,
          {"source_ips": 1, "top_ips": [["203.0.113.5", 12]], "first": "2026-09-11T19:30 19:31:00",
           "last": "2026-09-11T20:15 20:20:00", "window_minutes": 60}, "locked_out:d@example.com"),
]


class FormatTest(unittest.TestCase):
    def test_subject(self):
        self.assertEqual(format_subject("mx1.example.com", ALERTS), "[mail-sentinel mx1.example.com] 3 alerts: critical")
        self.assertEqual(format_subject("mx1.example.com", ALERTS[2:]), "[mail-sentinel mx1.example.com] 1 alert: medium")

    def test_body_has_machine_readable_header_lines(self):
        body = format_body("mx1.example.com", ALERTS, NOW)
        self.assertIn("critical abnormal_sending a@example.com 250", body)
        self.assertIn("high brute_force 203.0.113.99 40", body)
        self.assertIn("medium locked_out d@example.com 12", body)
        self.assertIn("ceiling 100", body)
        self.assertIn("b@example.com: 30", body)

    def test_a_flood_of_alerts_produces_a_bounded_body(self):
        # one locked_out per username tried: an attacker picks the count, so the
        # body cannot be allowed to grow until the provider rejects it
        flood = [Alert("locked_out", "medium", "u%03d@example.com" % i, 12,
                       {"source_ips": 1, "top_ips": [["203.0.113.5", 12]], "first": "a",
                        "last": "b", "window_minutes": 60}, "locked_out:u%03d" % i)
                 for i in range(300)]
        body = format_body("mx1.example.com", flood, NOW)
        self.assertLess(len(body.encode()), 32 * 1024)
        self.assertIn("300 alerts this cycle", body)
        self.assertIn("medium locked_out u000@example.com 12", body)
        self.assertIn("and %d more not listed" % (300 - MAX_DETAILED_ALERTS - MAX_LISTED_ALERTS), body)

    def test_a_normal_cycle_keeps_every_alert_in_full(self):
        body = format_body("mx1.example.com", ALERTS, NOW)
        self.assertNotIn("more, one line each", body)
        self.assertNotIn("alerts this cycle", body)

    def test_recipients_union_by_severity(self):
        self.assertEqual(recipients_for(ALERTS, cfg()), ["boss@example.com", "ops@example.com"])
        self.assertEqual(recipients_for(ALERTS[1:], cfg()), ["ops@example.com"])


class FakeResponse(io.BytesIO):
    def __init__(self, status, body=b"{}"):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class SendTest(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.sleeps = []

    def opener_ok(self, status):
        def opener(request, timeout=0):
            self.calls.append((request.full_url, dict(request.header_items()), json.loads(request.data.decode())))
            return FakeResponse(status)
        return opener

    def opener_fail_then_ok(self, code, status):
        state = {"n": 0}

        def opener(request, timeout=0):
            state["n"] += 1
            self.calls.append(request.full_url)
            if state["n"] == 1:
                raise urllib.error.HTTPError(request.full_url, code, "err", {}, io.BytesIO(b"server said no"))
            return FakeResponse(status)
        return opener

    def test_brevo_payload_and_headers(self):
        status = send_email(cfg("brevo"), ["ops@example.com"], "S", "B", KEY, opener=self.opener_ok(201))
        self.assertEqual(status, 201)
        url, headers, payload = self.calls[0]
        self.assertEqual(url, "https://api.brevo.com/v3/smtp/email")
        self.assertEqual(headers["Api-key"], KEY)
        self.assertEqual(payload, {"sender": {"email": "alerts@example.com"},
                                   "to": [{"email": "ops@example.com"}], "subject": "S", "textContent": "B"})

    def test_resend_payload_and_headers(self):
        status = send_email(cfg("resend"), ["ops@example.com"], "S", "B", KEY, opener=self.opener_ok(200))
        self.assertEqual(status, 200)
        url, headers, payload = self.calls[0]
        self.assertEqual(url, "https://api.resend.com/emails")
        self.assertEqual(headers["Authorization"], "Bearer " + KEY)
        self.assertEqual(payload, {"from": "alerts@example.com", "to": ["ops@example.com"], "subject": "S", "text": "B"})

    def test_5xx_is_retried_once(self):
        status = send_email(cfg(), ["ops@example.com"], "S", "B", KEY,
                            opener=self.opener_fail_then_ok(503, 201), sleep=self.sleeps.append)
        self.assertEqual(status, 201)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.sleeps, [5])

    def test_4xx_is_not_retried_and_message_has_no_key(self):
        with self.assertRaises(DeliveryError) as ctx:
            send_email(cfg(), ["ops@example.com"], "S", "B", KEY,
                       opener=self.opener_fail_then_ok(401, 201), sleep=self.sleeps.append)
        self.assertEqual(len(self.calls), 1)
        self.assertIn("401", str(ctx.exception))
        self.assertIn("server said no", str(ctx.exception))
        self.assertNotIn(KEY, str(ctx.exception))

    def test_connection_error_retried_then_raises(self):
        def opener(request, timeout=0):
            self.calls.append(1)
            raise urllib.error.URLError("no route")
        with self.assertRaises(DeliveryError):
            send_email(cfg(), ["ops@example.com"], "S", "B", KEY, opener=opener, sleep=self.sleeps.append)
        self.assertEqual(len(self.calls), 2)

    def test_request_identifies_itself_with_a_user_agent(self):
        # Cloudflare fronts the provider API and blocks urllib's default agent (HTTP 403,
        # error 1010). Measured against Brevo on 2026-09-11.
        send_email(cfg("brevo"), ["ops@example.com"], "S", "B", KEY, opener=self.opener_ok(201))
        _, headers, _ = self.calls[0]
        self.assertIn("mail-sentinel", headers["User-agent"])

    def test_unexpected_success_status_raises(self):
        with self.assertRaises(DeliveryError):
            send_email(cfg("brevo"), ["ops@example.com"], "S", "B", KEY, opener=self.opener_ok(202))


if __name__ == "__main__":
    unittest.main()
