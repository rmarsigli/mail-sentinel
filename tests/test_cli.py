import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from sentinel import cli

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


class FakeResponse(io.BytesIO):
    def __init__(self, status):
        super().__init__(b"{}")
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.maillog = os.path.join(self.root, "maillog")
        self.exim = os.path.join(self.root, "exim_mainlog")
        shutil.copy(os.path.join(FIX, "maillog.log"), self.maillog)
        shutil.copy(os.path.join(FIX, "exim_mainlog.log"), self.exim)
        self.key = os.path.join(self.root, "api.key")
        with open(self.key, "w") as fh:
            fh.write("fake-key\n")
        os.chmod(self.key, 0o600)
        self.state_dir = os.path.join(self.root, "state")
        self.log_file = os.path.join(self.root, "sentinel.log")
        self.config = os.path.join(self.root, "config.ini")
        with open(self.config, "w") as fh:
            fh.write("""
[server]
name = mx1.example.com
maillog = %s
exim_mainlog = %s
state_dir = %s
log_file = %s
[provider]
kind = resend
api_key_file = %s
from = alerts@example.com
[recipients]
critical = ops@example.com
high = ops@example.com
medium = ops@example.com
[brute_force]
min_failures = 3
window_minutes = 15
""" % (self.maillog, self.exim, self.state_dir, self.log_file, self.key))
        os.chmod(self.config, 0o600)
        self.sent = []
        self.out = io.StringIO()
        self.err = io.StringIO()

    def tearDown(self):
        self.tmp.cleanup()

    def opener(self, request, timeout=0):
        self.sent.append(json.loads(request.data.decode()))
        return FakeResponse(200)

    def run_cli(self, *args):
        self.out, self.err = io.StringIO(), io.StringIO()
        argv = ["--config", self.config, "--no-permission-check", "--now", "2026-09-11T20:30:00"] + list(args)
        return cli.main(argv, opener=self.opener, stdout=self.out, stderr=self.err)

    def state(self):
        with open(os.path.join(self.state_dir, "state.json")) as fh:
            return json.load(fh)

    def test_dry_run_reports_but_sends_nothing_and_saves_nothing(self):
        code = self.run_cli("run", "--dry-run")
        self.assertEqual(code, 0)
        self.assertEqual(self.sent, [])
        self.assertFalse(os.path.exists(os.path.join(self.state_dir, "state.json")))

    def test_dry_run_puts_alerts_on_stdout_and_the_summary_on_stderr(self):
        self.run_cli("run", "--dry-run")
        self.assertIn("high brute_force 203.0.113.99 3", self.out.getvalue())
        self.assertNotIn("high brute_force", self.err.getvalue())
        self.assertIn("run (dry-run)", self.err.getvalue())

    def test_run_sends_brute_force_alert_from_fixtures(self):
        # fixture: 203.0.113.99 fails 3 times at 20:23, no success -> brute_force with min_failures=3
        code = self.run_cli("run")
        self.assertEqual(code, 0)
        self.assertEqual(len(self.sent), 1)
        body = self.sent[0]["text"]
        self.assertIn("high brute_force 203.0.113.99 3", body)
        self.assertNotIn("203.0.113.10", body.split("high brute_force")[1].split("\n")[0])
        st = self.state()
        self.assertIn("brute_force:203.0.113.99", st["sent"])
        self.assertGreater(st["offsets"][self.maillog]["offset"], 0)

    def test_second_run_reads_nothing_new_and_suppresses(self):
        self.run_cli("run")
        code = self.run_cli("run")
        self.assertEqual(code, 0)
        self.assertEqual(len(self.sent), 1)
        with open(self.log_file) as fh:
            last = fh.read().strip().splitlines()[-1]
        self.assertIn("suppressed=1", last)
        self.assertIn("lines=0", last)

    def test_missing_log_file_exits_2(self):
        os.remove(self.exim)
        self.assertEqual(self.run_cli("run"), 2)

    def test_bad_config_exits_1(self):
        with open(self.config, "a") as fh:
            fh.write("\n[nope]\nx = 1\n")
        self.assertEqual(self.run_cli("run"), 1)

    def test_delivery_failure_exits_3_and_keeps_alert_unsent(self):
        import urllib.error

        def bad_opener(request, timeout=0):
            raise urllib.error.URLError("down")
        argv = ["--config", self.config, "--no-permission-check", "--now", "2026-09-11T20:30:00", "run"]
        self.assertEqual(cli.main(argv, opener=bad_opener, sleep=lambda s: None, stderr=self.err), 3)
        self.assertEqual(self.state()["sent"], {})

    def test_test_delivery_sends_one_message_to_all_recipients(self):
        self.assertEqual(self.run_cli("test-delivery"), 0)
        self.assertEqual(self.sent[0]["to"], ["ops@example.com"])
        self.assertIn("test", self.sent[0]["subject"].lower())

    def test_cron_mode_writes_errors_to_stderr_so_cron_mails_them(self):
        # cron mails when the job writes something, not when it exits non-zero;
        # a delivery failure that only reaches the log file is never seen
        import urllib.error

        def bad_opener(request, timeout=0):
            raise urllib.error.URLError("down")
        argv = ["--config", self.config, "--no-permission-check", "--now", "2026-09-11T20:30:00", "run"]
        real = io.StringIO()
        with contextlib.redirect_stderr(real):
            code = cli.main(argv, opener=bad_opener, sleep=lambda s: None)
        self.assertEqual(code, 3)
        self.assertIn("delivery failed", real.getvalue())

    def test_cron_mode_stays_quiet_on_a_clean_cycle(self):
        argv = ["--config", self.config, "--no-permission-check", "--now", "2026-09-11T20:30:00", "run"]
        real = io.StringIO()
        with contextlib.redirect_stderr(real):
            code = cli.main(argv, opener=self.opener)
        self.assertEqual(code, 0)
        self.assertEqual(real.getvalue(), "")

    def test_dry_run_does_not_quarantine_a_corrupt_state(self):
        os.makedirs(self.state_dir, exist_ok=True)
        state_path = os.path.join(self.state_dir, "state.json")
        with open(state_path, "w") as fh:
            fh.write("{not json")
        self.assertEqual(self.run_cli("run", "--dry-run"), 0)
        self.assertTrue(os.path.exists(state_path))
        self.assertEqual([f for f in os.listdir(self.state_dir) if "corrupt" in f], [])

    def test_unhandled_error_exits_4_with_output(self):
        def boom(*a, **kw):
            raise RuntimeError("boom")
        original = cli.read_new
        cli.read_new = boom
        try:
            code = self.run_cli("run")
        finally:
            cli.read_new = original
        self.assertEqual(code, 4)
        self.assertIn("unhandled RuntimeError", self.err.getvalue())

    def test_log_is_not_written_through_a_symlink_and_the_cycle_survives(self):
        # A symlink where the log file goes must not be followed, and a log that
        # cannot be written must never take the cycle down with it.
        decoy = os.path.join(self.root, "decoy.log")
        with open(decoy, "w") as fh:
            fh.write("untouched\n")
        os.symlink(decoy, self.log_file)
        code = self.run_cli("run")
        self.assertEqual(code, 0)
        self.assertEqual(len(self.sent), 1)
        with open(decoy) as fh:
            self.assertEqual(fh.read(), "untouched\n")

    def test_lock_is_not_opened_through_a_symlink(self):
        decoy = os.path.join(self.root, "decoy.lock")
        with open(decoy, "w") as fh:
            fh.write("untouched")
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        os.symlink(decoy, os.path.join(self.state_dir, "lock"))
        # Refusing to run is the safe outcome: exit 4 with the reason on stderr.
        self.assertEqual(self.run_cli("run"), 4)
        self.assertEqual(self.sent, [])
        with open(decoy) as fh:
            self.assertEqual(fh.read(), "untouched")

    def test_status_prints_config_without_key(self):
        out = io.StringIO()
        code = cli.main(["--config", self.config, "--no-permission-check", "status"], opener=self.opener, stdout=out)
        self.assertEqual(code, 0)
        self.assertIn("mx1.example.com", out.getvalue())
        self.assertNotIn("fake-key", out.getvalue())


if __name__ == "__main__":
    unittest.main()
