import os
import tempfile
import unittest
from unittest import mock

from sentinel.config import ConfigError, load_config

EXAMPLE = os.path.join(os.path.dirname(__file__), "..", "config.example.ini")


def write(tmpdir, text):
    path = os.path.join(tmpdir, "config.ini")
    with open(path, "w") as fh:
        fh.write(text)
    return path


MINIMAL = """
[server]
name = mx1.example.com
[provider]
kind = resend
api_key_file = {key}
from = alerts@example.com
[recipients]
critical = a@example.com, b@example.com
high = a@example.com
medium = a@example.com
"""


class LoadConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key = os.path.join(self.tmp.name, "api.key")
        with open(self.key, "w") as fh:
            fh.write("fake-key\n")
        os.chmod(self.key, 0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def test_example_file_loads_with_defaults(self):
        cfg = load_config(EXAMPLE, check_permissions=False, require_key_file=False)
        self.assertEqual(cfg.server.name, "mx1.example.com")
        self.assertEqual(cfg.brute_force.min_failures, 20)
        self.assertEqual(cfg.sending.baseline_multiplier, 5.0)
        self.assertEqual(cfg.recipients.critical, ["ops@example.com"])

    def test_minimal_config_fills_defaults(self):
        path = write(self.tmp.name, MINIMAL.format(key=self.key))
        cfg = load_config(path, check_permissions=False)
        self.assertEqual(cfg.server.maillog, "/var/log/maillog")
        self.assertEqual(cfg.locked_out.window_minutes, 60)
        self.assertEqual(cfg.recipients.critical, ["a@example.com", "b@example.com"])
        self.assertEqual(cfg.provider.kind, "resend")

    def test_unknown_key_is_rejected(self):
        text = MINIMAL.format(key=self.key).replace(
            "name = mx1.example.com", "name = mx1.example.com\nbogus = 1")
        path = write(self.tmp.name, text)
        with self.assertRaises(ConfigError):
            load_config(path, check_permissions=False)

    def test_unknown_section_is_rejected(self):
        path = write(self.tmp.name, MINIMAL.format(key=self.key) + "\n[extra]\nx = 1\n")
        with self.assertRaises(ConfigError):
            load_config(path, check_permissions=False)

    def test_malformed_ini_is_rejected(self):
        path = write(self.tmp.name, MINIMAL.format(key=self.key) + "\n[server]\nname = twice\n")
        with self.assertRaises(ConfigError):
            load_config(path, check_permissions=False)

    def test_non_numeric_threshold_is_rejected(self):
        path = write(self.tmp.name, MINIMAL.format(key=self.key) + "\n[brute_force]\nmin_failures = many\n")
        with self.assertRaises(ConfigError):
            load_config(path, check_permissions=False)

    def test_unknown_provider_is_rejected(self):
        text = MINIMAL.format(key=self.key).replace("kind = resend", "kind = sendgrid")
        path = write(self.tmp.name, text)
        with self.assertRaises(ConfigError):
            load_config(path, check_permissions=False)

    def test_missing_recipients_is_rejected(self):
        text = MINIMAL.format(key=self.key).replace("critical = a@example.com, b@example.com\nhigh = a@example.com\nmedium = a@example.com", "")
        path = write(self.tmp.name, text)
        with self.assertRaises(ConfigError):
            load_config(path, check_permissions=False)

    def test_severity_without_a_recipient_is_rejected(self):
        # an empty "to" is a 4xx from the provider, and that 4xx loses every
        # other alert travelling in the same email
        text = MINIMAL.format(key=self.key).replace("medium = a@example.com", "")
        path = write(self.tmp.name, text)
        with self.assertRaises(ConfigError) as ctx:
            load_config(path, check_permissions=False)
        self.assertIn("medium", str(ctx.exception))

    def test_key_file_must_exist(self):
        path = write(self.tmp.name, MINIMAL.format(key="/nonexistent/api.key"))
        with self.assertRaises(ConfigError):
            load_config(path, check_permissions=False)

    def test_loose_permissions_are_rejected(self):
        path = write(self.tmp.name, MINIMAL.format(key=self.key))
        os.chmod(path, 0o644)
        with self.assertRaises(ConfigError):
            load_config(path, check_permissions=True)

    def test_files_owned_by_the_running_user_are_accepted(self):
        path = write(self.tmp.name, MINIMAL.format(key=self.key))
        os.chmod(path, 0o600)
        cfg = load_config(path, check_permissions=True)
        self.assertEqual(cfg.server.name, "mx1.example.com")

    def test_file_owned_by_another_user_is_rejected(self):
        # chown needs root, so the other-owner case is proved by moving the
        # running uid instead: same stat, same comparison, no privileges needed.
        path = write(self.tmp.name, MINIMAL.format(key=self.key))
        os.chmod(path, 0o600)
        with mock.patch("os.getuid", return_value=os.getuid() + 1):
            with self.assertRaises(ConfigError) as ctx:
                load_config(path, check_permissions=True)
        self.assertIn("owned by", str(ctx.exception))
        self.assertIn("config file", str(ctx.exception))

    def test_api_key_owned_by_another_user_is_rejected(self):
        path = write(self.tmp.name, MINIMAL.format(key=self.key))
        os.chmod(path, 0o600)
        real_stat, key = os.stat, self.key

        def stat_with_foreign_key(target, *args, **kwargs):
            info = real_stat(target, *args, **kwargs)
            if target == key:
                return os.stat_result(tuple(info)[:4] + (info.st_uid + 1,) + tuple(info)[5:])
            return info

        with mock.patch("os.stat", side_effect=stat_with_foreign_key):
            with self.assertRaises(ConfigError) as ctx:
                load_config(path, check_permissions=True)
        self.assertIn("api key file", str(ctx.exception))

    def test_overrides_apply_to_sending_only(self):
        text = MINIMAL.format(key=self.key) + "\n[overrides]\nnews@example.com = ceiling_per_hour=2000, baseline_multiplier=10\n"
        path = write(self.tmp.name, text)
        cfg = load_config(path, check_permissions=False)
        self.assertEqual(cfg.sending_for("news@example.com").ceiling_per_hour, 2000)
        self.assertEqual(cfg.sending_for("news@example.com").baseline_multiplier, 10.0)
        self.assertEqual(cfg.sending_for("other@example.com").ceiling_per_hour, 100)

    def test_override_unknown_key_is_rejected(self):
        text = MINIMAL.format(key=self.key) + "\n[overrides]\nnews@example.com = window_minutes=5\n"
        path = write(self.tmp.name, text)
        with self.assertRaises(ConfigError):
            load_config(path, check_permissions=False)

    def test_redacted_dump_never_contains_key_path_contents(self):
        path = write(self.tmp.name, MINIMAL.format(key=self.key))
        cfg = load_config(path, check_permissions=False)
        dump = cfg.redacted()
        self.assertIn("mx1.example.com", dump)
        self.assertNotIn("fake-key", dump)


if __name__ == "__main__":
    unittest.main()
