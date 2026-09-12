import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest import mock

from sentinel.state import (empty_state, history_hours, is_suppressed, load_state, mark_sent,
                            prune_sent, save_state)

NOW = datetime(2026, 9, 11, 20, 30, 0)


class StateFileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "state.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_file_gives_empty_state_without_warning(self):
        state, warning = load_state(self.path, NOW)
        self.assertEqual(state["version"], 1)
        self.assertEqual(state["meta"]["first_run"], NOW.isoformat())
        self.assertEqual(state["auth"], {})
        self.assertIsNone(warning)

    def test_round_trip(self):
        state = empty_state(NOW)
        state["offsets"]["/var/log/maillog"] = {"inode": 5, "offset": 99}
        save_state(self.path, state)
        loaded, _ = load_state(self.path, NOW + timedelta(hours=1))
        self.assertEqual(loaded, state)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_corrupt_file_is_renamed_and_reported(self):
        with open(self.path, "w") as fh:
            fh.write("{not json")
        state, warning = load_state(self.path, NOW)
        self.assertEqual(state["auth"], {})
        self.assertIn("corrupt", warning)
        self.assertTrue(any(n.startswith("state.json.corrupt-") for n in os.listdir(self.tmp.name)))

    def test_save_is_atomic_no_tmp_left_behind(self):
        save_state(self.path, empty_state(NOW))
        self.assertEqual(sorted(os.listdir(self.tmp.name)), ["state.json"])

    def test_save_does_not_write_through_a_planted_symlink(self):
        # A symlink at state.json.tmp is how another user would try to make root
        # write where they want. The link is removed, never followed.
        decoy = os.path.join(self.tmp.name, "decoy")
        with open(decoy, "w") as fh:
            fh.write("untouched")
        os.symlink(decoy, self.path + ".tmp")
        save_state(self.path, empty_state(NOW))
        with open(decoy) as fh:
            self.assertEqual(fh.read(), "untouched")
        self.assertFalse(os.path.lexists(self.path + ".tmp"))
        self.assertEqual(load_state(self.path, NOW)[0], empty_state(NOW))

    def test_save_fails_instead_of_following_a_symlink_replanted_after_unlink(self):
        # The race the O_EXCL|O_NOFOLLOW open closes: the name is a symlink again
        # by the time we open it. Simulated by stopping the unlink from landing.
        decoy = os.path.join(self.tmp.name, "decoy")
        with open(decoy, "w") as fh:
            fh.write("untouched")
        os.symlink(decoy, self.path + ".tmp")
        with mock.patch("os.unlink"):
            with self.assertRaises(OSError):
                save_state(self.path, empty_state(NOW))
        with open(decoy) as fh:
            self.assertEqual(fh.read(), "untouched")
        self.assertFalse(os.path.exists(self.path))


class HistoryTest(unittest.TestCase):
    def test_history_hours_counts_from_first_run(self):
        state = empty_state(NOW)
        self.assertAlmostEqual(history_hours(state, NOW + timedelta(hours=72, minutes=30)), 72.5)


class DedupTest(unittest.TestCase):
    def test_not_suppressed_when_never_sent(self):
        state = empty_state(NOW)
        self.assertFalse(is_suppressed(state, "brute_force:1.1.1.1", NOW, 24))

    def test_suppressed_inside_window_and_free_after(self):
        state = empty_state(NOW)
        mark_sent(state, ["brute_force:1.1.1.1"], NOW)
        self.assertTrue(is_suppressed(state, "brute_force:1.1.1.1", NOW + timedelta(hours=23), 24))
        self.assertFalse(is_suppressed(state, "brute_force:1.1.1.1", NOW + timedelta(hours=25), 24))

    def test_prune_sent_drops_old_entries(self):
        state = empty_state(NOW)
        mark_sent(state, ["a", "b"], NOW - timedelta(hours=30))
        mark_sent(state, ["c"], NOW)
        prune_sent(state, NOW, 24)
        self.assertEqual(sorted(state["sent"]), ["c"])


if __name__ == "__main__":
    unittest.main()
