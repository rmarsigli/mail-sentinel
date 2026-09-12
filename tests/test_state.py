import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta

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
