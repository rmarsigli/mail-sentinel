import os
import tempfile
import unittest

from sentinel.tail import read_new


class ReadNewTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "log")
        self.record = {}

    def tearDown(self):
        self.tmp.cleanup()

    def append(self, text):
        with open(self.path, "a") as fh:
            fh.write(text)

    def test_first_read_returns_everything(self):
        self.append("one\ntwo\n")
        lines, rotated = read_new(self.path, self.record)
        self.assertEqual(lines, ["one", "two"])
        self.assertFalse(rotated)
        self.assertEqual(self.record["offset"], 8)

    def test_second_read_returns_only_new_lines(self):
        self.append("one\n")
        read_new(self.path, self.record)
        self.append("two\nthree\n")
        lines, _ = read_new(self.path, self.record)
        self.assertEqual(lines, ["two", "three"])

    def test_partial_last_line_is_left_for_next_time(self):
        self.append("one\ntw")
        lines, _ = read_new(self.path, self.record)
        self.assertEqual(lines, ["one"])
        self.assertEqual(self.record["offset"], 4)
        self.append("o\n")
        lines, _ = read_new(self.path, self.record)
        self.assertEqual(lines, ["two"])

    def test_rotation_restarts_at_zero(self):
        self.append("old1\nold2\n")
        read_new(self.path, self.record)
        os.rename(self.path, self.path + ".1")
        self.append("new1\n")
        lines, rotated = read_new(self.path, self.record)
        self.assertEqual(lines, ["new1"])
        self.assertTrue(rotated)

    def test_truncation_restarts_at_zero(self):
        self.append("a long first line\nsecond\n")
        read_new(self.path, self.record)
        with open(self.path, "w") as fh:
            fh.write("x\n")
        lines, rotated = read_new(self.path, self.record)
        self.assertEqual(lines, ["x"])
        self.assertTrue(rotated)

    def test_no_change_returns_nothing(self):
        self.append("one\n")
        read_new(self.path, self.record)
        lines, rotated = read_new(self.path, self.record)
        self.assertEqual(lines, [])
        self.assertFalse(rotated)

    def test_undecodable_bytes_do_not_crash(self):
        with open(self.path, "ab") as fh:
            fh.write(b"ok\n\xff\xfe bad\n")
        lines, _ = read_new(self.path, self.record)
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], "ok")

    def test_missing_file_raises(self):
        with self.assertRaises(OSError):
            read_new(self.path, self.record)


if __name__ == "__main__":
    unittest.main()
