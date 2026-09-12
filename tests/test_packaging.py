"""The shipped files have to agree with each other.

Renaming the wrapper without editing the cron file would leave cron calling a
path that does not exist, and nothing else in the suite would notice.
"""
import os
import re
import stat
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL_PREFIX = "/opt/mail-sentinel/"


def read(*parts):
    with open(os.path.join(ROOT, *parts)) as fh:
        return fh.read()


class CronFileTest(unittest.TestCase):
    def setUp(self):
        self.lines = [l for l in read("cron.d", "mail-sentinel").splitlines()
                      if l and not l.startswith("#")]
        self.jobs = [l for l in self.lines if l.startswith("*")]

    def test_one_job_calling_one_command(self):
        self.assertEqual(len(self.jobs), 1)
        fields = self.jobs[0].split()
        self.assertEqual(fields[5], "root")
        self.assertEqual(len(fields), 7, "cron should call one command, no shell logic")

    def test_the_command_exists_in_the_tree_and_is_executable(self):
        command = self.jobs[0].split()[6]
        self.assertTrue(command.startswith(INSTALL_PREFIX), command)
        local = os.path.join(ROOT, command[len(INSTALL_PREFIX):])
        self.assertTrue(os.path.isfile(local), "cron calls %s, which is not in the tree" % command)
        self.assertTrue(os.stat(local).st_mode & stat.S_IXUSR, "%s is not executable" % local)

    def test_no_unescaped_percent_in_the_job_line(self):
        # crontab(5): an unescaped % becomes a newline and the rest becomes stdin
        self.assertNotIn("%", re.sub(r"\\%", "", self.jobs[0]))

    def test_no_mailto(self):
        # cron already mails the job owner; where root's mail goes is the box's business
        self.assertEqual([l for l in self.lines if l.startswith("MAILTO")], [])


class DocumentationTest(unittest.TestCase):
    """Three of the claims in these files were false before 2026-09-12.

    The exit codes are a documented contract, so a code added or renumbered
    without touching the README should fail here rather than in an operator's
    troubleshooting session.
    """

    def test_readme_lists_every_exit_code_the_cli_defines(self):
        from sentinel import cli
        codes = {cli.EXIT_OK, cli.EXIT_CONFIG, cli.EXIT_LOGS, cli.EXIT_DELIVERY, cli.EXIT_INTERNAL}
        sentence = [line for line in read("README.md").splitlines()
                    if line.startswith("Exit codes are part of the contract")]
        self.assertEqual(len(sentence), 1, "README no longer states the exit code contract")
        listed = {int(n) for n in re.findall(r"\b(\d)\b", sentence[0])}
        self.assertEqual(codes, listed)

    def test_readme_does_not_promise_a_dovecot_the_parser_cannot_read(self):
        self.assertNotIn("Dovecot 2.3 or newer", read("README.md"))


class ShippedFilesTest(unittest.TestCase):
    def test_logrotate_file_targets_the_default_log(self):
        self.assertIn("/var/log/mail-sentinel.log", read("logrotate.d", "mail-sentinel"))


if __name__ == "__main__":
    unittest.main()
