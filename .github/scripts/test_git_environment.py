"""The git environment the tests share: it starts no background maintenance, and no test builds its own.

Every commit a test repository takes makes git run `git maintenance run --auto`. A newer git detaches that
run, and it holds a lock file under .git/objects while it works, so a test that ends first finds objects/
not empty when its temporary directory is removed (OSError, Errno 39). It failed one run of the script tests
in forty. The cure is for no test git command to start the run at all; these tests pin that."""

from __future__ import annotations

import glob
import os
import re
import subprocess
import tempfile
import unittest
from unittest import mock

import _testsupport as ts

HERE = os.path.dirname(os.path.abspath(__file__))
# What a commit's trace shows when git goes on to do upkeep: `maintenance run --auto` since git 2.29, and the
# `gc --auto` it replaced before that.
UPKEEP = re.compile(r"maintenance run|gc --auto")


def commit_trace(env):
    """The trace (stderr) of one commit, made the way ts.Repo.commit makes it, with tracing added to `env`."""
    with tempfile.TemporaryDirectory() as root:

        def run(*args, **extra):
            return subprocess.run(
                ["git", "-C", root, *args], check=True, capture_output=True, text=True, env=dict(env, **extra)
            )

        run("init", "-q", "-b", "main")
        run("add", "-A")
        return run("commit", "-q", "--allow-empty", "-m", "change", GIT_TRACE="1").stderr


class TestNoBackgroundUpkeep(unittest.TestCase):
    def test_a_commit_made_the_way_the_helper_makes_it_starts_no_maintenance_or_gc(self):
        trace = commit_trace(ts.GIT_ENV)
        # The commit itself shows in the trace, so an empty or unwritten trace cannot pass for a quiet one.
        self.assertIn("git commit", trace)
        self.assertIsNone(UPKEEP.search(trace), trace)

    def test_so_does_the_environment_a_test_builds_with_its_own_identity(self):
        trace = commit_trace(ts.git_env("t", "t@example.invalid"))
        self.assertIn("git commit", trace)
        self.assertIsNone(UPKEEP.search(trace), trace)

    def test_the_settings_are_ones_git_reads_and_come_after_any_the_shell_passed(self):
        inherited = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "test.inherited", "GIT_CONFIG_VALUE_0": "kept"}
        with mock.patch.dict(os.environ, inherited):
            env = ts.git_env()
        self.assertEqual(env["GIT_CONFIG_COUNT"], "3")
        for name, expected in (("test.inherited", "kept"), ("maintenance.auto", "false"), ("gc.auto", "0")):
            with self.subTest(name):
                done = subprocess.run(
                    ["git", "config", "--get", name], capture_output=True, text=True, env=env, check=True
                )
                self.assertEqual(done.stdout.strip(), expected)

    def test_a_count_the_shell_left_unreadable_does_not_stop_the_settings(self):
        with mock.patch.dict(os.environ, {"GIT_CONFIG_COUNT": "many"}):
            env = ts.git_env()
        self.assertEqual(env["GIT_CONFIG_COUNT"], "2")
        self.assertEqual((env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_KEY_1"]), ("maintenance.auto", "gc.auto"))

    def test_a_count_git_accepts_with_a_sign_or_white_space_keeps_the_callers_settings(self):
        # git reads the count with strtoul, so "+1" and " 1" both mean one setting: ours go after it.
        for count in ("+1", " 1"):
            with self.subTest(count):
                inherited = {"GIT_CONFIG_COUNT": count, "GIT_CONFIG_KEY_0": "test.inherited", "GIT_CONFIG_VALUE_0": "kept"}
                with mock.patch.dict(os.environ, inherited):
                    env = ts.git_env()
                self.assertEqual(env["GIT_CONFIG_COUNT"], "3")
                self.assertEqual((env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_VALUE_0"]), ("test.inherited", "kept"))
                self.assertEqual((env["GIT_CONFIG_KEY_1"], env["GIT_CONFIG_KEY_2"]), ("maintenance.auto", "gc.auto"))

    def test_a_count_no_one_can_read_is_none_and_never_raises(self):
        # "\u00b2" is a digit to str.isdigit() but not to int(); "-1" and "" are no count at all.
        for count in ("\u00b2", "abc", "-1", ""):
            with self.subTest(count):
                with mock.patch.dict(os.environ, {"GIT_CONFIG_COUNT": count}):
                    env = ts.git_env()
                self.assertEqual(env["GIT_CONFIG_COUNT"], "2")
                self.assertEqual((env["GIT_CONFIG_KEY_0"], env["GIT_CONFIG_KEY_1"]), ("maintenance.auto", "gc.auto"))

    def test_no_other_test_module_builds_its_own_git_environment(self):
        # The hand-built environments this replaced each carried the no-system-config setting, so a module that
        # still has it is building git an environment of its own, one that would start the upkeep again.
        own = {os.path.abspath(__file__), os.path.join(HERE, "_testsupport.py")}
        setting = "GIT_CONFIG_" + "NOSYSTEM"
        for path in sorted(glob.glob(os.path.join(HERE, "*.py"))):
            if os.path.abspath(path) in own:
                continue
            with self.subTest(os.path.basename(path)):
                with open(path, encoding="utf-8") as handle:
                    builds_its_own = setting in handle.read()
                # Not assertNotIn: its failure would print the whole module.
                self.assertFalse(builds_its_own, f"{os.path.basename(path)} names {setting}: use ts.git_env instead")


if __name__ == "__main__":
    unittest.main()
