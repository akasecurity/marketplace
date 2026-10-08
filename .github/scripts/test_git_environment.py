"""The git environment the tests share: it starts no background maintenance, and no test builds its own.

Every commit a test repository takes makes git run `git maintenance run --auto`. A newer git detaches that
run, and it holds a lock file under .git/objects while it works, so a test that ends first finds objects/
not empty when its temporary directory is removed (OSError, Errno 39). It failed one run of the script tests
in forty. The cure is for no test git command to start the run at all; these tests pin that."""

from __future__ import annotations

import ast
import glob
import os
import re
import subprocess
import tempfile
import unittest
from unittest import mock

import _testsupport as ts

HERE = os.path.dirname(os.path.abspath(__file__))
# What a commit's trace shows when git goes on to start upkeep: `maintenance run --auto` (git 2.29 and later).
# `gc --auto` is not matched, on purpose: before 2.29 every commit spawns it, it reads gc.auto=0 and exits at
# once, so it is in every trace and says nothing about whether upkeep ran. That setting is pinned by the config
# read-back test below instead.
UPKEEP = re.compile(r"maintenance run")


# Variables a test must take from ts.git_env, which sets them with the upkeep settings, and never build itself.
OWN_ENVIRONMENT_KEYS = frozenset(
    {
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
    }
)
SUBPROCESS_CALLS = frozenset({"run", "check_output", "check_call", "Popen"})


def _is_subprocess_call(func):
    return (
        isinstance(func, ast.Attribute)
        and func.attr in SUBPROCESS_CALLS
        and isinstance(func.value, ast.Name)
        and func.value.id == "subprocess"
    ) or (isinstance(func, ast.Name) and func.id in SUBPROCESS_CALLS - {"run"})


def environment_problems(source, name="module"):
    """What in this Python source gives git an environment of its own: a dict built with one of
    OWN_ENVIRONMENT_KEYS as a key or keyword, or a subprocess call whose command list starts with "git" and
    passes no env=. One line of text per finding, naming the module and the line."""
    problems = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if isinstance(key, ast.Constant) and key.value in OWN_ENVIRONMENT_KEYS:
                    problems.append(f"{name}:{node.lineno} builds a dict with {key.value}: use ts.git_env")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "dict":
                for keyword in node.keywords:
                    if keyword.arg in OWN_ENVIRONMENT_KEYS:
                        problems.append(f"{name}:{node.lineno} builds a dict with {keyword.arg}: use ts.git_env")
            if _is_subprocess_call(node.func) and node.args:
                command = node.args[0]
                runs_git = (
                    isinstance(command, (ast.List, ast.Tuple))
                    and command.elts
                    and isinstance(command.elts[0], ast.Constant)
                    and command.elts[0].value == "git"
                )
                if runs_git and not any(keyword.arg == "env" for keyword in node.keywords):
                    problems.append(f"{name}:{node.lineno} runs git without env=: pass ts.GIT_ENV or ts.git_env()")
    return problems


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

    def test_the_trace_pattern_matches_maintenance_and_ignores_an_instant_gc_auto(self):
        self.assertIsNotNone(UPKEEP.search("trace: built-in: git maintenance run --auto --no-quiet"))
        self.assertIsNone(UPKEEP.search("trace: run_command: git gc --auto"))

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

    def test_the_shared_git_helper_runs_under_the_environment_it_is_given_and_defaults_to_the_shared_one(self):
        with tempfile.TemporaryDirectory() as root:
            ts.git(root, "init", "-q", "-b", "main")
            own = ts.git_env("Zed", "zed@example.invalid")
            self.assertIn("Zed <zed@example.invalid>", ts.git(root, "var", "GIT_AUTHOR_IDENT", env=own))
            self.assertIn("test <test> ", ts.git(root, "var", "GIT_AUTHOR_IDENT"))

    def test_the_guard_catches_a_hand_built_environment(self):
        # Each of these is how a test could give git an environment of its own, and so a shell that starts upkeep.
        for name in sorted(OWN_ENVIRONMENT_KEYS):
            for shape, source in (
                ("a dict display", f"env = {{'{name}': 'x'}}\n"),
                ("dict() keywords", f"env = dict(os.environ, {name}='x')\n"),
            ):
                with self.subTest(f"{shape} with {name}"):
                    self.assertEqual(len(environment_problems(source)), 1, source)

    def test_the_guard_catches_a_git_command_run_without_an_environment(self):
        for call in ("run", "check_output", "check_call", "Popen"):
            for source in (
                f"subprocess.{call}(['git', '-C', root, 'status'])\n",
                f"subprocess.{call}(('git', 'status'), check=True)\n",
                f"subprocess.{call}(['git', 'status'], **options)\n",
            ):
                with self.subTest(source):
                    self.assertEqual(len(environment_problems(source)), 1, source)

    def test_the_guard_passes_what_it_should(self):
        for source in (
            "subprocess.run(['git', 'status'], env=env)\n",
            "subprocess.check_output(['git', 'log'], env=ts.GIT_ENV, text=True)\n",
            "subprocess.run([sys.executable, 'tool.py'], capture_output=True)\n",
            "subprocess.run(['jq', '-r', expression])\n",
            "subprocess.run(command)\n",
            "env = dict(os.environ, GIT_AUTHOR_DATE='d', GIT_COMMITTER_DATE='d')\n",
            "env = ts.git_env('t', 't@example.invalid')\n",
        ):
            with self.subTest(source):
                self.assertEqual(environment_problems(source), [])

    def test_no_test_module_builds_its_own_git_environment_or_runs_git_without_one(self):
        # What a module DOES is checked, not what it names: a dict built with an identity or config variable, or a
        # git command started without env=. Only test_*.py is read: _testsupport.py (which builds the
        # environment) and fakes.py are helpers, and the production modules run git in their caller's environment.
        modules = sorted(glob.glob(os.path.join(HERE, "test_*.py")))
        self.assertIn(os.path.abspath(__file__), [os.path.abspath(path) for path in modules])
        for path in modules:
            with self.subTest(os.path.basename(path)):
                with open(path, encoding="utf-8") as handle:
                    problems = environment_problems(handle.read(), os.path.basename(path))
                # Not assertEqual: its failure would print the whole module.
                self.assertFalse(problems, "; ".join(problems))


if __name__ == "__main__":
    unittest.main()
