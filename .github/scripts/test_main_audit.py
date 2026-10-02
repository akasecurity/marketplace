"""Tests for main_audit.py: every commit a push adds must be a code-owner-approved PR merge."""
import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import issue_router as rt
import main_audit as ma
from fakes import BOT, CODEOWNERS, REPO, FakeGit, FakeGitHub
from ghapi import GitHubError
from gitrepo import Git
from release_checks import GITHUB_ACTIONS_APP_ID


def R(suffix):
    return f"repos/{REPO}/{suffix}"


def repo() -> FakeGit:
    return FakeGit(chain=["p", "s1", "s2"], files={(sha, ".github/CODEOWNERS"): CODEOWNERS for sha in ("p", "s1", "s2")})


def validate_run(run_id=7, *, conclusion="success", status="completed", name="validate", app=GITHUB_ACTIONS_APP_ID) -> dict:
    """A check run as the API lists it: by default the green `validate` run of GitHub Actions."""
    return {"id": run_id, "name": name, "status": status, "conclusion": conclusion, "app": {"id": app}}


def pr_routes(sha, *, number=30, head="h30", pulls=None, author=BOT, committer=BOT, reviews=None, runs=None) -> dict:
    """The routes main-audit reads for the pull request that merged `sha`."""
    runs = [validate_run()] if runs is None else runs
    return {
        ("GET", R(f"commits/{sha}/pulls")): pulls if pulls is not None else [
            {"number": number, "merge_commit_sha": sha, "merged_at": "2026-10-05T10:00:00Z", "base": {"ref": "main"}}],
        ("GET", R(f"pulls/{number}")): {"head": {"sha": head}},
        ("GET", R(f"commits/{head}")): {"author": {"login": author}, "committer": {"login": committer}},
        ("GET", R(f"pulls/{number}/reviews")): reviews if reviews is not None else [
            {"state": "APPROVED", "commit_id": head, "user": {"login": "venuverse"}}],
        ("GET", R(f"commits/{head}/check-runs")): {"total_count": len(runs), "check_runs": runs},
    }


def github(**kwargs) -> FakeGitHub:
    return FakeGitHub(pr_routes("s1", **kwargs))


class TestMainAudit(unittest.TestCase):
    def audit(self, gh, git=None):
        return [item for item in ma.audit(git or repo(), gh, "p", "s1", sleep=lambda seconds: None) if item.red]

    def test_an_approved_bot_pr_merge_passes(self):
        self.assertEqual(self.audit(github()), [])

    def test_a_clean_push_reports_one_green_non_closing_summary(self):
        results = ma.audit(repo(), github(), "p", "s1", sleep=lambda seconds: None)
        self.assertEqual([(item.rule, item.red, item.auto_close) for item in results],
                         [("main-audit", False, False)])

        class Recorder:
            def __init__(self):
                self.applied = []

            def apply(self, result):
                self.applied.append(result)
                return result.rule

        recorder = Recorder()
        code = rt.route(rt.results_from_json(rt.results_to_json(results)), label="main-audit",
                        job_result="success", router=recorder)
        self.assertEqual(code, 0)
        self.assertEqual([item.rule for item in recorder.applied if item.red], [])

    def test_a_push_that_adds_no_commit_but_moves_main_is_red(self):
        results = [item for item in ma.audit(repo(), github(), "s2", "s1", sleep=lambda seconds: None) if item.red]
        self.assertEqual([(item.rule, item.auto_close) for item in results], [("main-audit-rewrite-s1", False)])
        self.assertIn("not an ancestor", results[0].detail)
        self.assertIn("rewritten or reset", results[0].detail)

    def test_an_old_tip_the_checkout_does_not_have_is_red_and_the_new_tip_is_still_audited(self):
        # The ordinary shape of a reset: the old tip lived only on main, so it was never fetched.
        results = ma.audit(repo(), github(pulls=[]), "gone", "s1", sleep=lambda seconds: None)
        self.assertEqual([(item.rule, item.red, item.auto_close) for item in results],
                         [("main-audit-rewrite-s1", True, False), ("main-audit-s1", True, False),
                          ("main-audit", False, False)])
        self.assertIn("not in the checkout", results[0].detail)

    def test_a_failure_part_way_keeps_what_was_found_and_is_recorded_against_the_push(self):
        git = FakeGit(chain=["p", "s1", "s2"], files={(sha, ".github/CODEOWNERS"): CODEOWNERS for sha in ("p", "s1", "s2")})
        gh = FakeGitHub({("GET", R("commits/s1/pulls")): [],
                         ("GET", R("commits/s2/pulls")): GitHubError(502, "GET", "commits/s2/pulls", "bad gateway\nretry")})
        results = ma.audit(git, gh, "p", "s2", sleep=lambda seconds: None)
        self.assertEqual([(item.rule, item.red, item.auto_close) for item in results],
                         [("main-audit-s1", True, False), ("main-audit-unaudited-s2", True, False),
                          ("main-audit", False, False)])
        self.assertIn("GitHubError", results[1].detail)
        self.assertIn("bad gateway retry", results[1].detail)
        self.assertIn("a person closes this issue", results[1].detail)

    def test_a_git_failure_is_recorded_against_the_push_instead_of_failing_the_job(self):
        class Broken(FakeGit):
            def is_ancestor(self, ancestor, descendant):
                raise ma.GitError("git merge-base failed")

        results = ma.audit(Broken(chain=["p", "s1"]), github(), "p", "s1", sleep=lambda seconds: None)
        self.assertEqual([(item.rule, item.red, item.auto_close) for item in results],
                         [("main-audit-unaudited-s1", True, False), ("main-audit", False, False)])

    def test_only_the_tip_waits_for_the_pull_request_association(self):
        waits = []
        git = FakeGit(chain=["p", "s1", "s2"], files={})
        gh = FakeGitHub({("GET", R("commits/s1/pulls")): [], ("GET", R("commits/s2/pulls")): []})
        results = ma.audit(git, gh, "p", "s2", sleep=waits.append)
        self.assertEqual(len([item for item in results if item.red]), 2)
        self.assertEqual(len(waits), 2)  # the tip's two waits between three asks; s1 asks without waiting
        self.assertEqual(len(gh.called("GET", R("commits/s1/pulls"))), 3)

    def test_a_reset_in_a_real_repository_is_red_and_does_not_raise(self):
        with tempfile.TemporaryDirectory() as root:
            env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                       GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                       GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")

            def sh(*args):
                return subprocess.run(["git", "-C", root, *args], env=env, check=True, capture_output=True,
                                      text=True).stdout.strip()

            sh("init", "-q", "-b", "main")
            for name in ("a", "b", "c"):
                with open(os.path.join(root, name), "w", encoding="utf-8") as handle:
                    handle.write(name)
                sh("add", name)
                sh("commit", "-q", "-m", name)
            old_tip, first = sh("rev-parse", "HEAD"), sh("rev-parse", "HEAD~2")
            sh("reset", "-q", "--hard", first)
            sh("reflog", "expire", "--expire=now", "--all")
            sh("gc", "-q", "--prune=now")
            git = Git(root)
            self.assertIsNone(git.is_ancestor(old_tip, first))
            self.assertTrue(git.is_ancestor(first, first))
            gh = FakeGitHub({("GET", R(f"commits/{first}/pulls")): []})
            results = ma.audit(git, gh, old_tip, first, sleep=lambda seconds: None)
        self.assertEqual([(item.rule, item.red) for item in results],
                         [(f"main-audit-rewrite-{first[:12]}", True), (f"main-audit-{first[:12]}", True),
                          ("main-audit", False)])

    def test_a_merge_commit_audits_only_mains_first_parent_commit(self):
        # A pull request merged with a merge commit puts the branch's own commits into the push too. They are
        # not on main's first-parent line and have no pull request of their own, so they are not audited.
        with tempfile.TemporaryDirectory() as root:
            env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                       GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                       GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")

            def sh(*args):
                return subprocess.run(["git", "-C", root, *args], env=env, check=True, capture_output=True,
                                      text=True).stdout.strip()

            def commit(name, text):
                path = os.path.join(root, name)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(text)
                sh("add", name)
                sh("commit", "-q", "-m", name)
                return sh("rev-parse", "HEAD")

            sh("init", "-q", "-b", "main")
            base = commit(".github/CODEOWNERS", CODEOWNERS)
            sh("switch", "-q", "-c", "feature")
            first, second = commit("one", "1"), commit("two", "2")
            sh("switch", "-q", "main")
            sh("merge", "-q", "--no-ff", "-m", "merge feature", "feature")
            merge = sh("rev-parse", "HEAD")
            gh = FakeGitHub({**pr_routes(merge, number=40, head="h40"),
                             ("GET", R(f"commits/{first}/pulls")): [], ("GET", R(f"commits/{second}/pulls")): []})
            results = ma.audit(Git(root), gh, base, merge, sleep=lambda seconds: None)
        self.assertEqual([(item.rule, item.red) for item in results], [("main-audit", False)])
        self.assertEqual(results[0].detail, "1 commit(s) audited in this push, 0 flagged.")
        self.assertEqual(gh.called("GET", R(f"commits/{first}/pulls")), [])
        self.assertEqual(gh.called("GET", R(f"commits/{second}/pulls")), [])

    def test_the_owners_are_read_at_the_commits_parent_not_the_commit_itself(self):
        # The PR's own tree makes its approver an owner; the parent's tree does not.
        git = FakeGit(chain=["p", "s1", "s2"], files={
            ("p", ".github/CODEOWNERS"): CODEOWNERS,
            ("s1", ".github/CODEOWNERS"): "* @Vaishnav-OM @venuverse @writer-example\n"})
        reviews = [{"state": "APPROVED", "commit_id": "h30", "user": {"login": "writer-example"}}]
        self.assertEqual(len(self.audit(github(reviews=reviews), git)), 1)

    def test_a_direct_push_is_red_and_waits_for_a_person_to_close_it(self):
        results = self.audit(github(pulls=[]))
        self.assertEqual(len(results), 1)
        self.assertEqual((results[0].rule, results[0].label, results[0].red, results[0].auto_close),
                         ("main-audit-s1", "main-audit", True, False))
        self.assertIn("pushed to main directly", results[0].detail)

    def test_an_approval_on_a_stale_head_does_not_count(self):
        results = self.audit(github(reviews=[{"state": "APPROVED", "commit_id": "old", "user": {"login": "venuverse"}}]))
        self.assertIn("without an approving review from a code owner", results[0].detail)

    def test_an_approval_from_the_last_pusher_does_not_count(self):
        results = self.audit(github(author="venuverse", committer="web-flow"))
        self.assertEqual(len(results), 1)
        self.assertIn("last pusher (venuverse)", results[0].detail)

    def test_a_web_commit_counts_its_author_not_web_flow(self):
        self.assertEqual(self.audit(github(author="Vaishnav-OM", committer="web-flow")), [])

    def test_a_merge_whose_final_head_passed_validate_is_green(self):
        gh = github(runs=[validate_run(5, conclusion="failure"), validate_run(9)])
        self.assertEqual(self.audit(gh), [])
        asked = gh.called("GET", R("commits/h30/check-runs"))
        self.assertEqual(len(asked), 1)
        self.assertEqual({key: asked[0][3][key] for key in ("check_name", "app_id", "filter")},
                         {"check_name": "validate", "app_id": 15368, "filter": "all"})

    def test_a_merge_past_a_failed_validate_is_red(self):
        for label, run in (("failed", validate_run(conclusion="failure")),
                           ("cancelled", validate_run(conclusion="cancelled")),
                           ("skipped", validate_run(conclusion="skipped")),
                           ("neutral", validate_run(conclusion="neutral")),
                           ("still running", validate_run(status="in_progress", conclusion=None)),
                           ("queued", validate_run(status="queued", conclusion=None))):
            with self.subTest(label):
                results = self.audit(github(runs=[run]))
                self.assertEqual(len(results), 1)
                self.assertIn("without a passing `validate` check from GitHub Actions on its final head `h30`",
                              results[0].detail)

    def test_a_merge_with_no_validate_run_is_red(self):
        results = self.audit(github(runs=[]))
        self.assertEqual(len(results), 1)
        self.assertIn("without a passing `validate` check", results[0].detail)
        self.assertIn("none ran", results[0].detail)

    def test_a_validate_run_from_another_app_does_not_count(self):
        # The API is asked for GitHub Actions' runs only, and the answer is checked again: a check with the
        # same name from any other app must not stand in for the required one.
        self.assertEqual(len(self.audit(github(runs=[validate_run(app=99)]))), 1)

    def test_a_run_with_another_name_does_not_count(self):
        self.assertEqual(len(self.audit(github(runs=[validate_run(name="lint")]))), 1)

    def test_the_latest_validate_run_decides(self):
        failed, passed = validate_run(5, conclusion="failure"), validate_run(9)
        for label, runs, expected in (
                ("a pass, then a failure", [passed, validate_run(12, conclusion="failure")], 1),
                ("a failure, then a pass", [failed, passed], 0),
                ("listed newest first", [passed, failed], 0),
                ("listed oldest last", [validate_run(12, conclusion="failure"), passed], 1)):
            with self.subTest(label):
                self.assertEqual(len(self.audit(github(runs=runs))), expected)

    def test_a_commit_with_no_approval_and_no_validate_is_one_result_naming_both(self):
        reviews = [{"state": "APPROVED", "commit_id": "old", "user": {"login": "venuverse"}}]
        results = self.audit(github(reviews=reviews, runs=[]))
        self.assertEqual(len(results), 1)
        self.assertIn("without an approving review from a code owner", results[0].detail)
        self.assertIn("without a passing `validate` check", results[0].detail)

    def test_an_approver_who_is_not_a_code_owner_does_not_count(self):
        reviews = [{"state": "APPROVED", "commit_id": "h30", "user": {"login": "writer-example"}}]
        self.assertEqual(len(self.audit(github(reviews=reviews))), 1)

    def run_main(self, gh):
        env = {"AFTER": "s1", "BEFORE": "p", "GITHUB_REPOSITORY": REPO, "GH_TOKEN": "t"}
        out = io.StringIO()
        real_audit = ma.audit
        with mock.patch.dict(os.environ, env), mock.patch.object(ma, "Git", lambda path: repo()), \
                mock.patch.object(ma, "GitHub", lambda token, repository: gh), \
                mock.patch.object(ma, "write_output", lambda key, value: None), \
                mock.patch.object(ma, "audit", lambda *args: real_audit(*args, sleep=lambda seconds: None)), \
                contextlib.redirect_stdout(out):
            code = ma.main(["--repo-dir", "."])
        return code, out.getvalue()

    def test_a_clean_push_prints_a_zero_count_summary_line(self):
        code, out = self.run_main(github())
        self.assertEqual(code, 0)
        self.assertIn("0 commit(s) in this push reached main without a code-owner-approved PR that passed validate", out)
        self.assertNotIn("::error::", out)

    def test_a_flagged_push_counts_the_red_commits_in_the_summary_line(self):
        code, out = self.run_main(github(pulls=[]))
        self.assertEqual(code, 0)
        self.assertIn("1 commit(s) in this push reached main without a code-owner-approved PR that passed validate", out)
        self.assertIn("::error::", out)

    def test_a_rewrite_is_not_counted_as_a_commit_in_the_summary_line(self):
        env = {"AFTER": "s1", "BEFORE": "gone", "GITHUB_REPOSITORY": REPO, "GH_TOKEN": "t"}
        out = io.StringIO()
        real_audit = ma.audit
        with mock.patch.dict(os.environ, env), mock.patch.object(ma, "Git", lambda path: repo()), \
                mock.patch.object(ma, "GitHub", lambda token, repository: github()), \
                mock.patch.object(ma, "write_output", lambda key, value: None), \
                mock.patch.object(ma, "audit", lambda *args: real_audit(*args, sleep=lambda seconds: None)), \
                contextlib.redirect_stdout(out):
            code = ma.main(["--repo-dir", "."])
        self.assertEqual(code, 0)
        self.assertIn("0 commit(s) in this push reached main without a code-owner-approved PR that passed validate", out.getvalue())
        self.assertIn("1 other problem(s) with this push", out.getvalue())

    def test_the_commits_a_push_added(self):
        self.assertEqual(ma.added_commits(repo(), "0" * 40, "s2"), ["s2"])
        self.assertEqual(ma.added_commits(repo(), "p", "s2"), ["s1", "s2"])


if __name__ == "__main__":
    unittest.main()
