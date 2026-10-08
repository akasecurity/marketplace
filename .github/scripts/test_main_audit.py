"""Tests for main_audit.py: every first-parent commit a push adds must be a code-owner-approved PR merge that passed validate."""
import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

import _testsupport as ts
import issue_router as rt
import main_audit as ma
import tag_release as tr
from fakes import BOT, CODEOWNERS, REPO, FakeGit, FakeGitHub
from ghapi import GitHubError
from gitrepo import Git
from release_checks import GITHUB_ACTIONS_APP_ID


def R(suffix):
    return f"repos/{REPO}/{suffix}"


def repo() -> FakeGit:
    return FakeGit(chain=["p", "s1", "s2"], files={(sha, ".github/CODEOWNERS"): CODEOWNERS for sha in ("p", "s1", "s2")})


@contextlib.contextmanager
def scratch_repo():
    """An empty repository on main in a temporary directory: yields (path, sh, commit), where `commit(name, text)`
    writes a file, commits it and returns its sha."""
    with tempfile.TemporaryDirectory() as root:
        env = ts.git_env("t", "t@example.invalid")

        def sh(*args):
            return ts.git(root, *args, env=env).strip()

        def commit(name, text=None):
            path = os.path.join(root, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(name if text is None else text)
            sh("add", name)
            sh("commit", "-q", "-m", name)
            return sh("rev-parse", "HEAD")

        sh("init", "-q", "-b", "main")
        yield root, sh, commit


MERGED_AT = "2026-10-05T10:00:00Z"  # when pr_routes' pull request merged
BEFORE_THE_MERGE = "2026-10-05T09:59:00Z"
AFTER_THE_MERGE = "2026-10-05T10:00:01Z"


def suite_of(run_id: int) -> int:
    """The id of the check suite a test check run is in: one suite for each run, as GitHub Actions makes them."""
    return 9000 + run_id


def validate_run(run_id=7, *, conclusion="success", status="completed", name="validate", app=GITHUB_ACTIONS_APP_ID,
                 started_at=BEFORE_THE_MERGE, suite=None) -> dict:
    """A check run as the API lists it: by default the green `validate` run of GitHub Actions, started a minute
    before the merge, in a check suite of its own (pr_routes makes that suite a pull_request_target run of validate.yml)."""
    return {"id": run_id, "name": name, "status": status, "conclusion": conclusion, "app": {"id": app},
            "started_at": started_at, "check_suite": {"id": suite_of(run_id) if suite is None else suite}}


def workflow_run(suite: int, *, event=tr.VALIDATE_EVENT, path=tr.VALIDATE_WORKFLOW) -> dict:
    """A workflow run as the API lists it for a check suite."""
    return {"id": suite - 1000, "check_suite_id": suite, "name": "validate", "event": event, "path": path,
            "created_at": "2026-10-05T09:50:00Z"}


def pr_routes(sha, *, number=30, head="h30", pulls=None, author=BOT, committer=BOT, reviews=None, runs=None,
              workflows=None, merged_at=MERGED_AT) -> dict:
    """The routes main-audit reads for the pull request that merged `sha`. `workflows` maps a check suite's id to
    the workflow runs the API lists for it (a suite it does not name lists none); left out, every suite is one
    pull_request_target run of validate.yml."""
    runs = [validate_run()] if runs is None else runs

    def listed(body, params):
        suite = params["check_suite_id"]
        found = [workflow_run(suite)] if workflows is None else workflows.get(suite, [])
        return {"total_count": len(found), "workflow_runs": found}

    return {
        ("GET", R("actions/runs")): listed,
        ("GET", R(f"commits/{sha}/pulls")): pulls if pulls is not None else [
            {"number": number, "merge_commit_sha": sha, "merged_at": merged_at, "base": {"ref": "main"}}],
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
        self.assertIn("only the new tip was audited", results[0].detail)

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
        with scratch_repo() as (root, sh, commit):
            for name in ("a", "b", "c"):
                commit(name)
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
        with scratch_repo() as (root, sh, commit):
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

    def test_a_rebase_merge_reports_each_rebased_commit_but_the_last(self):
        # A rebase merge puts every commit of the pull request on main as a new commit, and names only the last as
        # the pull request's merge commit. Each earlier one is on the first-parent line with no pull request of its
        # own, so it is reported; the last is audited as the merge, and passes.
        with scratch_repo() as (root, sh, commit):
            commit(".github/CODEOWNERS", CODEOWNERS)
            sh("switch", "-q", "-c", "feature")
            first_branch, second_branch = commit("one", "1"), commit("two", "2")
            sh("switch", "-q", "main")
            before = commit("moved", "m")  # main moved on while the pull request was open
            sh("cherry-pick", first_branch)
            rebased_first = sh("rev-parse", "HEAD")
            sh("cherry-pick", second_branch)
            rebased_last = sh("rev-parse", "HEAD")
            self.assertEqual(len({first_branch, second_branch, rebased_first, rebased_last}), 4)
            merged = [{"number": 40, "merge_commit_sha": rebased_last, "merged_at": "2026-10-05T10:00:00Z",
                       "base": {"ref": "main"}}]
            gh = FakeGitHub({**pr_routes(rebased_last, number=40, head="h40", pulls=merged),
                             ("GET", R(f"commits/{rebased_first}/pulls")): merged})
            results = ma.audit(Git(root), gh, before, rebased_last, sleep=lambda seconds: None)
        self.assertEqual([(item.rule, item.red, item.auto_close) for item in results],
                         [(f"main-audit-{rebased_first[:12]}", True, False), ("main-audit", False, False)])
        self.assertIn("is not the merge commit of any pull request", results[0].detail)
        self.assertIn(f"links it to PR #40, which merged into main at `{rebased_last}`", results[0].detail)
        self.assertIn("one of the commits of a rebase merge", results[0].detail)
        self.assertNotIn("pushed to main directly", results[0].detail)
        self.assertEqual(results[-1].detail, "2 commit(s) audited in this push, 1 flagged.")

    def test_a_rewrite_audits_every_first_parent_commit_after_the_merge_base(self):
        with scratch_repo() as (root, sh, commit):
            commit(".github/CODEOWNERS", CODEOWNERS)
            base = commit("a")
            old_tip = commit("b")
            sh("branch", "old", old_tip)  # the old tip is still in the checkout, so the merge base can be found
            sh("reset", "-q", "--hard", base)
            first, second = commit("c"), commit("d")
            gh = FakeGitHub({("GET", R(f"commits/{first}/pulls")): [], ("GET", R(f"commits/{second}/pulls")): []})
            results = ma.audit(Git(root), gh, old_tip, second, sleep=lambda seconds: None)
        self.assertEqual([item.rule for item in results],
                         [f"main-audit-rewrite-{second[:12]}", f"main-audit-{first[:12]}", f"main-audit-{second[:12]}",
                          "main-audit"])
        self.assertIn(f"after their merge base `{base[:12]}`", results[0].detail)
        self.assertEqual(results[-1].detail, "2 commit(s) audited in this push, 3 flagged.")
        self.assertEqual(gh.called("GET", R(f"commits/{old_tip}/pulls")), [])

    def test_a_rewrite_that_adds_nothing_past_the_merge_base_still_audits_the_new_tip(self):
        results = ma.audit(repo(), github(), "s2", "s1", sleep=lambda seconds: None)
        self.assertEqual([item.rule for item in results], ["main-audit-rewrite-s1", "main-audit"])
        self.assertIn("adds nothing after their merge base `s1`", results[0].detail)
        self.assertEqual(results[-1].detail, "1 commit(s) audited in this push, 1 flagged.")

    def test_a_rewrite_with_no_shared_history_audits_the_new_tip_only(self):
        with scratch_repo() as (root, sh, commit):
            commit(".github/CODEOWNERS", CODEOWNERS)
            tip = commit("b")
            sh("switch", "-q", "--orphan", "other")
            unrelated = commit("x")
            sh("switch", "-q", "main")
            gh = FakeGitHub({("GET", R(f"commits/{tip}/pulls")): []})
            results = ma.audit(Git(root), gh, unrelated, tip, sleep=lambda seconds: None)
        self.assertEqual([item.rule for item in results],
                         [f"main-audit-rewrite-{tip[:12]}", f"main-audit-{tip[:12]}", "main-audit"])
        self.assertIn("share no history", results[0].detail)
        self.assertIn("only the new tip was audited", results[0].detail)

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

    def test_a_commit_linked_to_a_pull_request_merged_at_another_commit_is_called_part_of_a_rebase_merge(self):
        other_merge = [{"number": 40, "merge_commit_sha": "s2", "merged_at": "2026-10-05T10:00:00Z",
                        "base": {"ref": "main"}}]
        gh = github(pulls=other_merge)
        results = self.audit(gh)
        self.assertEqual([(item.rule, item.red, item.auto_close) for item in results],
                         [("main-audit-s1", True, False)])
        self.assertIn("`s1` is not the merge commit of any pull request. GitHub links it to PR #40, which merged "
                      "into main at `s2`", results[0].detail)
        self.assertIn("a rebase merge", results[0].detail)
        self.assertIn("allows squash merges only", results[0].detail)
        self.assertNotIn("pushed to main directly", results[0].detail)
        # The wording comes from the answer the lookup already read: no ask beyond the lookup's own.
        self.assertEqual(len(gh.called("GET", R("commits/s1/pulls"))), tr.ASSOCIATION_ATTEMPTS)

    def test_a_commit_linked_only_to_a_pull_request_that_did_not_merge_into_main_is_a_direct_push(self):
        stamp = "2026-10-05T10:00:00Z"
        for label, pull in (
                ("an open pull request", {"number": 41, "merge_commit_sha": None, "merged_at": None,
                                          "base": {"ref": "main"}}),
                ("a closed one that never merged", {"number": 42, "merge_commit_sha": "s2", "merged_at": None,
                                                    "base": {"ref": "main"}}),
                ("one merged into another branch", {"number": 43, "merge_commit_sha": "s2", "merged_at": stamp,
                                                    "base": {"ref": "release"}}),
                ("one with no base", {"number": 44, "merge_commit_sha": "s2", "merged_at": stamp}),
                ("a merged one with no merge commit", {"number": 45, "merge_commit_sha": None, "merged_at": stamp,
                                                       "base": {"ref": "main"}})):
            with self.subTest(label):
                results = self.audit(github(pulls=[pull]))
                self.assertEqual(len(results), 1)
                self.assertIn("is not the merge commit of any pull request: it was pushed to main directly.",
                              results[0].detail)
                self.assertNotIn("rebase", results[0].detail)

    def test_an_approval_on_a_stale_head_does_not_count(self):
        results = self.audit(github(reviews=[{"state": "APPROVED", "commit_id": "old", "user": {"login": "venuverse"}}]))
        self.assertIn("without an approving review from a code owner", results[0].detail)

    def test_an_approval_from_the_last_pusher_does_not_count(self):
        results = self.audit(github(author="venuverse", committer="web-flow"))
        self.assertEqual(len(results), 1)
        self.assertIn("last pusher (venuverse)", results[0].detail)

    def test_a_head_whose_pusher_cannot_be_named_is_red_whoever_approved(self):
        # The head commit's author and committer are the stand-in for the last pusher. When neither is a login
        # (an email GitHub cannot match to an account; web-flow alone), the approver cannot be told from the
        # pusher, so an owner's approval is not accepted on trust.
        cases = {
            "an author with no account and a web committer": dict(author=None, committer="web-flow"),
            "only web-flow": dict(author="web-flow", committer="web-flow"),
            "an empty login": dict(author="", committer=""),
        }
        for label, kwargs in cases.items():
            with self.subTest(label):
                results = self.audit(github(**kwargs))
                self.assertEqual(len(results), 1)
                self.assertIn("could not identify who pushed its final head `h30`", results[0].detail)
        routes = pr_routes("s1")
        routes[("GET", R("commits/h30"))] = {"author": None, "committer": None}  # no author or committer object at all
        results = self.audit(FakeGitHub(routes))
        self.assertEqual(len(results), 1)
        self.assertIn("could not identify who pushed", results[0].detail)

    def test_a_pusher_named_by_either_field_is_enough_to_judge_the_approval(self):
        for kwargs in (dict(author=None, committer="Vaishnav-OM"), dict(author="Vaishnav-OM", committer=None)):
            with self.subTest(**kwargs):
                self.assertEqual(self.audit(github(**kwargs)), [])
        # ... and it is still the pusher's own approval that is refused.
        results = self.audit(github(author=None, committer="venuverse"))
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
        for label, run, state in (("failed", validate_run(conclusion="failure"), "failure"),
                                  ("cancelled", validate_run(conclusion="cancelled"), "cancelled"),
                                  ("skipped", validate_run(conclusion="skipped"), "skipped"),
                                  ("neutral", validate_run(conclusion="neutral"), "neutral"),
                                  ("completed with no conclusion", validate_run(conclusion=None),
                                   "without a result"),
                                  ("still running", validate_run(status="in_progress", conclusion=None),
                                   "in_progress"),
                                  ("queued", validate_run(status="queued", conclusion=None), "queued")):
            with self.subTest(label):
                results = self.audit(github(runs=[run]))
                self.assertEqual(len(results), 1)
                self.assertIn("without a passing `validate` check from GitHub Actions on its final head `h30`",
                              results[0].detail)
                self.assertIn(f"its latest run: {state}.", results[0].detail)

    def test_a_merge_with_no_validate_run_is_red(self):
        results = self.audit(github(runs=[]))
        self.assertEqual(len(results), 1)
        self.assertIn("without a passing `validate` check", results[0].detail)
        self.assertIn("none ran", results[0].detail)

    def test_a_run_of_another_workflow_file_or_started_by_another_event_does_not_count(self):
        # A job named validate in any other workflow, or in validate.yml run for a push or a pull request, reports
        # the same check name. Only validate.yml run by pull_request_target is the required check.
        for label, workflow in {
                "another file": workflow_run(suite_of(7), path=".github/workflows/ci.yml"),
                "a lookalike path": workflow_run(suite_of(7), path=".github/workflows/validate.yml.bak"),
                "a push": workflow_run(suite_of(7), event="push"),
                "a pull request": workflow_run(suite_of(7), event="pull_request"),
                "no event": {"path": tr.VALIDATE_WORKFLOW}}.items():
            with self.subTest(label):
                results = self.audit(github(workflows={suite_of(7): [workflow]}))
                self.assertEqual(len(results), 1)
                self.assertIn("none ran before it merged", results[0].detail)

    def test_a_pass_from_another_workflow_cannot_stand_in_for_a_failed_validate(self):
        failed, impostor = validate_run(7, conclusion="failure"), validate_run(9)
        for label, runs in (("oldest first", [failed, impostor]), ("newest first", [impostor, failed])):
            with self.subTest(label):
                results = self.audit(github(runs=runs, workflows={
                    suite_of(7): [workflow_run(suite_of(7))],
                    suite_of(9): [workflow_run(suite_of(9), path=".github/workflows/ci.yml")]}))
                self.assertEqual(len(results), 1)
                self.assertIn("its latest run: failure.", results[0].detail)

    def test_a_failure_from_another_workflow_does_not_fail_a_validated_merge(self):
        runs = [validate_run(7), validate_run(9, conclusion="failure")]
        self.assertEqual(self.audit(github(runs=runs, workflows={
            suite_of(7): [workflow_run(suite_of(7))],
            suite_of(9): [workflow_run(suite_of(9), path=".github/workflows/ci.yml")]})), [])

    def test_a_green_run_after_the_merge_does_not_clear_a_merge_past_a_failed_validate(self):
        # An edit of the closed PR, or a manual re-run, starts validate again on the same head.
        failed, rerun = validate_run(7, conclusion="failure"), validate_run(9, started_at=AFTER_THE_MERGE)
        for label, runs in (("oldest first", [failed, rerun]), ("newest first", [rerun, failed])):
            with self.subTest(label):
                results = self.audit(github(runs=runs))
                self.assertEqual(len(results), 1)
                self.assertIn("its latest run: failure.", results[0].detail)

    def test_a_failed_run_after_the_merge_does_not_fail_a_validated_merge(self):
        later = validate_run(9, conclusion="failure", started_at=AFTER_THE_MERGE)
        self.assertEqual(self.audit(github(runs=[validate_run(7), later])), [])

    def test_a_head_whose_only_run_started_after_the_merge_had_none_before_it(self):
        results = self.audit(github(runs=[validate_run(9, started_at=AFTER_THE_MERGE)]))
        self.assertEqual(len(results), 1)
        self.assertIn("none ran before it merged", results[0].detail)

    def test_a_run_queued_before_the_merge_and_started_after_it_does_not_count(self):
        # The workflow run was created before the merge, as a re-run's is; the job started after it.
        rerun = validate_run(9, started_at=AFTER_THE_MERGE)
        self.assertEqual(len(self.audit(github(runs=[validate_run(7, conclusion="failure"), rerun]))), 1)

    def test_a_run_that_started_in_the_second_of_the_merge_counts(self):
        self.assertEqual(self.audit(github(runs=[validate_run(7, started_at=MERGED_AT)])), [])

    def test_the_time_the_pull_request_merged_is_the_one_the_runs_are_compared_with(self):
        run = validate_run(7, started_at="2026-10-05T10:03:00Z")
        self.assertEqual(self.audit(github(runs=[run], merged_at="2026-10-05T10:05:00Z")), [])
        self.assertEqual(len(self.audit(github(runs=[run], merged_at="2026-10-05T10:01:00Z"))), 1)

    def test_a_merge_whose_time_cannot_be_read_leaves_no_run_to_count(self):
        # The check cannot be placed before a merge whose time is unknown, so it is not taken to have passed.
        for merged_at in ("yesterday", "2026-10-05", "2026-10-05T10:00:00+00:00"):
            with self.subTest(merged_at):
                results = self.audit(github(merged_at=merged_at))
                self.assertEqual(len(results), 1)
                self.assertIn("none ran before it merged", results[0].detail)

    def test_the_workflow_run_is_asked_for_through_the_check_suite_of_the_run_that_decides(self):
        gh = github(runs=[validate_run(5), validate_run(9)])
        self.assertEqual(self.audit(gh), [])
        self.assertEqual([call[3] for call in gh.called("GET", R("actions/runs"))], [{"check_suite_id": suite_of(9)}])

    def test_a_workflow_run_read_that_fails_is_a_push_the_audit_could_not_finish(self):
        gh = github()
        gh.routes[("GET", R("actions/runs"))] = GitHubError(403, "GET", R("actions/runs"), "Resource not accessible")
        results = [item for item in ma.audit(repo(), gh, "p", "s1", sleep=lambda seconds: None) if item.red]
        self.assertEqual([item.rule for item in results], ["main-audit-unaudited-s1"])
        self.assertIn("403", results[0].detail)

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

    def test_an_approval_the_owner_later_withdrew_does_not_count(self):
        def review(state, login="venuverse", commit="h30"):
            return {"state": state, "commit_id": commit, "user": {"login": login}}

        for label, reviews, expected in (
                ("changes requested after the approval", [review("APPROVED"), review("CHANGES_REQUESTED")], 1),
                ("a dismissed review after the approval", [review("APPROVED"), review("DISMISSED")], 1),
                ("a comment after the approval changes nothing", [review("APPROVED"), review("COMMENTED")], 0),
                ("an approval after the request for changes", [review("CHANGES_REQUESTED"), review("APPROVED")], 0),
                ("one owner withdrew and the other approved",
                 [review("APPROVED"), review("CHANGES_REQUESTED"), review("APPROVED", "Vaishnav-OM")], 0),
                ("both owners withdrew",
                 [review("APPROVED"), review("APPROVED", "Vaishnav-OM"), review("CHANGES_REQUESTED"),
                  review("CHANGES_REQUESTED", "Vaishnav-OM")], 1)):
            with self.subTest(label):
                results = self.audit(github(reviews=reviews))
                self.assertEqual(len(results), expected)
                if expected:
                    self.assertIn("without an approving review from a code owner", results[0].detail)

    def test_a_codeowners_file_it_cannot_read_is_that_commits_problem(self):
        files = {
            "a team": "* @akasecurity/maintainers\n",
            "a team beside a user": "* @akasecurity/maintainers @venuverse\n",
            "an email address": "* owner@example.invalid @venuverse\n",
            "a path rule": "/docs @writer-example\n* @Vaishnav-OM @venuverse\n",
            "a second star rule": "* @Vaishnav-OM\n* @venuverse\n",
            "no owner on the star line": "*\n",
            "no file": None,
            "bytes that are not UTF-8": b"# caf\xe9 team\n* @Vaishnav-OM @venuverse\n",
        }
        for label, text in files.items():
            with self.subTest(label):
                git = FakeGit(chain=["p", "s1", "s2"], files={
                    **({("p", ".github/CODEOWNERS"): text} if text is not None else {}),
                    ("s1", ".github/CODEOWNERS"): CODEOWNERS})
                results = self.audit(github(), git)
                self.assertEqual([item.rule for item in results], ["main-audit-s1"])
                self.assertIn("its approval could not be checked: .github/CODEOWNERS at p", results[0].detail)

    def test_an_unreadable_codeowners_file_does_not_stop_the_rest_of_the_push_being_audited(self):
        # A file that is not UTF-8 text is as unreadable as a team owner: a red result for its commit, not a crash
        # that would leave the later commits of the push unchecked.
        for label, text in {"a team": "* @akasecurity/maintainers\n",
                            "bytes that are not UTF-8": b"# caf\xe9 team\n* @Vaishnav-OM\n"}.items():
            with self.subTest(label):
                git = FakeGit(chain=["p", "s1", "s2"], files={("p", ".github/CODEOWNERS"): text,
                                                               ("s1", ".github/CODEOWNERS"): CODEOWNERS})
                gh = FakeGitHub({**pr_routes("s1"), **pr_routes("s2", number=31, head="h31", runs=[])})
                results = ma.audit(git, gh, "p", "s2", sleep=lambda seconds: None)
                self.assertEqual([(item.rule, item.red) for item in results],
                                 [("main-audit-s1", True), ("main-audit-s2", True), ("main-audit", False)])
                self.assertIn("could not be checked", results[0].detail)
                self.assertNotIn("could not be checked", results[1].detail)  # s2 is read at s1, whose file is fine
                self.assertIn("without a passing `validate` check", results[1].detail)

    def test_an_unreadable_codeowners_file_and_a_failed_validate_are_one_result(self):
        git = FakeGit(chain=["p", "s1"], files={("p", ".github/CODEOWNERS"): "* @akasecurity/maintainers\n"})
        results = self.audit(github(runs=[validate_run(conclusion="failure")]), git)
        self.assertEqual(len(results), 1)
        self.assertIn("could not be checked", results[0].detail)
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
