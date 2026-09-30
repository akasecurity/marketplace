"""Tests for main_audit.py: every commit a push adds must be a code-owner-approved PR merge."""
import unittest

import issue_router as rt
import main_audit as ma
from fakes import BOT, CODEOWNERS, REPO, FakeGit, FakeGitHub


def R(suffix):
    return f"repos/{REPO}/{suffix}"


def repo() -> FakeGit:
    return FakeGit(chain=["p", "s1", "s2"], files={(sha, ".github/CODEOWNERS"): CODEOWNERS for sha in ("p", "s1", "s2")})


def github(*, pulls=None, author=BOT, committer=BOT, reviews=None) -> FakeGitHub:
    return FakeGitHub({
        ("GET", R("commits/s1/pulls")): pulls if pulls is not None else [
            {"number": 30, "merge_commit_sha": "s1", "merged_at": "2026-10-05T10:00:00Z"}],
        ("GET", R("pulls/30")): {"head": {"sha": "h30"}},
        ("GET", R("commits/h30")): {"author": {"login": author}, "committer": {"login": committer}},
        ("GET", R("pulls/30/reviews")): reviews if reviews is not None else [
            {"state": "APPROVED", "commit_id": "h30", "user": {"login": "venuverse"}}],
    })


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
        self.assertIn("rewritten or reset", results[0].detail)

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

    def test_an_approver_who_is_not_a_code_owner_does_not_count(self):
        reviews = [{"state": "APPROVED", "commit_id": "h30", "user": {"login": "writer-example"}}]
        self.assertEqual(len(self.audit(github(reviews=reviews))), 1)

    def test_the_commits_a_push_added(self):
        self.assertEqual(ma.added_commits(repo(), "0" * 40, "s2"), ["s2"])
        self.assertEqual(ma.added_commits(repo(), "p", "s2"), ["s1", "s2"])


if __name__ == "__main__":
    unittest.main()
