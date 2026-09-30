"""Tests for tag_release.py: the sweep, the tag message, the PR facts and the branch clean-up."""
import unittest

import tag_release as tr
from fakes import (CODEOWNERS, INTEGRITY, REPO, FakeGit, FakeGitHub, fleet_tag, manifest, not_found, pull,
                   pulls_route, safety, safety_entry)
from import_release import Refused
from release_checks import MANIFEST, SAFETY_FILE


def R(suffix):
    return f"repos/{REPO}/{suffix}"


def history(chain=("t8", "a", "b", "c", "d")) -> FakeGit:
    """main after fleet-v8 ("t8", 0.9.14): a description-only merge ("a"), a release to 0.9.15 ("b"),
    a rollback to 0.9.14 ("c"), and the entry's removal ("d")."""
    older = {"0.9.14": safety_entry("0.9.14", "0.9.13")}
    newer = dict(older, **{"0.9.15": safety_entry("0.9.15", "0.9.14", "additive", ())})
    content = {"t8": (manifest("0.9.14", INTEGRITY["0.9.14"]), older),
               "a": (manifest("0.9.14", INTEGRITY["0.9.14"]), older),
               "b": (manifest("0.9.15", INTEGRITY["0.9.15"]), newer),
               "c": (manifest("0.9.14", INTEGRITY["0.9.14"]), newer),
               "d": (manifest(entry=False), newer)}
    files = {}
    for sha, (text, table) in content.items():
        files[(sha, MANIFEST)] = text
        files[(sha, SAFETY_FILE)] = safety(table)
        files[(sha, ".github/CODEOWNERS")] = CODEOWNERS
    return FakeGit(chain=list(chain), files=files, tags=[fleet_tag(7, "t7"), fleet_tag(8, "t8")])


def sweep_github() -> FakeGitHub:
    return FakeGitHub({
        ("GET", R("git/ref/tags/fleet-v9")): not_found(),
        ("GET", R("git/ref/tags/fleet-v10")): not_found(),
        ("GET", R("git/ref/tags/fleet-v11")): not_found(),
        ("GET", R("commits/b/pulls")): [{"number": 13, "merge_commit_sha": "b", "merged_at": "2026-10-02T00:00:00Z"}],
        ("GET", R("pulls/13")): {"head": {"sha": "h13"}, "labels": [], "merged_by": {"login": "venuverse"}},
        ("GET", R("pulls/13/reviews")): [
            {"state": "COMMENTED", "commit_id": "h13", "user": {"login": "Vaishnav-OM"}},
            {"state": "APPROVED", "commit_id": "h13", "user": {"login": "venuverse"}}],
        ("GET", R("commits/c/pulls")): [
            {"number": 15, "merge_commit_sha": "other", "merged_at": None},
            {"number": 14, "merge_commit_sha": "c", "merged_at": "2026-10-03T00:00:00Z"}],
        ("GET", R("pulls/14")): {"head": {"sha": "h14"}, "labels": [{"name": "rollback"}, {"name": "drill"}],
                                 "merged_by": {"login": "org-owner-example"}},
        ("GET", R("pulls/14/reviews")): [
            {"state": "APPROVED", "commit_id": "stale14", "user": {"login": "Vaishnav-OM"}},
            {"state": "APPROVED", "commit_id": "h14", "user": {"login": "writer-example"}}],
        ("GET", R("commits/d/pulls")): [],
        ("POST", R("git/tags")): lambda body, params: {"sha": "object-" + body["tag"]},
        ("POST", R("git/refs")): {"ref": "created"},
    })


class TestPending(unittest.TestCase):
    def test_each_untagged_version_change_oldest_first(self):
        self.assertEqual(tr.pending(history()), ["b", "c", "d"])

    def test_a_commit_that_already_carries_a_tag_is_skipped(self):
        git = history()
        git.tags.append(fleet_tag(9, "b"))
        self.assertEqual(tr.pending(git), ["c", "d"])

    def test_nothing_to_tag_when_the_pin_did_not_change(self):
        self.assertEqual(tr.pending(history(chain=("t8", "a"))), [])


class TestSweep(unittest.TestCase):
    def test_contiguous_annotated_tags_with_the_contract_message(self):
        gh = sweep_github()
        waits = []
        self.assertEqual(tr.sweep(history(), gh, sleep=waits.append),
                         ["fleet-v9 -> b (ai-tc 0.9.15)", "fleet-v10 -> c (ai-tc 0.9.14)",
                          "fleet-v11 -> d (ai-tc entry removed)"])
        self.assertEqual(len(gh.called("GET", R("commits/d/pulls"))), 3)  # an empty association is asked again
        self.assertEqual(waits, [20.0, 20.0])
        tags = [call[2] for call in gh.called("POST", R("git/tags"))]
        self.assertEqual([(t["tag"], t["object"], t["type"]) for t in tags],
                         [("fleet-v9", "b", "commit"), ("fleet-v10", "c", "commit"), ("fleet-v11", "d", "commit")])
        self.assertEqual(tags[0]["message"], "fleet-v9: ai-tc 0.9.15\n\nversion: 0.9.15\n"
                         f"integrity: {INTEGRITY['0.9.15']}\npr: 13\napprover: venuverse\nstore-migration: additive\n")
        self.assertEqual(tags[1]["message"], "fleet-v10: ai-tc 0.9.14\n\nversion: 0.9.14\n"
                         f"integrity: {INTEGRITY['0.9.14']}\npr: 14\napprover: none\nstore-migration: additive\n"
                         "rollback-from: 0.9.15\ndrill: true\napprover-note: ruleset bypass by org-owner-example\n")
        self.assertEqual(tags[2]["message"], "fleet-v11: ai-tc entry removed\n\nversion: entry removed\n"
                         "integrity: none\npr: none\napprover: none\nstore-migration: none\n"
                         "approver-note: no pull request merged this commit\n")
        self.assertEqual([call[2] for call in gh.called("POST", R("git/refs"))],
                         [{"ref": "refs/tags/fleet-v9", "sha": "object-fleet-v9"},
                          {"ref": "refs/tags/fleet-v10", "sha": "object-fleet-v10"},
                          {"ref": "refs/tags/fleet-v11", "sha": "object-fleet-v11"}])

    def test_a_next_tag_that_already_exists_on_github_stops_the_sweep(self):
        gh = sweep_github()
        gh.routes[("GET", R("git/ref/tags/fleet-v9"))] = {"ref": "refs/tags/fleet-v9"}
        with self.assertRaisesRegex(Refused, "fleet-v9 already exists"):
            tr.sweep(history(), gh, sleep=lambda seconds: None)
        self.assertEqual(gh.writes(), [])

    def test_an_association_that_appears_on_the_second_ask_is_used(self):
        answers = [[], [{"number": 13, "merge_commit_sha": "b", "merged_at": "2026-10-02T00:00:00Z"}]]
        gh = sweep_github()
        gh.routes[("GET", R("commits/b/pulls"))] = lambda body, params: answers.pop(0)
        self.assertEqual(tr.merged_pull(gh, "b", sleep=lambda seconds: None)["number"], 13)

    def test_a_forward_version_without_a_safety_entry_records_unknown(self):
        git = FakeGit(chain=["t8", "b"], files={("b", SAFETY_FILE): safety({})})
        self.assertEqual(tr.store_migration(git, "b", "0.9.15", "0.9.14"), "unknown")


class TestCleanup(unittest.TestCase):
    def test_only_the_bots_branches_with_a_closed_pr_are_deleted(self):
        pulls = [pull(20, "bot/pin-ai-tc-0.9.15", state="closed", merged=True), pull(21, "bot/pin-ai-tc-0.9.16"),
                 pull(22, "bot/rollback-ai-tc-0.9.14-to-0.9.13", state="closed")]
        refs = [{"ref": f"refs/heads/{name}"} for name in
                ("bot/pin-ai-tc-0.9.15", "bot/pin-ai-tc-0.9.16", "bot/rollback-ai-tc-0.9.14-to-0.9.13", "bot/remove-ai-tc-7")]
        gh = FakeGitHub({("GET", R("pulls")): pulls_route(pulls), ("GET", R("git/matching-refs/heads/bot/")): refs,
                         ("DELETE", R("git/refs/heads/bot/pin-ai-tc-0.9.15")): None,
                         ("DELETE", R("git/refs/heads/bot/rollback-ai-tc-0.9.14-to-0.9.13")): None})
        self.assertEqual(tr.cleanup_branches(gh), ["bot/pin-ai-tc-0.9.15", "bot/rollback-ai-tc-0.9.14-to-0.9.13"])


if __name__ == "__main__":
    unittest.main()
