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
        ("GET", R("commits/b/pulls")): [{"number": 13, "merge_commit_sha": "b", "merged_at": "2026-10-02T00:00:00Z",
                                        "base": {"ref": "main"}}],
        ("GET", R("pulls/13")): {"head": {"sha": "h13"}, "labels": [], "merged_by": {"login": "venuverse"}},
        ("GET", R("pulls/13/reviews")): [
            {"state": "COMMENTED", "commit_id": "h13", "user": {"login": "Vaishnav-OM"}},
            {"state": "APPROVED", "commit_id": "h13", "user": {"login": "venuverse"}}],
        ("GET", R("commits/c/pulls")): [
            {"number": 15, "merge_commit_sha": "other", "merged_at": None, "base": {"ref": "main"}},
            {"number": 14, "merge_commit_sha": "c", "merged_at": "2026-10-03T00:00:00Z", "base": {"ref": "main"}}],
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
        # A lower-numbered tag on a later commit: the walk still starts after the highest tag (fleet-v8),
        # and the commit that carries a tag is passed over.
        git = history()
        git.tags = [fleet_tag(7, "c"), fleet_tag(8, "t8")]
        self.assertEqual(tr.pending(git), ["b", "d"])

    def test_numbering_resumes_after_the_highest_tag(self):
        git = history()
        git.tags.append(fleet_tag(9, "b"))
        self.assertEqual(tr.pending(git), ["c", "d"])

    def test_nothing_to_tag_when_the_pin_did_not_change(self):
        self.assertEqual(tr.pending(history(chain=("t8", "a"))), [])

    def test_the_walk_reads_main_by_its_full_ref(self):
        # A tag named main resolves before the branch of that name, so a bare "main" can point anywhere.
        class FullRefOnly(FakeGit):
            def main(self):
                return "refs/remotes/origin/main"

            def rev_parse(self, rev):
                if rev == "main":
                    raise AssertionError("main was read by its bare name")
                return self.chain[-1] if rev == "refs/remotes/origin/main" else rev

        base = history()
        git = FullRefOnly(chain=base.chain, files=base.files, tags=base.tags)
        self.assertEqual(tr.pending(git), ["b", "c", "d"])


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
        answers = [[], [{"number": 13, "merge_commit_sha": "b", "merged_at": "2026-10-02T00:00:00Z",
                         "base": {"ref": "main"}}]]
        gh = sweep_github()
        gh.routes[("GET", R("commits/b/pulls"))] = lambda body, params: answers.pop(0)
        self.assertEqual(tr.merged_pull(gh, "b", sleep=lambda seconds: None)["number"], 13)

    def test_a_pr_merged_into_another_branch_is_not_mains_merge(self):
        gh = sweep_github()
        gh.routes[("GET", R("commits/b/pulls"))] = [
            {"number": 13, "merge_commit_sha": "b", "merged_at": "2026-10-02T00:00:00Z", "base": {"ref": "release"}}]
        self.assertIsNone(tr.merged_pull(gh, "b", sleep=lambda seconds: None))
        gh.routes[("GET", R("commits/b/pulls"))] = [
            {"number": 13, "merge_commit_sha": "b", "merged_at": "2026-10-02T00:00:00Z"}]
        self.assertIsNone(tr.merged_pull(gh, "b", sleep=lambda seconds: None))  # no base at all: not main's either

    def test_a_forward_version_without_a_safety_entry_records_unknown(self):
        git = FakeGit(chain=["t8", "b"], files={("b", SAFETY_FILE): safety({})})
        self.assertEqual(tr.store_migration(git, "b", "0.9.15", "0.9.14"), "unknown")


class TestStoreMigration(unittest.TestCase):
    def classify(self, version: str, previous: str, table: dict) -> str:
        git = FakeGit(chain=["x"], files={("x", SAFETY_FILE): safety(table)})
        return tr.store_migration(git, "x", version, previous)

    def test_a_rollback_across_a_not_rollback_safe_release_records_it(self):
        table = {"0.9.14": safety_entry("0.9.14", "0.9.13"), "0.9.15": safety_entry("0.9.15", "0.9.14", "additive", ())}
        self.assertEqual(self.classify("0.9.13", "0.9.15", table), "not-rollback-safe")

    def test_a_rollback_whose_only_flagged_release_is_the_one_rolled_back_from_records_it(self):
        table = {"0.9.14": safety_entry("0.9.14", "0.9.13")}
        self.assertEqual(self.classify("0.9.13", "0.9.14", table), "not-rollback-safe")

    def test_one_flagged_release_among_additive_ones_is_enough(self):
        table = {"0.9.14": safety_entry("0.9.14", "0.9.13"), "0.9.15": safety_entry("0.9.15", "0.9.14", "additive", ()),
                 "0.9.16": safety_entry("0.9.16", "0.9.15", "additive", ())}
        self.assertEqual(self.classify("0.9.13", "0.9.16", table), "not-rollback-safe")

    def test_a_flagged_target_or_a_flagged_release_above_the_previous_pin_does_not_count(self):
        table = {"0.9.13": safety_entry("0.9.13", "0.9.12"), "0.9.15": safety_entry("0.9.15", "0.9.14"),
                 "0.9.14": safety_entry("0.9.14", "0.9.13", "additive", ())}
        self.assertEqual(self.classify("0.9.13", "0.9.14", table), "additive")

    def test_a_forward_release_records_its_own_classification(self):
        table = {"0.9.15": safety_entry("0.9.15", "0.9.14")}
        self.assertEqual(self.classify("0.9.15", "0.9.14", table), "not-rollback-safe")


class TestApprover(unittest.TestCase):
    def test_the_last_owner_approval_on_the_final_head_is_named(self):
        gh = FakeGitHub({
            ("GET", R("commits/b/pulls")): [{"number": 13, "merge_commit_sha": "b", "merged_at": "2026-10-02T00:00:00Z",
                                             "base": {"ref": "main"}}],
            ("GET", R("pulls/13")): {"head": {"sha": "h13"}, "labels": [], "merged_by": {"login": "venuverse"}},
            ("GET", R("pulls/13/reviews")): [
                {"state": "APPROVED", "commit_id": "h13", "user": {"login": "venuverse"}},
                {"state": "APPROVED", "commit_id": "h13", "user": {"login": "Vaishnav-OM"}}]})
        facts = tr.pr_facts(gh, "b", ["Vaishnav-OM", "venuverse"], sleep=lambda seconds: None)
        self.assertEqual(facts["approver"], "Vaishnav-OM")

    def test_owners_are_read_from_the_merged_commits_parent(self):
        git = history(chain=("t8", "b"))
        git.files[("b", ".github/CODEOWNERS")] = "* @Vaishnav-OM @venuverse @added-by-the-merge\n"
        gh = sweep_github()
        gh.routes[("GET", R("pulls/13/reviews"))] = [
            {"state": "APPROVED", "commit_id": "h13", "user": {"login": "added-by-the-merge"}}]
        tr.sweep(git, gh, sleep=lambda seconds: None)
        message = gh.called("POST", R("git/tags"))[0][2]["message"]
        self.assertIn("approver: none\n", message)
        self.assertIn("approver-note: ruleset bypass by venuverse\n", message)


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

    def test_a_reimport_reusing_a_closed_prs_branch_name_keeps_the_branch(self):
        pulls = [pull(20, "bot/pin-ai-tc-0.9.15", state="closed", merged=True), pull(30, "bot/pin-ai-tc-0.9.15")]
        gh = FakeGitHub({("GET", R("pulls")): pulls_route(pulls),
                         ("GET", R("git/matching-refs/heads/bot/")): [{"ref": "refs/heads/bot/pin-ai-tc-0.9.15"}]})
        self.assertEqual(tr.cleanup_branches(gh), [])
        self.assertEqual(gh.writes(), [])


if __name__ == "__main__":
    unittest.main()
