"""Tests for tag_release.py: the sweep, the tag message, the PR facts and the branch clean-up."""
import contextlib
import io
import os
import re
import unittest
from unittest import mock

import tag_release as tr
from fakes import (CODEOWNERS, INTEGRITY, REPO, FakeGit, FakeGitHub, fleet_tag, manifest, not_found, pull,
                   pulls_route, safety, safety_entry)
from ghapi import GitHubError
from gitrepo import GitError
from import_release import Refused
from release_checks import MANIFEST, SAFETY_FILE, InfraError


NOW = 1_790_000_000


def R(suffix):
    return f"repos/{REPO}/{suffix}"


def history(chain=("t8", "a", "b", "c", "d"), times=None) -> FakeGit:
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
    return FakeGit(chain=list(chain), files=files, tags=[fleet_tag(7, "t7"), fleet_tag(8, "t8")], times=times)


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
        # "d" has no PR; it is old enough to be tagged as a push without one.
        self.assertEqual(tr.sweep(history(times={"d": NOW - 7200}), gh, sleep=waits.append, now=lambda: NOW),
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

    def test_a_young_commit_with_no_linked_pr_is_left_untagged_and_stops_the_sweep(self):
        gh = sweep_github()
        git = history(chain=("t8", "b", "d"), times={"d": NOW - 600})
        with self.assertRaisesRegex(Refused, "links no merged pull request"):
            tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW)
        tags = [call[2] for call in gh.called("POST", R("git/tags"))]
        self.assertEqual([(t["tag"], t["object"]) for t in tags], [("fleet-v9", "b")])  # nothing at or after "d"
        self.assertEqual(len(gh.called("POST", R("git/refs"))), 1)

    def test_an_unlinked_commit_over_an_hour_old_is_tagged_as_a_push_without_a_pr(self):
        for age in (tr.UNLINKED_GRACE, 7200):
            with self.subTest(age=age):
                gh = sweep_github()
                git = history(chain=("t8", "b", "d"), times={"d": NOW - age})
                self.assertEqual(tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW),
                                 ["fleet-v9 -> b (ai-tc 0.9.15)", "fleet-v10 -> d (ai-tc entry removed)"])
                message = gh.called("POST", R("git/tags"))[1][2]["message"]
                self.assertIn("pr: none\napprover: none\n", message)
                self.assertIn("approver-note: no pull request merged this commit\n", message)

    def test_a_young_commit_is_tagged_when_a_merged_pr_is_linked(self):
        # Only a commit with no linked PR waits: the age of one that has a PR is never consulted.
        gh = sweep_github()
        git = history(chain=("t8", "b"), times={"b": NOW - 60})
        self.assertEqual(tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW),
                         ["fleet-v9 -> b (ai-tc 0.9.15)"])

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


class TestRestore(unittest.TestCase):
    def removal_then_restore(self, restored: str) -> tuple[FakeGit, FakeGitHub]:
        """0.9.14 (fleet-v8) -> 0.9.15, which is not rollback-safe -> the entry removed -> the entry back at `restored`."""
        older = {"0.9.14": safety_entry("0.9.14", "0.9.13", "additive", ())}
        newer = dict(older, **{"0.9.15": safety_entry("0.9.15", "0.9.14")})
        content = {"t8": (manifest("0.9.14", INTEGRITY["0.9.14"]), older), "b": (manifest("0.9.15", INTEGRITY["0.9.15"]), newer),
                   "d": (manifest(entry=False), newer), "e": (manifest(restored, INTEGRITY[restored]), newer)}
        files = {}
        for sha, (text, table) in content.items():
            files[(sha, MANIFEST)] = text
            files[(sha, SAFETY_FILE)] = safety(table)
            files[(sha, ".github/CODEOWNERS")] = CODEOWNERS
        git = FakeGit(chain=["t8", "b", "d", "e"], files=files, tags=[fleet_tag(8, "t8")], times={"d": NOW - 7200})
        gh = sweep_github()
        gh.routes.update({
            ("GET", R("commits/e/pulls")): [{"number": 16, "merge_commit_sha": "e", "merged_at": "2026-10-04T00:00:00Z",
                                             "base": {"ref": "main"}}],
            ("GET", R("pulls/16")): {"head": {"sha": "h16"}, "labels": [], "merged_by": {"login": "venuverse"}},
            ("GET", R("pulls/16/reviews")): [{"state": "APPROVED", "commit_id": "h16", "user": {"login": "venuverse"}}]})
        return git, gh

    def messages(self, git, gh) -> list[str]:
        tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW)
        return [call[2]["message"] for call in gh.called("POST", R("git/tags"))]

    def test_a_restore_below_the_pin_before_the_removal_records_a_rollback(self):
        removal, restore = self.messages(*self.removal_then_restore("0.9.14"))[1:]
        self.assertIn("store-migration: none\n", removal)  # the removal's own tag is as before
        self.assertNotIn("rollback-from", removal)
        self.assertIn("version: 0.9.14\n", restore)
        self.assertIn("rollback-from: 0.9.15\n", restore)
        self.assertIn("store-migration: not-rollback-safe\n", restore)

    def test_a_restore_at_the_pin_before_the_removal_is_not_a_rollback(self):
        restore = self.messages(*self.removal_then_restore("0.9.15"))[2]
        self.assertIn("version: 0.9.15\n", restore)
        self.assertNotIn("rollback-from", restore)

    def test_the_last_pin_is_found_through_consecutive_removals_and_is_absent_at_the_root(self):
        git = FakeGit(chain=["r", "x", "y", "z"], files={
            ("r", MANIFEST): manifest(entry=False), ("x", MANIFEST): manifest("0.9.15", INTEGRITY["0.9.15"]),
            ("y", MANIFEST): manifest(entry=False), ("z", MANIFEST): manifest(entry=False)})
        self.assertEqual(tr.last_pinned(git, "z"), "0.9.15")
        self.assertEqual(tr.last_pinned(git, "x"), "0.9.15")
        self.assertEqual(tr.last_pinned(git, "r"), tr.ABSENT)
        self.assertEqual(tr.last_pinned(git, None), tr.ABSENT)


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

    def facts_for(self, reviews, owners=("Vaishnav-OM", "venuverse"), unreadable=""):
        gh = FakeGitHub({
            ("GET", R("commits/b/pulls")): [{"number": 13, "merge_commit_sha": "b", "merged_at": "2026-10-02T00:00:00Z",
                                             "base": {"ref": "main"}}],
            ("GET", R("pulls/13")): {"head": {"sha": "h13"}, "labels": [{"name": "drill"}],
                                     "merged_by": {"login": "org-owner-example"}},
            ("GET", R("pulls/13/reviews")): reviews})
        return tr.pr_facts(gh, "b", None if owners is None else list(owners), sleep=lambda seconds: None,
                           unreadable=unreadable)

    def test_owners_that_could_not_be_read_name_no_approver_and_claim_no_bypass(self):
        facts = self.facts_for([{"state": "APPROVED", "commit_id": "h13", "user": {"login": "venuverse"}}],
                               owners=None, unreadable="the file names a team")
        self.assertEqual(facts, {"pr": "13", "approver": "unknown", "drill": True,
                                 "note": "code owners could not be read: the file names a team"})

    def test_a_commit_no_pull_request_merged_has_no_approver_whether_or_not_the_owners_could_be_read(self):
        # With no pull request there is no approval to match, so the owners do not matter.
        gh = FakeGitHub({("GET", R("commits/d/pulls")): []})
        facts = tr.pr_facts(gh, "d", None, sleep=lambda seconds: None, unreadable="the file names a team")
        self.assertEqual((facts["pr"], facts["approver"]), ("none", "none"))
        self.assertEqual(facts["note"], "no pull request merged this commit")

    def test_an_owner_who_approved_then_requested_changes_is_not_the_approver(self):
        facts = self.facts_for([{"state": "APPROVED", "commit_id": "h13", "user": {"login": "venuverse"}},
                                {"state": "CHANGES_REQUESTED", "commit_id": "h13", "user": {"login": "venuverse"}}])
        self.assertEqual((facts["approver"], facts["note"]), ("none", "ruleset bypass by org-owner-example"))

    def test_an_owner_who_requested_changes_and_then_approved_is_the_approver(self):
        facts = self.facts_for([{"state": "CHANGES_REQUESTED", "commit_id": "h13", "user": {"login": "venuverse"}},
                                {"state": "APPROVED", "commit_id": "h13", "user": {"login": "venuverse"}}])
        self.assertEqual((facts["approver"], facts["note"]), ("venuverse", None))

    def test_a_dismissed_approval_does_not_count_and_a_later_comment_does_not_withdraw_one(self):
        dismissed = self.facts_for([{"state": "APPROVED", "commit_id": "h13", "user": {"login": "venuverse"}},
                                    {"state": "DISMISSED", "commit_id": "h13", "user": {"login": "venuverse"}}])
        self.assertEqual(dismissed["approver"], "none")
        commented = self.facts_for([{"state": "APPROVED", "commit_id": "h13", "user": {"login": "venuverse"}},
                                    {"state": "COMMENTED", "commit_id": "h13", "user": {"login": "venuverse"}}])
        self.assertEqual(commented["approver"], "venuverse")

    def test_the_approver_named_is_the_owner_who_approved_last(self):
        reviews = [{"state": "APPROVED", "commit_id": "h13", "user": {"login": "Vaishnav-OM"}},
                   {"state": "APPROVED", "commit_id": "h13", "user": {"login": "venuverse"}},
                   {"state": "APPROVED", "commit_id": "h13", "user": {"login": "Vaishnav-OM"}}]
        self.assertEqual(self.facts_for(reviews)["approver"], "Vaishnav-OM")
        self.assertEqual(tr.owner_approvals(reviews, "h13", ["Vaishnav-OM", "venuverse"]), ["venuverse", "Vaishnav-OM"])

    def test_owner_approvals_leaves_out_an_excluded_reviewer(self):
        reviews = [{"state": "APPROVED", "commit_id": "h13", "user": {"login": "Vaishnav-OM"}},
                   {"state": "APPROVED", "commit_id": "h13", "user": {"login": "venuverse"}},
                   {"state": "APPROVED", "commit_id": "h13", "user": {"login": "writer-example"}},
                   {"state": "APPROVED", "commit_id": "old", "user": None}]
        self.assertEqual(tr.owner_approvals(reviews, "h13", ["Vaishnav-OM", "venuverse"], exclude={"venuverse"}),
                         ["Vaishnav-OM"])

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


class TestCodeOwners(unittest.TestCase):
    def owners(self, text):
        files = {} if text is None else {("x", ".github/CODEOWNERS"): text}
        return tr.code_owners(FakeGit(chain=["x"], files=files), "x")

    def test_one_star_line_of_users_is_read_whatever_surrounds_it(self):
        cases = {
            "the repository's own file": ("* @Vaishnav-OM @venuverse\n", ["Vaishnav-OM", "venuverse"]),
            "comments and blank lines": ("# who reviews\n\n* @a_b @c-d  # everyone\n\n", ["a_b", "c-d"]),
            "tabs and CRLF line ends": ("*\t@a\t@b\r\n", ["a", "b"]),
            "no final newline": ("* @a", ["a"]),
        }
        for label, (text, expected) in cases.items():
            with self.subTest(label):
                self.assertEqual(self.owners(text), expected)

    def test_the_repositorys_own_codeowners_file_can_be_read(self):
        # A change to that file that the strict reader cannot read would make the tag of every commit merged on top
        # of it record an unknown approver, so it fails here first, while a pull request can still fix it.
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "CODEOWNERS")
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        self.assertEqual(self.owners(text), ["Vaishnav-OM", "venuverse"])

    def test_anything_else_is_a_refusal_that_names_the_file(self):
        cases = {
            "no file": (None, "is missing"),
            "an empty file": ("", "exactly one rule"),
            "only comments": ("# nobody yet\n", "exactly one rule"),
            "a team": ("* @akasecurity/maintainers\n", "`@akasecurity/maintainers`"),
            "a team among users": ("* @a @org/team @b\n", "`@org/team`"),
            "an email address": ("* @a b@example.com\n", "`b@example.com`"),
            "a name without an at sign": ("* someone\n", "`someone`"),
            "a bare at sign": ("* @\n", "`@`"),
            "a handle that is not a login": ("* @a. @b[bot]\n", "`@a.`"),
            "a path rule beside the star line": ("* @a\n/docs @b\n", "exactly one rule"),
            "only a path rule": ("/docs @a\n", "exactly one rule"),
            "two star lines": ("* @a\n* @b\n", "exactly one rule"),
            "a different catch-all pattern": ("** @a\n", "exactly one rule"),
            "a star line naming no owner": ("*\n", "names no owner"),
        }
        for label, (text, expected) in cases.items():
            with self.subTest(label):
                with self.assertRaises(Refused) as caught:
                    self.owners(text)
                self.assertIn(".github/CODEOWNERS at x", str(caught.exception))
                self.assertIn(expected, str(caught.exception))


class TestSweepOwners(unittest.TestCase):
    """The owners come from the merged commit's parent, which is fixed history: no later pull request can change
    that file. A file the strict reader cannot read must therefore never stop the sweep, or tagging would stop
    for good. The tag says the approver is unknown instead."""

    def test_a_codeowners_file_it_cannot_read_gives_an_unknown_approver_and_the_tag_is_cut(self):
        cases = {
            "a team owner": "* @akasecurity/maintainers\n",
            "a path rule": "* @Vaishnav-OM @venuverse\n/docs @venuverse\n",
            "no file": None,
        }
        for label, text in cases.items():
            with self.subTest(label):
                git = history(chain=("t8", "b"))
                if text is None:
                    del git.files[("t8", ".github/CODEOWNERS")]
                else:
                    git.files[("t8", ".github/CODEOWNERS")] = text
                gh = sweep_github()
                self.assertEqual(tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW),
                                 ["fleet-v9 -> b (ai-tc 0.9.15)"])
                message = gh.called("POST", R("git/tags"))[0][2]["message"]
                # The PR is still named; nobody is named as its approver, and no bypass is claimed: venuverse
                # approved it, and under the file as it stands nobody can say whether that counts.
                self.assertIn("pr: 13\napprover: unknown\n", message)
                self.assertRegex(message, r"(?m)^approver-note: code owners could not be read: "
                                          r"\.github/CODEOWNERS at t8 \S")
                self.assertEqual(message.count("approver-note:"), 1)
                self.assertNotIn("bypass", message)
                self.assertEqual(len(gh.called("POST", R("git/refs"))), 1)

    def test_an_unreadable_file_marks_only_the_commits_whose_parent_holds_it(self):
        # b's parent (t8) and d's parent (c) are readable; c's parent (b) is not. Reading each commit's own parent
        # is what lets the sweep carry on past it: d is tagged with its real approver.
        git = history(chain=("t8", "b", "c", "d"), times={"d": NOW - 7200})
        git.files[("b", ".github/CODEOWNERS")] = "* @akasecurity/maintainers\n"
        gh = sweep_github()
        gh.routes[("GET", R("commits/d/pulls"))] = [
            {"number": 17, "merge_commit_sha": "d", "merged_at": "2026-10-04T00:00:00Z", "base": {"ref": "main"}}]
        gh.routes[("GET", R("pulls/17"))] = {"head": {"sha": "h17"}, "labels": [], "merged_by": {"login": "venuverse"}}
        gh.routes[("GET", R("pulls/17/reviews"))] = [
            {"state": "APPROVED", "commit_id": "h17", "user": {"login": "Vaishnav-OM"}}]
        self.assertEqual(len(tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW)), 3)
        approvers = [re.search(r"(?m)^approver: (.*)$", call[2]["message"]).group(1)
                     for call in gh.called("POST", R("git/tags"))]
        self.assertEqual(approvers, ["venuverse", "unknown", "Vaishnav-OM"])

    def test_a_sweep_it_refuses_is_one_error_annotation(self):
        gh = sweep_github()
        gh.routes[("GET", R("git/ref/tags/fleet-v9"))] = {"ref": "refs/tags/fleet-v9"}
        code, out = run_main("sweep", history(chain=("t8", "b")), gh)
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("::error::fleet-v9 already exists"), out)
        self.assertEqual(out.count("\n"), 1)

    def test_a_root_commit_has_no_owners_to_read(self):
        # Nothing precedes it, so there is no file to read and no approval to be recorded as a bypass.
        class RootOnly(FakeGit):
            def first_parent_after(self, base, tip):
                return ["r"]

        git = RootOnly(chain=["r"], tags=[fleet_tag(8, "t8")], files={
            ("r", MANIFEST): manifest("0.9.15", INTEGRITY["0.9.15"]), ("r", SAFETY_FILE): safety({})})
        gh = sweep_github()
        gh.routes[("GET", R("commits/r/pulls"))] = [
            {"number": 13, "merge_commit_sha": "r", "merged_at": "2026-10-02T00:00:00Z", "base": {"ref": "main"}}]
        tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW)
        message = gh.called("POST", R("git/tags"))[0][2]["message"]
        self.assertIn("approver: none\n", message)
        self.assertIn("approver-note: ruleset bypass by venuverse\n", message)


def branch_ref(name: str, tip: str) -> dict:
    return {"ref": f"refs/heads/{name}", "object": {"sha": tip, "type": "commit"}}


def run_main(command: str, git, gh) -> tuple[int, str]:
    """tag_release.main with the checkout and the GitHub client replaced: its exit code and its output."""
    out = io.StringIO()
    with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO, "GH_TOKEN": "t"}), \
            mock.patch.object(tr, "Git", lambda path: git), mock.patch.object(tr, "GitHub", lambda token, repo: gh), \
            contextlib.redirect_stdout(out):
        code = tr.main([command])
    return code, out.getvalue()


def refused(path: str, status: int = 422, body: str = '{"message": "Repository rule violations found"}'):
    return GitHubError(status, "POST", path, body)


class TestGitHubFailures(unittest.TestCase):
    def test_a_tag_ref_github_refuses_is_an_error_naming_the_ruleset(self):
        gh = sweep_github()
        gh.routes[("POST", R("git/refs"))] = lambda body, params: (
            refused(R("git/refs")) if body["ref"] == "refs/tags/fleet-v10" else {"ref": "created"})
        with self.assertRaises(Refused) as caught:
            tr.sweep(history(times={"d": NOW - 7200}), gh, sleep=lambda seconds: None, now=lambda: NOW)
        text = str(caught.exception)
        self.assertIn("fleet-v10 at c", text)
        self.assertIn("HTTP 422", text)
        self.assertIn("Repository rule violations found", text)
        self.assertIn("fleet-tags-create", text)
        self.assertIn("Already done in this run: fleet-v9 -> b (ai-tc 0.9.15)", text)
        self.assertNotIn("fleet-v10 -> c", text)

    def test_the_first_tag_refused_reports_nothing_as_done(self):
        gh = sweep_github()
        gh.routes[("POST", R("git/tags"))] = refused(R("git/tags"), 403, "Resource not accessible by integration")
        with self.assertRaises(Refused) as caught:
            tr.sweep(history(), gh, sleep=lambda seconds: None, now=lambda: NOW)
        self.assertIn("HTTP 403", str(caught.exception))
        self.assertNotIn("Already done", str(caught.exception))

    def test_a_refused_tag_ends_the_sweep_run_with_an_error_annotation(self):
        gh = sweep_github()
        gh.routes[("POST", R("git/refs"))] = refused(R("git/refs"))
        code, out = run_main("sweep", history(chain=("t8", "b")), gh)
        self.assertEqual(code, 1)
        self.assertRegex(out, r"(?m)^::error::GitHub refused to create fleet-v9 at b \(HTTP 422")
        self.assertIn("fleet-tags-create", out)
        self.assertEqual(out.count("\n"), 1)  # one annotation line, no traceback

    def test_a_branch_deletion_github_refuses_is_an_error(self):
        pulls = [pull(20, "bot/pin-ai-tc-0.9.15", state="closed", merged=True)]
        gh = FakeGitHub({("GET", R("pulls")): pulls_route(pulls),
                         ("GET", R("git/matching-refs/heads/bot/")): [branch_ref("bot/pin-ai-tc-0.9.15", f"{20:040x}")],
                         ("DELETE", R("git/refs/heads/bot/pin-ai-tc-0.9.15")): refused(R("git/refs/heads/bot/pin-ai-tc-0.9.15"))})
        code, out = run_main("cleanup-branches", FakeGit(chain=[]), gh)
        self.assertEqual(code, 1)
        self.assertRegex(out, r"(?m)^::error::GitHub refused to delete bot/pin-ai-tc-0\.9\.15 \(HTTP 422")
        self.assertIn("bot-branches", out)

    def test_any_other_github_or_git_failure_is_an_error_annotation_too(self):
        class Broken(FakeGit):
            """A checkout whose `where` read raises `error`."""

            def __init__(self, where, error, **kwargs):
                super().__init__(**kwargs)
                self.where, self.error = where, error

            def fleet_tags(self):
                if self.where == "fleet_tags":
                    raise self.error
                return super().fleet_tags()

            def main(self):
                if self.where == "main":
                    raise self.error
                return super().main()

        def reads(path, status=502):
            gh = sweep_github()
            gh.routes[("GET", path)] = GitHubError(status, "GET", path, "Bad Gateway")
            return gh

        cases = {
            "tag lookup": (history(chain=("t8", "b")), reads(R("git/ref/tags/fleet-v9"), 500)),
            "pull request read": (history(chain=("t8", "b")), reads(R("pulls/13"))),
            "git failure": (Broken("fleet_tags", GitError("git for-each-ref failed: bad object"), chain=["t8"]),
                            sweep_github()),
            "no main in the checkout": (Broken("main", InfraError("git", "no main ref"), chain=["t8"],
                                               tags=[fleet_tag(8, "t8")]), sweep_github()),
        }
        for name, (git, gh) in cases.items():
            with self.subTest(name):
                code, out = run_main("sweep", git, gh)
                self.assertEqual(code, 1)
                self.assertTrue(out.startswith("::error::"), out)
                self.assertEqual(out.count("\n"), 1)


class TestCleanup(unittest.TestCase):
    def test_only_the_bots_branches_with_a_closed_pr_are_deleted(self):
        pulls = [pull(20, "bot/pin-ai-tc-0.9.15", state="closed", merged=True), pull(21, "bot/pin-ai-tc-0.9.16"),
                 pull(22, "bot/rollback-ai-tc-0.9.14-to-0.9.13", state="closed")]
        # pull(n, ...) gives its PR the head f"{n:040x}"; a branch is at its closed PR's head here.
        refs = [branch_ref("bot/pin-ai-tc-0.9.15", f"{20:040x}"), branch_ref("bot/pin-ai-tc-0.9.16", f"{21:040x}"),
                branch_ref("bot/rollback-ai-tc-0.9.14-to-0.9.13", f"{22:040x}"), branch_ref("bot/remove-ai-tc-7", f"{23:040x}")]
        gh = FakeGitHub({("GET", R("pulls")): pulls_route(pulls), ("GET", R("git/matching-refs/heads/bot/")): refs,
                         ("DELETE", R("git/refs/heads/bot/pin-ai-tc-0.9.15")): None,
                         ("DELETE", R("git/refs/heads/bot/rollback-ai-tc-0.9.14-to-0.9.13")): None})
        self.assertEqual(tr.cleanup_branches(gh), ["bot/pin-ai-tc-0.9.15", "bot/rollback-ai-tc-0.9.14-to-0.9.13"])

    def test_a_reimport_reusing_a_closed_prs_branch_name_keeps_the_branch(self):
        pulls = [pull(20, "bot/pin-ai-tc-0.9.15", state="closed", merged=True), pull(30, "bot/pin-ai-tc-0.9.15")]
        gh = FakeGitHub({("GET", R("pulls")): pulls_route(pulls),
                         ("GET", R("git/matching-refs/heads/bot/")): [branch_ref("bot/pin-ai-tc-0.9.15", f"{20:040x}")]})
        self.assertEqual(tr.cleanup_branches(gh), [])
        self.assertEqual(gh.writes(), [])

    def test_a_branch_re_created_after_its_pr_closed_is_kept(self):
        # A reimport deleted the closed PR's branch and made it again: a new commit, which no closed PR closed on.
        pulls = [pull(20, "bot/pin-ai-tc-0.9.15", state="closed", merged=True)]
        gh = FakeGitHub({("GET", R("pulls")): pulls_route(pulls),
                         ("GET", R("git/matching-refs/heads/bot/")): [branch_ref("bot/pin-ai-tc-0.9.15", f"{99:040x}")]})
        self.assertEqual(tr.cleanup_branches(gh), [])
        self.assertEqual(gh.writes(), [])

    def test_a_branch_whose_tip_is_not_given_is_kept(self):
        pulls = [pull(20, "bot/pin-ai-tc-0.9.15", state="closed", merged=True)]
        gh = FakeGitHub({("GET", R("pulls")): pulls_route(pulls),
                         ("GET", R("git/matching-refs/heads/bot/")): [{"ref": "refs/heads/bot/pin-ai-tc-0.9.15"}]})
        self.assertEqual(tr.cleanup_branches(gh), [])
        self.assertEqual(gh.writes(), [])


if __name__ == "__main__":
    unittest.main()
