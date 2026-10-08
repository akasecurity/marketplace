"""Tests for tag_release.py: the sweep, the tag message, the PR facts and the branch clean-up."""
import contextlib
import io
import json
import os
import re
import tempfile
import unittest
import urllib.parse
from unittest import mock

import _testsupport as ts
import release_checks
import tag_release as tr
from fakes import (CODEOWNERS, INTEGRITY, REPO, UNREADABLE_MANIFESTS, FakeGit, FakeGitHub, fleet_tag, manifest,
                   not_found, pull, pulls_route, safety, safety_entry)
from ghapi import GitHub, GitHubError
from gitrepo import Git, GitError
from import_release import Refused
from release_checks import GITHUB_ACTIONS_APP_ID, MANIFEST, SAFETY_FILE, InfraError


NOW = 1_790_000_000


def R(suffix):
    return f"repos/{REPO}/{suffix}"


MERGED_AT = "2026-10-02T00:00:00Z"  # when PR 13 merged, in sweep_github and in TestValidateOnTheFinalHead.facts
BEFORE_THE_MERGE = "2026-10-01T23:59:00Z"
AFTER_THE_MERGE = "2026-10-02T00:00:01Z"


def suite_of(run_id: int) -> int:
    """The id of the check suite a test check run is in: one suite for each run, as GitHub Actions makes them."""
    return 9000 + run_id


def validate_run(run_id=7, *, conclusion="success", status="completed", name="validate", app=GITHUB_ACTIONS_APP_ID,
                 started_at=BEFORE_THE_MERGE, suite=None) -> dict:
    """A check run as the API lists it: by default the green `validate` run of GitHub Actions, started a minute
    before the merge, in a check suite of its own (`checks` makes that suite a pull_request_target run of validate.yml)."""
    return {"id": run_id, "name": name, "status": status, "conclusion": conclusion, "app": {"id": app},
            "started_at": started_at, "check_suite": {"id": suite_of(run_id) if suite is None else suite}}


def workflow_run(suite: int, *, event="pull_request_target", path=tr.VALIDATE_WORKFLOW,
                 created_at="2026-10-01T23:50:00Z") -> dict:
    """A workflow run as the API lists it for a check suite. `created_at` is when the run was queued, which may
    be long before the job started; the code under test never reads it."""
    return {"id": suite - 1000, "check_suite_id": suite, "name": "validate", "event": event, "path": path,
            "created_at": created_at, "run_started_at": created_at}


def checks(head: str, runs: list | None = None, workflows: dict | None = None) -> dict:
    """The routes answering the check-run list of `head` (one green `validate` run unless `runs` says otherwise; an
    empty list is a head nothing ran on) and the workflow-run list asked for by `check_suite_id`. `workflows` maps
    a check suite's id to the workflow runs the API lists for it (a suite it does not name lists none); left out,
    every suite is one pull_request_target run of validate.yml."""
    def listed(body, params):
        suite = params["check_suite_id"]
        found = [workflow_run(suite)] if workflows is None else workflows.get(suite, [])
        return {"total_count": len(found), "workflow_runs": found}

    return {("GET", R(f"commits/{head}/check-runs")): [validate_run()] if runs is None else runs,
            ("GET", R("actions/runs")): listed}


def scratch_repository(directory: str):
    """`git init` in `directory`, and a function that runs git there with a fixed identity and no user config."""
    env = ts.git_env("test", "test@example.invalid")

    def sh(*args):
        return ts.git(directory, *args, env=env).strip()

    sh("init", "-q", "-b", "main")
    return sh


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
        ("GET", R("commits/b/pulls")): [{"number": 13, "merge_commit_sha": "b", "merged_at": MERGED_AT,
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
        **checks("h13"),
        **checks("h14"),
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

    def test_an_unlinked_commit_dated_ahead_of_the_clock_does_not_hold_the_tags_after_it(self):
        # Only a direct push can carry a future committer date (GitHub dates the commits it makes at the moment
        # it makes them), for example from a machine with the wrong clock. Waiting for that date would leave
        # this commit and every later one untagged until then, so it is tagged now as an old one would be.
        ahead = {"just past the allowance": tr.CLOCK_SKEW + 1, "hours": 7200 * 3, "years": 86400 * 365 * 5}
        for label, seconds in ahead.items():
            with self.subTest(label):
                gh = sweep_github()
                # d (the entry's removal, no PR) is dated ahead; c (a linked rollback) comes after it.
                git = history(chain=("t8", "d", "c"), times={"d": NOW + seconds})
                self.assertEqual(tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW),
                                 ["fleet-v9 -> d (ai-tc entry removed)", "fleet-v10 -> c (ai-tc 0.9.14)"])
                message = gh.called("POST", R("git/tags"))[0][2]["message"]
                self.assertIn("pr: none\napprover: none\n", message)
                self.assertIn("approver-note: no pull request merged this commit\n", message)

    def test_an_unlinked_commit_dated_a_little_ahead_of_the_clock_is_still_young(self):
        # A runner's clock and a committer's differ by a little, so a date within the allowance is not a wrong
        # clock: the commit is held for the hour like any other young one.
        for seconds in (120, tr.CLOCK_SKEW):
            with self.subTest(seconds=seconds):
                gh = sweep_github()
                git = history(chain=("t8", "b", "d"), times={"d": NOW + seconds})
                with self.assertRaisesRegex(Refused, "links no merged pull request"):
                    tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW)
                tags = [call[2] for call in gh.called("POST", R("git/tags"))]
                self.assertEqual([(t["tag"], t["object"]) for t in tags], [("fleet-v9", "b")])

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

    def test_the_association_hands_back_the_answer_that_decided_it(self):
        elsewhere = {"number": 13, "merge_commit_sha": "c", "merged_at": "2026-10-02T00:00:00Z", "base": {"ref": "main"}}
        own = {**elsewhere, "number": 14, "merge_commit_sha": "b"}
        gh = sweep_github()
        gh.routes[("GET", R("commits/b/pulls"))] = [elsewhere]
        # No PR has this commit as its merge commit: the list the last ask returned comes back with None, and the
        # three asks are the whole cost, so a caller that wants the list does not ask a fourth time.
        self.assertEqual(tr.pull_association(gh, "b", sleep=lambda seconds: None), (None, [elsewhere]))
        self.assertEqual(len(gh.called("GET", R("commits/b/pulls"))), tr.ASSOCIATION_ATTEMPTS)
        answers = [[], [elsewhere, own]]
        gh.routes[("GET", R("commits/b/pulls"))] = lambda body, params: answers.pop(0)
        self.assertEqual(tr.pull_association(gh, "b", sleep=lambda seconds: None), (own, [elsewhere, own]))

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
        self.assertEqual(tr.store_migration(git, "b", "0.9.15", "0.9.14"), ("unknown", ""))


class TestUnreadableManifests(unittest.TestCase):
    """A commit already on main never gets better, so a manifest that cannot be read at one must not stop the
    sweep (and so every tag after it) for good. The commit is no pin change, it is reported, and the sweep goes on."""

    def broken(self, sha: str, text: str, chain=("t8", "a", "b", "c", "d")) -> FakeGit:
        git = history(chain=chain)
        git.files[(sha, MANIFEST)] = text
        return git

    def test_a_commit_whose_manifest_cannot_be_read_is_no_pin_change_and_the_walk_goes_on(self):
        for label, text in UNREADABLE_MANIFESTS.items():
            with self.subTest(label):
                git = self.broken("a", text)
                changes, unreadable = tr.pin_changes(git, "t8")
                self.assertEqual(changes, ["b", "c", "d"])
                self.assertEqual(list(unreadable), ["a"])
                self.assertIn(f"{MANIFEST} at a cannot be read: ", unreadable["a"])
                self.assertEqual(tr.pending(git), ["b", "c", "d"])

    def test_the_reason_is_one_line_however_long_the_parser_message_is(self):
        git = self.broken("a", '{"k": 1, "' + "k" * 5000 + '": 1, "' + "k" * 5000 + '": 2}')
        _, unreadable = tr.pin_changes(git, "t8")
        self.assertNotIn("\n", unreadable["a"])
        self.assertLess(len(unreadable["a"]), 400)

    def test_a_reason_that_spans_lines_cannot_start_a_workflow_command_of_its_own(self):
        # The reason becomes a warning annotation, and a command is read only at the start of a line.
        git = history(chain=("t8", "a"))
        with mock.patch.object(tr, "entry_of", side_effect=Refused("one\n::error::two\r\nthree")):
            _, unreadable = tr.pin_changes(git, "t8")
        self.assertNotRegex(unreadable["a"], r"[\r\n]")
        self.assertIn("one ::error::two three", unreadable["a"])

    def test_a_broken_commit_between_two_pin_changes_is_passed_over(self):
        # "c" sits between the release (b, 0.9.15) and the entry's removal (d): d is compared with b.
        changes, unreadable = tr.pin_changes(self.broken("c", "{"), "t8")
        self.assertEqual((changes, list(unreadable)), (["b", "d"], ["c"]))

    def test_the_tip_can_be_the_broken_commit(self):
        changes, unreadable = tr.pin_changes(self.broken("c", "{", chain=("t8", "a", "b", "c")), "t8")
        self.assertEqual((changes, list(unreadable)), (["b"], ["c"]))

    def test_a_manifest_broken_for_one_commit_and_mended_to_the_same_version_is_no_change(self):
        git = history(chain=("t8", "a", "a2"))
        git.files[("a", MANIFEST)] = "{"
        git.files[("a2", MANIFEST)] = manifest("0.9.14", INTEGRITY["0.9.14"])
        self.assertEqual(tr.pin_changes(git, "t8"), ([], {"a": unreadable_reason(git, "a")}))

    def test_a_pin_change_behind_a_broken_commit_is_found_at_the_first_commit_that_reads(self):
        git = history(chain=("t8", "a", "b"))
        git.files[("a", MANIFEST)] = "[" * 100_000
        self.assertEqual(tr.pin_changes(git, "t8")[0], ["b"])

    def test_a_tagged_commit_is_neither_a_pin_change_nor_reported(self):
        git = self.broken("a", "{")
        git.tags.append(fleet_tag(9, "a"))
        self.assertEqual(tr.pin_changes(git, "t8"), (["b", "c", "d"], {}))

    def test_the_sweep_reports_each_broken_commit_once_tags_the_rest_and_ends_green(self):
        gh = sweep_github()
        code, out = run_main("sweep", self.broken("a", "{", chain=("t8", "a", "b")), gh)
        self.assertEqual(code, 0, out)
        warnings = re.findall(r"(?m)^::warning::.*$", out)
        self.assertEqual(len(warnings), 1, out)
        self.assertIn(f"{MANIFEST} at a cannot be read", warnings[0])
        self.assertIn("not counted as a pin change", warnings[0])
        self.assertIn("created fleet-v9 -> b (ai-tc 0.9.15)", out)
        self.assertIn("tagged 1 commit(s)", out)

    def test_nothing_to_tag_after_a_broken_commit_is_still_reported(self):
        code, out = run_main("sweep", self.broken("a", "{", chain=("t8", "a")), sweep_github())
        self.assertEqual(code, 0, out)
        self.assertRegex(out, r"(?m)^::warning::.*at a cannot be read")
        self.assertIn("nothing to tag", out)

    def test_a_tag_after_a_broken_commit_records_the_version_it_moved_from_not_the_broken_one(self):
        # c rolls 0.9.15 (b) back to 0.9.14, with the broken commit a in between: the rollback is still recorded.
        gh = sweep_github()
        tr.sweep(self.broken("a", "{", chain=("t8", "b", "a", "c")), gh, sleep=lambda seconds: None, now=lambda: NOW)
        first, second = (call[2]["message"] for call in gh.called("POST", R("git/tags")))
        self.assertIn("version: 0.9.15\n", first)
        self.assertIn("version: 0.9.14\n", second)
        self.assertIn("rollback-from: 0.9.15\n", second)

    def test_a_restore_after_a_removal_is_compared_with_the_last_version_that_could_be_read(self):
        # b pins 0.9.15, d removes the entry (no PR, old enough to be tagged), a is broken, c restores 0.9.14.
        git = history(chain=("t8", "b", "d", "a", "c"), times={"d": NOW - 7200})
        git.files[("a", MANIFEST)] = "{"
        gh = sweep_github()
        tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW)
        messages = [call[2]["message"] for call in gh.called("POST", R("git/tags"))]
        self.assertIn("rollback-from: 0.9.15\n", messages[-1])

    def test_the_last_pin_is_found_back_through_broken_commits(self):
        git = history(chain=("t8", "b", "a", "c", "d"))
        git.files[("a", MANIFEST)] = "{"
        git.files[("c", MANIFEST)] = "{"
        self.assertEqual(tr.last_pinned(git, "c"), "0.9.15")
        self.assertEqual(tr.version_up_to(git, "c"), "0.9.15")
        self.assertEqual(tr.version_up_to(git, "a"), "0.9.15")
        self.assertEqual(tr.version_at(git, "a"), tr.UNREADABLE)
        root = history(chain=("a", "b"))
        root.files[("a", MANIFEST)] = "{"
        self.assertEqual((tr.version_up_to(root, "a"), tr.last_pinned(root, "a")), (tr.ABSENT, tr.ABSENT))

    def test_a_damaged_checkout_is_still_an_error_not_an_unreadable_manifest(self):
        class Damaged(FakeGit):
            def show(self, rev, path):
                raise GitError("git show failed: bad object")

        git = Damaged(chain=["t8", "a"], tags=[fleet_tag(8, "t8")])
        with self.assertRaises(GitError):
            tr.pin_changes(git, "t8")

    def test_a_manifest_that_is_not_text_is_unreadable_too(self):
        class NotText(FakeGit):
            def show(self, rev, path):
                if (rev, path) == ("a", MANIFEST):
                    raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
                return super().show(rev, path)

        base = history(chain=("t8", "a", "b"))
        git = NotText(chain=base.chain, files=base.files, tags=base.tags)
        changes, unreadable = tr.pin_changes(git, "t8")
        self.assertEqual((changes, list(unreadable)), (["b"], ["a"]))

    def table(self, text, version, previous):
        git = FakeGit(chain=["x"], files={("x", SAFETY_FILE): text})
        return tr.store_migration(git, "x", version, previous)[0]

    def test_a_safety_table_that_cannot_be_read_records_unknown_for_a_release_and_for_a_rollback(self):
        # An empty table would call a rollback across an unsafe release additive.
        for label, text in {"not JSON": "{", "too deeply nested": "[" * 100_000, "not an object": "[]",
                            "versions that is not an object": '{"versions": []}', "a repeated key": '{"a": 1, "a": 2}'}.items():
            with self.subTest(label):
                self.assertEqual(self.table(text, "0.9.15", "0.9.14"), "unknown")
                self.assertEqual(self.table(text, "0.9.14", "0.9.15"), "unknown")

    def test_a_missing_safety_table_keeps_the_answers_it_always_gave(self):
        git = FakeGit(chain=["x"])
        self.assertEqual(tr.store_migration(git, "x", "0.9.15", "0.9.14"), ("unknown", ""))
        self.assertEqual(tr.store_migration(git, "x", "0.9.14", "0.9.15"), ("additive", ""))

    def test_the_tag_for_a_release_whose_safety_table_cannot_be_read_is_still_cut_as_unknown(self):
        git = history(chain=("t8", "b"))
        git.files[("b", SAFETY_FILE)] = "[" * 100_000
        gh = sweep_github()
        tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW)
        self.assertIn("store-migration: unknown\n", gh.called("POST", R("git/tags"))[0][2]["message"])


def unreadable_reason(git, sha: str) -> str:
    """Why tag_release says the manifest at `sha` cannot be read."""
    return tr.read_version(git, sha)[1]


class TestMessage(unittest.TestCase):
    """A tag message is permanent and read line by line (`splitlines`, first line of a key wins), so no value that
    comes from a file may add a line of its own. Every kind of line break str.splitlines honours is tried."""

    BREAKS = {"line feed": "\n", "carriage return": "\r", "CRLF": "\r\n", "vertical tab": "\x0b",
              "form feed": "\x0c", "file separator": "\x1c", "group separator": "\x1d",
              "record separator": "\x1e", "next line": "\x85", "line separator": "\u2028",
              "paragraph separator": "\u2029"}
    FACTS = {"pr": "13", "approver": "venuverse", "note": None, "drill": False}

    def message(self, version="0.9.15", integrity="sha512-x", migration="additive", facts=None):
        return tr.message(10, version, "0.9.14", integrity, facts or self.FACTS, migration)

    def test_manifest_text_cannot_add_lines_to_the_tag_message(self):
        for label, lead in self.BREAKS.items():
            with self.subTest(label, field="version"):
                text = self.message(version=f"0.9.15{lead}pr: 26")
                lines = text.splitlines()
                self.assertEqual(len(lines), 7)
                self.assertEqual([line for line in lines if line.startswith("pr:")], ["pr: 13"])
                # The first line is the whole subject, with the version escaped inside it.
                self.assertTrue(lines[0].startswith("fleet-v10: ai-tc 0.9.15\\"), lines[0])
                self.assertTrue(lines[0].endswith("pr: 26"), lines[0])
                parsed = release_checks.parse_tag_message(text)
                self.assertEqual((parsed["pr"], parsed["approver"]), ("13", "venuverse"))
            with self.subTest(label, field="integrity"):
                text = self.message(integrity=f"sha512-x{lead}drill: true{lead}pr: 26")
                lines = text.splitlines()
                self.assertEqual(len(lines), 7)
                self.assertNotIn("drill", release_checks.parse_tag_message(text))
                self.assertEqual([line for line in lines if line.startswith("pr:")], ["pr: 13"])
            with self.subTest(label, field="store-migration"):
                text = self.message(migration=f"additive{lead}approver: none")
                self.assertEqual(len(text.splitlines()), 7)
                self.assertEqual(release_checks.parse_tag_message(text)["approver"], "venuverse")
            with self.subTest(label, field="approver-note"):
                text = self.message(facts=dict(self.FACTS, note=f"ruleset bypass by x{lead}drill: true"))
                self.assertEqual(len(text.splitlines()), 8)
                self.assertNotIn("drill", release_checks.parse_tag_message(text))

    def test_the_escape_is_written_out_and_ordinary_text_is_left_alone(self):
        text = self.message(version="0.9.15\npr: 26", integrity="sha512-x\ty")
        self.assertIn("fleet-v10: ai-tc 0.9.15\\npr: 26\n", text)
        self.assertIn("\nversion: 0.9.15\\npr: 26\nintegrity: sha512-x\\ty\n", text)
        plain = self.message(integrity=INTEGRITY["0.9.15"], facts=dict(self.FACTS, note="code owners could not be "
                                                                         "read: `.github/CODEOWNERS` at abc (caf\u00e9)"))
        self.assertIn(f"integrity: {INTEGRITY['0.9.15']}\n", plain)
        self.assertIn("approver-note: code owners could not be read: `.github/CODEOWNERS` at abc (caf\u00e9)\n", plain)

    def test_a_version_with_a_line_break_is_still_tagged_as_recorded_in_one_line(self):
        # A version that is not x.y.z is not refused: a bypass edit has to be recorded, and tag-audit flags it.
        git = history(chain=("t8", "b"))
        git.files[("b", MANIFEST)] = manifest("0.9.15\npr: 26", "sha512-x\ndrill: true")
        gh = sweep_github()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            created = tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW)
        self.assertEqual(len(created), 1)
        # The run's log line is one line too: the runner reads a line that starts `::` as a workflow command.
        self.assertEqual(len(out.getvalue().splitlines()), 1, out.getvalue())
        text = gh.called("POST", R("git/tags"))[0][2]["message"]
        self.assertEqual(len(text.splitlines()), 7, text)
        self.assertEqual([line for line in text.splitlines() if line.startswith("pr:")], ["pr: 13"])
        self.assertNotIn("drill", release_checks.parse_tag_message(text))


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
            ("GET", R("pulls/16/reviews")): [{"state": "APPROVED", "commit_id": "h16", "user": {"login": "venuverse"}}],
            **checks("h16")})
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
        return tr.store_migration(git, "x", version, previous)[0]

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


# What a value that is not a string can be in JSON, for the fields the tag message prints.
NOT_A_STRING = {"null": None, "a number": 5, "a boolean": True, "a list of numbers": [5], "an object": {"sha512": "x"}}


def wrong_entry(version: str, previous: str) -> str:
    """Why a rollback from `previous` to `version` records unknown when a crossed entry has the wrong type."""
    return (f"store-migration unknown: rollback-safety.json holds an entry between {version} and {previous} "
            "that is not an object with a string classification")


def with_integrity(version: str, value) -> str:
    """The manifest for `version` with metadata.integrity set to `value`, whatever its type."""
    doc = json.loads(manifest(version, INTEGRITY[version]))
    next(plugin for plugin in doc["plugins"] if plugin["name"] == "ai-tc")["metadata"]["integrity"] = value
    return release_checks.dump_json(doc)


class TestValuesOfTheWrongType(unittest.TestCase):
    """A manifest or a safety table that parses can still hold a value of the wrong type at a pin change (only a push
    that skipped validate leaves one). The tag message prints these values, and the sweep stopped on them, so no
    later pin change was ever tagged. Each now falls back to `unknown` and says why in the tag's note."""

    def classify(self, version: str, previous: str, table: dict) -> tuple[str, str]:
        git = FakeGit(chain=["x"], files={("x", SAFETY_FILE): safety(table)})
        return tr.store_migration(git, "x", version, previous)

    def test_an_integrity_that_is_not_a_string_is_unknown_with_the_reason(self):
        for label, value in NOT_A_STRING.items():
            with self.subTest(label):
                git = FakeGit(chain=["x"], files={("x", MANIFEST): with_integrity("0.9.15", value)})
                self.assertEqual(tr.integrity_at(git, "x"), (
                    "unknown", "integrity unknown: metadata.integrity of the ai-tc entry is not a string"))

    def test_an_integrity_that_is_a_string_or_absent_is_read_as_before(self):
        git = FakeGit(chain=["x", "y", "z"], files={("x", MANIFEST): manifest("0.9.15", INTEGRITY["0.9.15"]),
                                                    ("y", MANIFEST): manifest("0.9.15"),
                                                    ("z", MANIFEST): manifest(entry=False)})
        self.assertEqual(tr.integrity_at(git, "x"), (INTEGRITY["0.9.15"], ""))
        self.assertEqual(tr.integrity_at(git, "y"), ("none", ""))
        self.assertEqual(tr.integrity_at(git, "z"), ("none", ""))

    def test_a_classification_that_is_not_a_string_is_unknown_for_a_release_with_the_reason(self):
        for label, value in NOT_A_STRING.items():
            with self.subTest(label):
                table = {"0.9.15": dict(safety_entry("0.9.15", "0.9.14"), classification=value)}
                self.assertEqual(self.classify("0.9.15", "0.9.14", table), (
                    "unknown", "store-migration unknown: the classification of 0.9.15 in rollback-safety.json "
                    "is not a string"))

    def test_a_crossed_entry_that_is_not_an_object_is_unknown_on_a_rollback_with_the_reason(self):
        for label, value in {"a string": "not-rollback-safe", "a number": 5, "null": None, "a list": [],
                             "a boolean": False}.items():
            with self.subTest(label):
                table = {"0.9.14": safety_entry("0.9.14", "0.9.13", "additive", ()), "0.9.15": value}
                self.assertEqual(self.classify("0.9.14", "0.9.15", table), ("unknown", wrong_entry("0.9.14", "0.9.15")))
                table = {"0.9.14": value, "0.9.15": safety_entry("0.9.15", "0.9.14", "additive", ())}
                self.assertEqual(self.classify("0.9.13", "0.9.15", table), ("unknown", wrong_entry("0.9.13", "0.9.15")))

    def test_a_crossed_classification_that_is_not_a_string_is_unknown_on_a_rollback(self):
        for label, value in NOT_A_STRING.items():
            with self.subTest(label):
                table = {"0.9.15": dict(safety_entry("0.9.15", "0.9.14"), classification=value)}
                self.assertEqual(self.classify("0.9.14", "0.9.15", table), ("unknown", wrong_entry("0.9.14", "0.9.15")))

    def test_a_crossed_entry_that_says_not_rollback_safe_still_decides_beside_a_broken_one(self):
        table = {"0.9.14": 5, "0.9.15": safety_entry("0.9.15", "0.9.14")}
        self.assertEqual(self.classify("0.9.13", "0.9.15", table), ("not-rollback-safe", ""))

    def test_an_entry_the_answer_does_not_rest_on_is_not_read(self):
        # Above the previous pin, at or below the target, and a key that is not a version: none is crossed.
        table = {"0.9.13": 5, "0.9.15": 5, "later": 5, "0.9.14": safety_entry("0.9.14", "0.9.13", "additive", ())}
        self.assertEqual(self.classify("0.9.13", "0.9.14", table), ("additive", ""))
        forward = {"0.9.14": 5, "0.9.15": safety_entry("0.9.15", "0.9.14")}
        self.assertEqual(self.classify("0.9.15", "0.9.14", forward), ("not-rollback-safe", ""))

    def test_the_sweep_tags_a_pin_change_whose_integrity_is_not_a_string_and_goes_on(self):
        for label, value in NOT_A_STRING.items():
            with self.subTest(label):
                git = history(chain=("t8", "b", "c"))
                git.files[("b", MANIFEST)] = with_integrity("0.9.15", value)
                gh = sweep_github()
                self.assertEqual(tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW),
                                 ["fleet-v9 -> b (ai-tc 0.9.15)", "fleet-v10 -> c (ai-tc 0.9.14)"])
                tags = [call[2]["message"] for call in gh.called("POST", R("git/tags"))]
                self.assertEqual(tags[0], "fleet-v9: ai-tc 0.9.15\n\nversion: 0.9.15\nintegrity: unknown\npr: 13\n"
                                 "approver: venuverse\nstore-migration: additive\napprover-note: integrity unknown: "
                                 "metadata.integrity of the ai-tc entry is not a string\n")
                self.assertIn(f"integrity: {INTEGRITY['0.9.14']}\n", tags[1])

    def test_the_sweep_tags_a_release_whose_classification_is_not_a_string_and_goes_on(self):
        for label, value in NOT_A_STRING.items():
            with self.subTest(label):
                git = history(chain=("t8", "b", "c"))
                broken = dict(safety_entry("0.9.15", "0.9.14"), classification=value)
                git.files[("b", SAFETY_FILE)] = safety({"0.9.14": safety_entry("0.9.14", "0.9.13"), "0.9.15": broken})
                gh = sweep_github()
                self.assertEqual(len(tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW)), 2)
                tags = [call[2]["message"] for call in gh.called("POST", R("git/tags"))]
                self.assertIn("store-migration: unknown\napprover-note: store-migration unknown: the classification "
                              "of 0.9.15 in rollback-safety.json is not a string\n", tags[0])

    def test_the_sweep_tags_a_rollback_across_an_entry_that_is_not_an_object_and_goes_on(self):
        for label, value in {"a string": "not-rollback-safe", "null": None, "a number": 5}.items():
            with self.subTest(label):
                git = history(chain=("t8", "b", "c"))
                git.files[("c", SAFETY_FILE)] = safety({"0.9.14": safety_entry("0.9.14", "0.9.13"), "0.9.15": value})
                gh = sweep_github()
                self.assertEqual(len(tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW)), 2)
                tags = [call[2]["message"] for call in gh.called("POST", R("git/tags"))]
                self.assertIn("store-migration: unknown\nrollback-from: 0.9.15\ndrill: true\n", tags[1])
                # Joined to the note the rollback already had.
                note = f"ruleset bypass by org-owner-example; {wrong_entry('0.9.14', '0.9.15')}"
                self.assertIn(f"approver-note: {note}\n", tags[1])

    def test_a_reason_is_added_to_a_note_the_tag_already_has_and_to_none(self):
        self.assertEqual(tr.noted({"note": None, "pr": "1"}, "", "why"), {"note": "why", "pr": "1"})
        self.assertEqual(tr.noted({"note": "a", "pr": "1"}, "b", "", "c"), {"note": "a; b; c", "pr": "1"})
        self.assertEqual(tr.noted({"note": "a"}, "", ""), {"note": "a"})
        self.assertEqual(tr.noted({"note": None}, ""), {"note": None})


class TestApprover(unittest.TestCase):
    def test_the_last_owner_approval_on_the_final_head_is_named(self):
        gh = FakeGitHub({
            ("GET", R("commits/b/pulls")): [{"number": 13, "merge_commit_sha": "b", "merged_at": "2026-10-02T00:00:00Z",
                                             "base": {"ref": "main"}}],
            ("GET", R("pulls/13")): {"head": {"sha": "h13"}, "labels": [], "merged_by": {"login": "venuverse"}},
            ("GET", R("pulls/13/reviews")): [
                {"state": "APPROVED", "commit_id": "h13", "user": {"login": "venuverse"}},
                {"state": "APPROVED", "commit_id": "h13", "user": {"login": "Vaishnav-OM"}}],
            **checks("h13")})
        facts = tr.pr_facts(gh, "b", ["Vaishnav-OM", "venuverse"], sleep=lambda seconds: None)
        self.assertEqual(facts["approver"], "Vaishnav-OM")

    def facts_for(self, reviews, owners=("Vaishnav-OM", "venuverse"), unreadable=""):
        gh = FakeGitHub({
            ("GET", R("commits/b/pulls")): [{"number": 13, "merge_commit_sha": "b", "merged_at": "2026-10-02T00:00:00Z",
                                             "base": {"ref": "main"}}],
            ("GET", R("pulls/13")): {"head": {"sha": "h13"}, "labels": [{"name": "drill"}],
                                     "merged_by": {"login": "org-owner-example"}},
            ("GET", R("pulls/13/reviews")): reviews,
            **checks("h13")})
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


class TestValidateOnTheFinalHead(unittest.TestCase):
    """A code owner's approval says nothing about the required `validate` check: an org owner can merge past a
    failed or missing one. The tag for such a merge says so in its approver-note, whoever approved it."""

    NOTE = "validate had not passed on the PR's final head"
    MERGER = "org-owner-example"
    APPROVED = [{"state": "APPROVED", "commit_id": "h13", "user": {"login": "venuverse"}}]

    def facts(self, runs, reviews=None, owners=("Vaishnav-OM", "venuverse"), unreadable="", workflows=None,
              merged_at=MERGED_AT):
        """The facts for PR 13 (final head h13, merged by an org owner at `merged_at`) whose head carries `runs`
        (in the check suites `workflows` describes, by default one pull_request_target run of validate.yml each),
        and the client."""
        gh = FakeGitHub({
            ("GET", R("commits/b/pulls")): [{"number": 13, "merge_commit_sha": "b", "merged_at": merged_at,
                                             "base": {"ref": "main"}}],
            ("GET", R("pulls/13")): {"head": {"sha": "h13"}, "labels": [], "merged_by": {"login": self.MERGER}},
            ("GET", R("pulls/13/reviews")): self.APPROVED if reviews is None else reviews,
            **checks("h13", runs, workflows)})
        facts = tr.pr_facts(gh, "b", None if owners is None else list(owners), sleep=lambda seconds: None,
                            unreadable=unreadable)
        return facts, gh

    def test_an_approved_merge_whose_head_has_no_validate_run_is_noted(self):
        facts, _ = self.facts([])
        self.assertEqual((facts["pr"], facts["approver"]), ("13", "venuverse"))
        self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")

    def test_an_approved_merge_whose_latest_validate_run_did_not_succeed_is_noted_with_how_it_ended(self):
        for conclusion in ("failure", "cancelled", "timed_out", "skipped", "neutral", "action_required", "stale"):
            with self.subTest(conclusion):
                facts, _ = self.facts([validate_run(conclusion=conclusion)])
                self.assertEqual(facts["approver"], "venuverse")
                self.assertEqual(facts["note"], f"{self.NOTE} (latest run: {conclusion}); merged by {self.MERGER}")

    def test_a_validate_run_that_had_not_finished_is_noted_by_its_status(self):
        # An unfinished run has no conclusion; its status is what the note says, and it is not a pass.
        for status in ("queued", "in_progress", "waiting", "pending"):
            with self.subTest(status):
                facts, _ = self.facts([validate_run(status=status, conclusion=None)])
                self.assertEqual(facts["note"], f"{self.NOTE} (latest run: {status}); merged by {self.MERGER}")

    def test_a_rerun_that_failed_after_a_pass_leaves_the_head_unvalidated_whatever_order_they_are_listed_in(self):
        passed, failed = validate_run(7), validate_run(9, conclusion="failure")
        for label, runs in {"oldest first": [passed, failed], "newest first": [failed, passed]}.items():
            with self.subTest(label):
                facts, _ = self.facts(runs)
                self.assertEqual(facts["note"], f"{self.NOTE} (latest run: failure); merged by {self.MERGER}")

    def test_a_pass_after_a_failure_validates_the_head_whatever_order_they_are_listed_in(self):
        failed, passed = validate_run(7, conclusion="failure"), validate_run(9)
        for label, runs in {"oldest first": [failed, passed], "newest first": [passed, failed]}.items():
            with self.subTest(label):
                facts, _ = self.facts(runs)
                self.assertEqual((facts["approver"], facts["note"]), ("venuverse", None))

    def test_an_approved_merge_with_a_passing_validate_run_adds_no_note(self):
        facts, _ = self.facts([validate_run()])
        self.assertEqual(facts, {"pr": "13", "approver": "venuverse", "note": None, "drill": False})

    def test_a_bypass_with_a_failed_run_joins_both_notes_and_names_the_merger_once(self):
        facts, _ = self.facts([validate_run(conclusion="failure")], reviews=[])
        self.assertEqual(facts["approver"], "none")
        self.assertEqual(facts["note"], f"ruleset bypass by {self.MERGER}; {self.NOTE} (latest run: failure)")
        self.assertEqual(facts["note"].count(self.MERGER), 1)
        facts, _ = self.facts([], reviews=[])
        self.assertEqual(facts["note"], f"ruleset bypass by {self.MERGER}; {self.NOTE} (no run)")
        self.assertEqual(facts["note"].count(self.MERGER), 1)

    def test_a_bypass_with_a_passing_run_keeps_its_own_note_only(self):
        facts, _ = self.facts([validate_run()], reviews=[])
        self.assertEqual((facts["approver"], facts["note"]), ("none", f"ruleset bypass by {self.MERGER}"))

    def test_an_unknown_approver_with_a_failed_run_keeps_both_notes_and_names_the_merger(self):
        facts, _ = self.facts([validate_run(conclusion="failure")], owners=None, unreadable="the file names a team")
        self.assertEqual(facts["approver"], "unknown")
        self.assertEqual(facts["note"], "code owners could not be read: the file names a team; "
                                        f"{self.NOTE} (latest run: failure); merged by {self.MERGER}")
        self.assertEqual(facts["note"].count(self.MERGER), 1)

    def test_an_unknown_approver_with_a_passing_run_keeps_only_the_unreadable_note(self):
        facts, _ = self.facts([validate_run()], owners=None, unreadable="the file names a team")
        self.assertEqual((facts["approver"], facts["note"]),
                         ("unknown", "code owners could not be read: the file names a team"))

    def test_runs_from_another_app_or_under_another_name_are_ignored(self):
        # Only the job named validate that GitHub Actions reports is the required check. A green run of that name
        # from another app, or a green run of another name, passes nothing; and a red one of either does not fail
        # a head whose real validate run is green.
        not_the_check = {
            "a green run from another app": [validate_run(5, app=1234)],
            "a green run of another name": [validate_run(5, name="lint")],
            "a green run of a longer name": [validate_run(5, name="validate / extra")],
            "a green run with no app": [{"id": 5, "name": "validate", "status": "completed", "conclusion": "success"}],
            "a green run whose app is null": [dict(validate_run(5), app=None)],
        }
        for label, runs in not_the_check.items():
            with self.subTest(label):
                facts, _ = self.facts(runs)
                self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")
        beside_the_real_run = {
            "a later red run from another app": validate_run(9, conclusion="failure", app=1234),
            "a later red run of another name": validate_run(9, conclusion="failure", name="lint"),
            "a later unfinished run of another name": validate_run(9, status="in_progress", conclusion=None, name="build"),
        }
        for label, other in beside_the_real_run.items():
            with self.subTest(label):
                facts, _ = self.facts([validate_run(5), other])
                self.assertEqual((facts["approver"], facts["note"]), ("venuverse", None))

    def test_the_runs_are_asked_for_by_name_and_app_and_all_of_them(self):
        # filter=all: the default lists only the latest run of each name, which would hide a later re-run's result.
        _, gh = self.facts([validate_run()])
        asked = gh.called("GET", R("commits/h13/check-runs"))
        self.assertEqual(len(asked), 1)
        self.assertEqual(asked[0][3], {"check_name": "validate", "app_id": 15368, "filter": "all"})

    def test_a_run_of_another_workflow_file_counts_for_nothing(self):
        # A job named validate in any other file reports the same check name; only validate.yml is the check.
        for path in (".github/workflows/ci.yml", ".github/workflows/validate.yaml", ".github/workflows/validate.yml.bak",
                     ".github/workflows/sub/validate.yml", ".github/scripts/validate.yml", "validate.yml",
                     ".github/workflows/Validate.yml", "", None):
            with self.subTest(path):
                facts, _ = self.facts([validate_run(5)], workflows={suite_of(5): [workflow_run(suite_of(5), path=path)]})
                self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")

    def test_a_run_of_validate_yml_that_another_event_started_counts_for_nothing(self):
        # validate.yml answers for pull_request_target, whose workflow GitHub takes from main. The same file run for
        # a pull request, a push or by hand is the file as the branch has it, which the branch's author wrote.
        for event in ("pull_request", "push", "workflow_dispatch", "schedule", "workflow_run", "pull_request_review",
                      "", None):
            with self.subTest(event):
                facts, _ = self.facts([validate_run(5)], workflows={suite_of(5): [workflow_run(suite_of(5), event=event)]})
                self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")

    def test_a_workflow_run_the_api_gives_no_event_or_path_for_counts_for_nothing(self):
        for label, workflow in {"no event": {"id": 1, "path": tr.VALIDATE_WORKFLOW},
                                "no path": {"id": 1, "event": "pull_request_target"},
                                "not an object": "validate.yml"}.items():
            with self.subTest(label):
                facts, _ = self.facts([validate_run(5)], workflows={suite_of(5): [workflow]})
                self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")

    def test_the_workflow_file_is_the_file_whatever_ref_follows_its_path(self):
        facts, _ = self.facts([validate_run(5)], workflows={
            suite_of(5): [workflow_run(suite_of(5), path=f"{tr.VALIDATE_WORKFLOW}@refs/heads/main")]})
        self.assertEqual((facts["approver"], facts["note"]), ("venuverse", None))

    def test_a_pass_from_another_workflow_cannot_stand_in_for_a_failed_validate(self):
        # What the rule is for: a pull request can add a workflow with a job named validate, and its green run is
        # newer than the real one. It must not turn a head the real check failed on into a validated one.
        failed, impostor = validate_run(7, conclusion="failure"), validate_run(9)
        for what, workflow in {"another file": workflow_run(suite_of(9), path=".github/workflows/ci.yml"),
                               "validate.yml run for a push": workflow_run(suite_of(9), event="push"),
                               "validate.yml run for a pull request": workflow_run(suite_of(9), event="pull_request")}.items():
            for label, runs in {"oldest first": [failed, impostor], "newest first": [impostor, failed]}.items():
                with self.subTest(f"{what}, {label}"):
                    facts, _ = self.facts(runs, workflows={suite_of(7): [workflow_run(suite_of(7))],
                                                           suite_of(9): [workflow]})
                    self.assertEqual(facts["note"], f"{self.NOTE} (latest run: failure); merged by {self.MERGER}")

    def test_a_failure_from_another_workflow_does_not_fail_a_validated_head(self):
        passed, impostor = validate_run(7), validate_run(9, conclusion="failure")
        facts, _ = self.facts([passed, impostor], workflows={
            suite_of(7): [workflow_run(suite_of(7))],
            suite_of(9): [workflow_run(suite_of(9), path=".github/workflows/ci.yml")]})
        self.assertEqual((facts["approver"], facts["note"]), ("venuverse", None))

    def test_a_run_that_started_after_the_merge_does_not_fail_a_head_that_was_validated(self):
        # An edit of the closed pull request, or a manual re-run, starts validate again on the same head.
        passed, later = validate_run(7), validate_run(9, conclusion="failure", started_at=AFTER_THE_MERGE)
        for label, runs in {"oldest first": [passed, later], "newest first": [later, passed]}.items():
            with self.subTest(label):
                facts, _ = self.facts(runs)
                self.assertEqual((facts["approver"], facts["note"]), ("venuverse", None))

    def test_a_run_that_started_after_the_merge_does_not_pass_a_head_that_was_not_validated(self):
        failed, later = validate_run(7, conclusion="failure"), validate_run(9, started_at=AFTER_THE_MERGE)
        for label, runs in {"oldest first": [failed, later], "newest first": [later, failed]}.items():
            with self.subTest(label):
                facts, _ = self.facts(runs)
                self.assertEqual(facts["note"], f"{self.NOTE} (latest run: failure); merged by {self.MERGER}")

    def test_a_head_whose_only_run_started_after_the_merge_had_no_run(self):
        facts, _ = self.facts([validate_run(9, started_at=AFTER_THE_MERGE)])
        self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")

    def test_a_run_queued_before_the_merge_and_started_after_it_does_not_count(self):
        # The workflow run was created (queued) before the merge, as every re-run's is; the job started after it.
        # Its start is what counts, so a re-run of a passing validate cannot pass a head that failed it.
        failed, rerun = validate_run(7, conclusion="failure"), validate_run(9, started_at=AFTER_THE_MERGE)
        facts, _ = self.facts([failed, rerun], workflows={
            suite_of(7): [workflow_run(suite_of(7))],
            suite_of(9): [workflow_run(suite_of(9), created_at="2026-10-01T23:30:00Z")]})
        self.assertEqual(facts["note"], f"{self.NOTE} (latest run: failure); merged by {self.MERGER}")

    def test_a_run_that_started_in_the_second_of_the_merge_counts_and_one_a_second_later_does_not(self):
        facts, _ = self.facts([validate_run(7, started_at=MERGED_AT)])
        self.assertEqual((facts["approver"], facts["note"]), ("venuverse", None))
        facts, _ = self.facts([validate_run(7, started_at="2026-10-02T00:00:01Z")])
        self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")

    def test_the_merge_time_is_the_time_the_pull_request_merged(self):
        # The same run is before one merge and after another.
        run = validate_run(7, started_at="2026-10-02T00:00:30Z")
        facts, _ = self.facts([run], merged_at="2026-10-02T00:01:00Z")
        self.assertEqual((facts["approver"], facts["note"]), ("venuverse", None))
        facts, _ = self.facts([run], merged_at="2026-10-02T00:00:00Z")
        self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")

    def test_a_run_with_no_usable_start_time_counts_for_nothing(self):
        for started in (None, "", "yesterday", "2026-10-01", "2026-10-01T23:59:00+00:00", "2026-10-01 23:59:00", 1790000000):
            with self.subTest(started):
                facts, _ = self.facts([validate_run(7, started_at=started)])
                self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")
        run = validate_run(7)
        del run["started_at"]
        facts, _ = self.facts([run])
        self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")

    def test_a_merge_with_no_usable_time_leaves_no_run_to_count(self):
        for merged_at in (None, "", "last week", "2026-10-02", "2026-10-02T00:00:00+00:00", 1790000000):
            with self.subTest(merged_at):
                gh = FakeGitHub(checks("h13", [validate_run(7)]))
                self.assertIsNone(tr.validate_conclusion(gh, "h13", merged_at))

    def test_a_check_run_with_no_check_suite_counts_for_nothing(self):
        for label, suite in {"none": None, "empty": {}, "no id": {"id": None}, "a text id": {"id": "9007"},
                             "a true id": {"id": True}}.items():
            with self.subTest(label):
                run = dict(validate_run(7), check_suite=suite)
                facts, gh = self.facts([run])
                self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")
                self.assertEqual(gh.called("GET", R("actions/runs")), [])
        run = validate_run(7)
        del run["check_suite"]
        facts, _ = self.facts([run])
        self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")

    def test_a_check_suite_that_lists_no_workflow_run_or_two_counts_for_nothing(self):
        # Nothing then says which workflow the check run belongs to. A suite is one workflow run's.
        valid = workflow_run(suite_of(7))
        for label, listed in {"none": [], "two": [valid, workflow_run(suite_of(7), path=".github/workflows/ci.yml")],
                              "the same twice": [valid, valid]}.items():
            with self.subTest(label):
                facts, _ = self.facts([validate_run(7)], workflows={suite_of(7): listed})
                self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")

    def test_an_answer_that_is_not_a_list_of_workflow_runs_counts_for_nothing(self):
        for label, answer in {"a list": [], "text": "none", "no list": {"total_count": 1},
                              "a null list": {"workflow_runs": None}, "text for the list": {"workflow_runs": "x"}}.items():
            with self.subTest(label):
                gh = FakeGitHub({**checks("h13", [validate_run(7)]), ("GET", R("actions/runs")): answer})
                self.assertIsNone(tr.validate_conclusion(gh, "h13", MERGED_AT))

    def test_the_workflow_run_is_asked_for_through_the_check_suite_of_the_run_that_decides(self):
        # Newest first, and only until one counts: the older runs are not asked about.
        _, gh = self.facts([validate_run(5), validate_run(9), validate_run(7)])
        asked = gh.called("GET", R("actions/runs"))
        self.assertEqual([call[3] for call in asked], [{"check_suite_id": suite_of(9)}])

    def test_older_runs_are_asked_about_only_while_the_newer_ones_do_not_count(self):
        workflows = {suite_of(9): [workflow_run(suite_of(9), path=".github/workflows/ci.yml")],
                     suite_of(7): [workflow_run(suite_of(7))]}
        facts, gh = self.facts([validate_run(5), validate_run(9, conclusion="failure"),
                                validate_run(7, conclusion="cancelled")], workflows=workflows)
        self.assertEqual(facts["note"], f"{self.NOTE} (latest run: cancelled); merged by {self.MERGER}")
        self.assertEqual([call[3] for call in gh.called("GET", R("actions/runs"))],
                         [{"check_suite_id": suite_of(9)}, {"check_suite_id": suite_of(7)}])

    def test_a_check_suite_is_asked_about_once(self):
        # Two attempts of one job share a suite.
        runs = [validate_run(7, suite=9100), validate_run(9, suite=9100), validate_run(8, suite=9100)]
        facts, gh = self.facts(runs, workflows={9100: [workflow_run(9100, path=".github/workflows/ci.yml")]})
        self.assertEqual(facts["note"], f"{self.NOTE} (no run); merged by {self.MERGER}")
        self.assertEqual([call[3] for call in gh.called("GET", R("actions/runs"))], [{"check_suite_id": 9100}])

    def test_no_workflow_run_is_asked_about_for_a_head_nothing_validated_before_the_merge(self):
        _, gh = self.facts([validate_run(9, started_at=AFTER_THE_MERGE), validate_run(7, name="lint")])
        self.assertEqual(gh.called("GET", R("actions/runs")), [])

    def test_the_api_envelopes_and_every_page_of_runs_are_read_through_the_real_client(self):
        pages = {1: [validate_run(run_id, conclusion="failure") for run_id in range(101, 201)],
                 2: [validate_run(300)]}
        asked = []

        def transport(method, url, headers, data):
            parsed = urllib.parse.urlparse(url)
            asked.append(parsed)
            query = urllib.parse.parse_qs(parsed.query)
            if parsed.path == f"/repos/{REPO}/actions/runs":
                # The envelope the workflow-run list is answered in.
                found = [workflow_run(int(query["check_suite_id"][0]))]
                return 200, json.dumps({"total_count": len(found), "workflow_runs": found}).encode()
            return 200, json.dumps({"total_count": 101, "check_runs": pages[int(query["page"][0])]}).encode()

        client = GitHub("token", REPO, transport=transport)
        # 100 failed runs on the first page and the latest, a pass, on the second: the highest id decides.
        self.assertEqual(tr.validate_conclusion(client, "h13", MERGED_AT), "success")
        self.assertEqual([call.path for call in asked],
                         [f"/repos/{REPO}/commits/h13/check-runs"] * 2 + [f"/repos/{REPO}/actions/runs"])
        self.assertEqual(urllib.parse.parse_qs(asked[0].query),
                         {"check_name": ["validate"], "app_id": ["15368"], "filter": ["all"],
                          "per_page": ["100"], "page": ["1"]})
        # Only the run that decides is looked up, through its check suite.
        self.assertEqual(urllib.parse.parse_qs(asked[2].query), {"check_suite_id": [str(suite_of(300))]})

    def test_no_pull_request_means_no_check_read(self):
        # The routes hold no check-runs answer: a read of one fails the test.
        gh = FakeGitHub({("GET", R("commits/d/pulls")): []})
        facts = tr.pr_facts(gh, "d", None, sleep=lambda seconds: None)
        self.assertEqual((facts["pr"], facts["approver"]), ("none", "none"))
        self.assertEqual(facts["note"], "no pull request merged this commit")

    def test_the_tag_for_a_merge_past_a_failed_validate_carries_the_note(self):
        gh = sweep_github()
        gh.routes.update(checks("h13", [validate_run(7), validate_run(9, conclusion="failure")]))
        tr.sweep(history(chain=("t8", "b")), gh, sleep=lambda seconds: None, now=lambda: NOW)
        message = gh.called("POST", R("git/tags"))[0][2]["message"]
        self.assertEqual(message, "fleet-v9: ai-tc 0.9.15\n\nversion: 0.9.15\n"
                         f"integrity: {INTEGRITY['0.9.15']}\npr: 13\napprover: venuverse\nstore-migration: additive\n"
                         f"approver-note: {self.NOTE} (latest run: failure); merged by venuverse\n")
        # The audit reads the same message: one pr, one approver.
        parsed = release_checks.parse_tag_message(message)
        self.assertEqual((parsed["pr"], parsed["approver"]), ("13", "venuverse"))

    def test_the_tag_for_a_merge_whose_only_validate_run_belongs_to_another_workflow_carries_the_note(self):
        gh = sweep_github()
        gh.routes.update(checks("h13", [validate_run(7)], {
            suite_of(7): [workflow_run(suite_of(7), path=".github/workflows/ci.yml")]}))
        tr.sweep(history(chain=("t8", "b")), gh, sleep=lambda seconds: None, now=lambda: NOW)
        message = gh.called("POST", R("git/tags"))[0][2]["message"]
        self.assertIn(f"approver-note: {self.NOTE} (no run); merged by venuverse\n", message)

    def test_a_run_made_after_the_merge_changes_nothing_in_the_tag(self):
        # PR 13 merged at MERGED_AT: a failed run that started after it is not what the tag records.
        gh = sweep_github()
        gh.routes.update(checks("h13", [validate_run(7), validate_run(9, conclusion="failure",
                                                                    started_at=AFTER_THE_MERGE)]))
        tr.sweep(history(chain=("t8", "b")), gh, sleep=lambda seconds: None, now=lambda: NOW)
        self.assertNotIn("approver-note", gh.called("POST", R("git/tags"))[0][2]["message"])

    def test_the_note_is_added_only_to_the_tag_whose_head_did_not_pass(self):
        gh = sweep_github()
        gh.routes.update(checks("h14", [validate_run(conclusion="failure")]))
        tr.sweep(history(chain=("t8", "b", "c")), gh, sleep=lambda seconds: None, now=lambda: NOW)
        first, second = (call[2]["message"] for call in gh.called("POST", R("git/tags")))
        self.assertNotIn("approver-note", first)
        self.assertIn("approver-note: ruleset bypass by org-owner-example; "
                      f"{self.NOTE} (latest run: failure)\n", second)

    def test_the_checks_are_read_with_the_workflow_token_and_the_tags_are_written_with_the_apps(self):
        writer = sweep_github()
        # A read of the checks or of their workflow runs through this client fails.
        del writer.routes[("GET", R("commits/h13/check-runs"))]
        del writer.routes[("GET", R("actions/runs"))]
        reader = FakeGitHub(checks("h13", [validate_run(conclusion="failure")]))
        clients = {"app-token": writer, "workflow-token": reader}
        env = {"GITHUB_REPOSITORY": REPO, "GH_TOKEN": "app-token", "GITHUB_TOKEN": "workflow-token"}
        out = io.StringIO()
        with mock.patch.dict(os.environ, env), mock.patch.object(tr, "Git", lambda path: history(chain=("t8", "b"))), \
                mock.patch.object(tr, "GitHub", lambda token, repo: clients[token]), contextlib.redirect_stdout(out):
            code = tr.main(["sweep"])
        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual([(call[0], call[1]) for call in reader.calls],
                         [("GET", R("commits/h13/check-runs")), ("GET", R("actions/runs"))])
        self.assertEqual(reader.writes(), [])
        message = writer.called("POST", R("git/tags"))[0][2]["message"]
        self.assertIn(f"approver-note: {self.NOTE} (latest run: failure); merged by venuverse\n", message)

    def test_a_check_read_that_fails_stops_the_sweep_before_that_commit_is_tagged(self):
        # A tag is permanent, so a read that cannot say how validate ended must not become a tag without the note.
        gh = sweep_github()
        path = R("commits/h13/check-runs")
        gh.routes[("GET", path)] = GitHubError(403, "GET", path, "Resource not accessible by integration")
        code, out = run_main("sweep", history(chain=("t8", "b", "c")), gh)
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("::error::"), out)
        self.assertIn("HTTP 403", out)
        self.assertEqual(out.count("\n"), 1)
        self.assertEqual(gh.writes(), [])


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
        # Once a commit is merged, the CODEOWNERS of its parent can no longer change, so a pin change that a pull
        # request merged on top of a file the strict reader cannot read is tagged with an unknown approver (a push
        # with no pull request records `none`, whatever the file holds). This fails on the pull request first; the
        # workflow that runs it is not a required check, so it does not stop the merge.
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

    def test_a_file_that_is_not_utf8_text_is_a_refusal_that_names_the_file(self):
        # Read through the real Git, which decodes what it shows as UTF-8 and raises on a byte that is not: the
        # strict reader must turn that into its refusal, and only for bytes that are not text (a UTF-8 comment is fine).
        with tempfile.TemporaryDirectory() as directory:
            env = ts.git_env("test", "test@example.invalid")

            def sh(*args):
                return ts.git(directory, *args, env=env).strip()

            def commit_owners(content: bytes) -> str:
                with open(os.path.join(directory, ".github", "CODEOWNERS"), "wb") as handle:
                    handle.write(content)
                sh("add", "-A")
                sh("commit", "-q", "-m", "owners")
                return sh("rev-parse", "HEAD")

            sh("init", "-q", "-b", "main")
            os.makedirs(os.path.join(directory, ".github"))
            git = Git(directory)
            readable = commit_owners("# caf\u00e9 team\n* @a @b\n".encode("utf-8"))
            self.assertEqual(tr.code_owners(git, readable), ["a", "b"])
            unreadable = commit_owners(b"# caf\xe9 team\n* @a @b\n")  # one Latin-1 byte, in a comment
            with self.assertRaises(Refused) as caught:
                tr.code_owners(git, unreadable)
            self.assertIn(f".github/CODEOWNERS at {unreadable[:12]}", str(caught.exception))
            self.assertIn("not valid UTF-8", str(caught.exception))


    def test_an_entry_that_is_not_a_file_is_a_refusal_that_names_the_kind(self):
        # A submodule entry has no blob: Git.show raises GitError ("bad object") for it, and that must not escape
        # as a statement about the checkout, because the sweep would stop on it for good.
        for mode, kind in (("160000", "a submodule"), ("120000", "a symbolic link"), ("040000", "a directory")):
            with self.subTest(kind):
                git = FakeGit(chain=["x"], files={("x", ".github/CODEOWNERS"): "* @a\n"},
                              modes={("x", ".github/CODEOWNERS"): mode})
                with self.assertRaises(Refused) as caught:
                    tr.code_owners(git, "x")
                self.assertIn(f".github/CODEOWNERS at x is {kind}, not a file", str(caught.exception))
        # An executable file is still a file.
        git = FakeGit(chain=["x"], files={("x", ".github/CODEOWNERS"): "* @a\n"},
                      modes={("x", ".github/CODEOWNERS"): "100755"})
        self.assertEqual(tr.code_owners(git, "x"), ["a"])

    def test_an_entry_that_is_not_a_file_is_a_refusal_in_a_real_repository(self):
        # Read through the real Git: a gitlink at the path makes `git show` fail with "bad object", a symbolic link
        # shows its target, and a directory lists its entries. None of them is a file of rules.
        with tempfile.TemporaryDirectory() as directory:
            sh = scratch_repository(directory)
            path = os.path.join(directory, ".github", "CODEOWNERS")
            os.makedirs(os.path.dirname(path))
            git = Git(directory)

            def commit(label):
                sh("add", "-A")
                sh("commit", "-q", "-m", label)
                return sh("rev-parse", "HEAD")

            with open(path, "w", encoding="utf-8") as handle:
                handle.write("* @a @b\n")
            plain = commit("file")
            self.assertEqual(tr.code_owners(git, plain), ["a", "b"])

            os.remove(path)
            sh("update-index", "--add", "--cacheinfo", f"160000,{'a' * 40},.github/CODEOWNERS")
            sh("commit", "-q", "-m", "submodule")
            submodule = sh("rev-parse", "HEAD")
            self.assertEqual(sh("ls-tree", submodule, "--", ".github/CODEOWNERS").split()[:2], ["160000", "commit"])
            with self.assertRaises(GitError):
                git.show(submodule, ".github/CODEOWNERS")  # the failure Git.show reports for it
            sh("rm", "-q", "--cached", ".github/CODEOWNERS")

            os.symlink("elsewhere", path)
            link = commit("symbolic link")
            os.remove(path)
            os.makedirs(path)
            with open(os.path.join(path, "inner"), "w", encoding="utf-8") as handle:
                handle.write("* @a\n")
            directory_entry = commit("directory")

            for label, sha, kind in (("submodule", submodule, "a submodule"), ("symbolic link", link, "a symbolic link"),
                                     ("directory", directory_entry, "a directory")):
                with self.subTest(label):
                    with self.assertRaises(Refused) as caught:
                        tr.code_owners(git, sha)
                    self.assertIn(f".github/CODEOWNERS at {sha[:12]} is {kind}, not a file", str(caught.exception))


    def test_a_damaged_checkout_still_raises_instead_of_reading_as_unreadable_owners(self):
        # Git.show raises GitError for a blob the tree lists but the checkout lacks. That says the checkout is
        # damaged, not that the file is unreadable, so it must stay an error and not become an unknown approver.
        with tempfile.TemporaryDirectory() as directory:
            sh = scratch_repository(directory)
            os.makedirs(os.path.join(directory, ".github"))
            with open(os.path.join(directory, ".github", "CODEOWNERS"), "w", encoding="utf-8") as handle:
                handle.write("* @a\n")
            sh("add", "-A")
            sh("commit", "-q", "-m", "owners")
            sha = sh("rev-parse", "HEAD")
            blob = sh("rev-parse", f"{sha}:.github/CODEOWNERS")
            loose = os.path.join(directory, ".git", "objects", blob[:2], blob[2:])
            os.chmod(loose, 0o644)
            os.remove(loose)
            with self.assertRaises(GitError):
                tr.code_owners(Git(directory), sha)


class TestSweepOwners(unittest.TestCase):
    """The owners come from the merged commit's parent, which is fixed history: no later pull request can change
    that file. A file the strict reader cannot read must therefore never stop the sweep, or tagging would stop
    for good. The tag says the approver is unknown instead."""

    def test_a_codeowners_file_it_cannot_read_gives_an_unknown_approver_and_the_tag_is_cut(self):
        cases = {
            "a team owner": "* @akasecurity/maintainers\n",
            "a path rule": "* @Vaishnav-OM @venuverse\n/docs @venuverse\n",
            "no file": None,
            "bytes that are not UTF-8": b"# caf\xe9 team\n* @Vaishnav-OM @venuverse\n",
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

    def test_a_codeowners_entry_that_is_a_submodule_gives_an_unknown_approver_and_the_tag_is_cut(self):
        # Reading it raises GitError in the checkout, not a Refused; the sweep must not stop on a parent that can
        # never change. The commit after it is tagged with its own parent's file.
        git = history(chain=("t8", "b", "c"))
        git.modes[("t8", ".github/CODEOWNERS")] = "160000"
        gh = sweep_github()
        self.assertEqual(tr.sweep(git, gh, sleep=lambda seconds: None, now=lambda: NOW),
                         ["fleet-v9 -> b (ai-tc 0.9.15)", "fleet-v10 -> c (ai-tc 0.9.14)"])
        first, second = (call[2]["message"] for call in gh.called("POST", R("git/tags")))
        self.assertIn("pr: 13\napprover: unknown\n", first)
        self.assertRegex(first, r"(?m)^approver-note: code owners could not be read: "
                                r"\.github/CODEOWNERS at t8 is a submodule, not a file")
        self.assertIn("approver: none\n", second)  # c's parent (b) holds a readable file; nobody approved PR 14

    def test_an_unreadable_file_marks_only_the_commits_whose_parent_holds_it(self):
        # b's parent (t8) and d's parent (c) are readable; c's parent (b) is not. The catch that no longer refuses is
        # what lets the sweep carry on past c; reading each commit's own parent is what gives d its real approver.
        git = history(chain=("t8", "b", "c", "d"), times={"d": NOW - 7200})
        git.files[("b", ".github/CODEOWNERS")] = "* @akasecurity/maintainers\n"
        gh = sweep_github()
        gh.routes[("GET", R("commits/d/pulls"))] = [
            {"number": 17, "merge_commit_sha": "d", "merged_at": "2026-10-04T00:00:00Z", "base": {"ref": "main"}}]
        gh.routes[("GET", R("pulls/17"))] = {"head": {"sha": "h17"}, "labels": [], "merged_by": {"login": "venuverse"}}
        gh.routes[("GET", R("pulls/17/reviews"))] = [
            {"state": "APPROVED", "commit_id": "h17", "user": {"login": "Vaishnav-OM"}}]
        gh.routes.update(checks("h17"))
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
            "check run read": (history(chain=("t8", "b")), reads(R("commits/h13/check-runs"), 403)),
            "workflow run read": (history(chain=("t8", "b")), reads(R("actions/runs"), 403)),
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
