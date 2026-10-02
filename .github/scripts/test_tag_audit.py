"""Tests for tag_audit.py: the ruleset read, the previous-run comparison and the frozen list."""
import copy
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import release_checks
import tag_audit as ta
from fakes import REPO, FakeGit, FakeGitHub, fleet_tag

UPDATE = {"type": "update", "parameters": {"update_allows_fetch_and_merge": False}}
LOCKED = [{"type": "creation"}, UPDATE, {"type": "deletion"}]


def R(suffix):
    return f"repos/{REPO}/{suffix}"


def ruleset(number, name, target, include, rules, exclude=()):
    return {"id": number, "name": name, "target": target, "enforcement": "active",
            "conditions": {"ref_name": {"include": list(include), "exclude": list(exclude)}}, "rules": copy.deepcopy(rules)}


def good_rulesets():
    review = {"required_approving_review_count": 1, "require_code_owner_review": True,
              "dismiss_stale_reviews_on_push": True, "require_last_push_approval": True,
              "required_review_thread_resolution": False, "allowed_merge_methods": ["squash"]}
    checks = {"strict_required_status_checks_policy": False,
              "required_status_checks": [{"context": "validate", "integration_id": 15368}]}
    return {
        1: ruleset(1, "main", "branch", ["refs/heads/main"],
                   [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "pull_request", "parameters": review},
                    {"type": "required_status_checks", "parameters": checks}]),
        2: ruleset(2, "tags-locked", "tag", ["refs/tags/*", "refs/tags/**/*"], LOCKED, exclude=["refs/tags/fleet-v*"]),
        3: ruleset(3, "fleet-tags-create", "tag", ["refs/tags/fleet-v*"], [{"type": "creation"}]),
        4: ruleset(4, "fleet-tags-immutable", "tag", ["refs/tags/fleet-v*"],
                   [UPDATE, {"type": "deletion"}, {"type": "non_fast_forward"}]),
        5: ruleset(5, "bot-branches", "branch", ["refs/heads/bot/*", "refs/heads/bot/**/*"], LOCKED),
        6: ruleset(6, "x4-branches", "branch", ["refs/heads/x4/*"], LOCKED),
        7: ruleset(7, "x4-tags", "tag", ["refs/tags/x4/*"], LOCKED),
    }


COMMIT = "1" * 40
FROZEN = "if this change is explained, re-freeze it in a reviewed pull request (`tag_audit.py freeze`)"


def frozen_file(testcase, rows):
    """A frozen tag list on disk holding `rows`; removed when the test ends."""
    root = tempfile.TemporaryDirectory()
    testcase.addCleanup(root.cleanup)
    path = os.path.join(root.name, "fleet-tags.frozen.json")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(release_checks.dump_json(rows))
    return path


def github(rulesets):
    routes = {("GET", R("rulesets")): [{"id": number, "name": body["name"]} for number, body in rulesets.items()]}
    for number, body in rulesets.items():
        routes[("GET", R(f"rulesets/{number}"))] = body
    return FakeGitHub(routes)


class TestRulesets(unittest.TestCase):
    def test_the_configured_rulesets_pass(self):
        self.assertEqual(ta.check_rulesets(github(good_rulesets())), [])
        # RULESETS is built from release_checks' tables, the ones an external vendored copy
        # of release_checks.audit_rulesets runs, so the two cannot drift.
        self.assertEqual({name: (want["target"], want["rules"]) for name, want in ta.RULESETS.items()},
                         release_checks.EXPECTED_RULESETS)

    def test_the_fallback_tag_include_passes(self):
        sets = good_rulesets()
        sets[2]["conditions"]["ref_name"]["include"] = ["refs/tags/**/*", "refs/tags/*"]
        self.assertEqual(ta.check_rulesets(github(sets)), [])

    def test_a_missing_or_duplicated_ruleset_is_named(self):
        sets = good_rulesets()
        del sets[5]
        sets[8] = dict(copy.deepcopy(sets[4]), id=8)
        problems = ta.check_rulesets(github(sets))
        self.assertIn("ruleset 'bot-branches': expected exactly one, found 0", problems)
        self.assertIn("ruleset 'fleet-tags-immutable': expected exactly one, found 2", problems)

    def test_a_disabled_ruleset_is_named(self):
        sets = good_rulesets()
        sets[4]["enforcement"] = "disabled"
        self.assertEqual(ta.check_rulesets(github(sets)), ["ruleset 'fleet-tags-immutable' is 'disabled', not active"])

    def test_main_without_its_review_rules_or_the_pinned_check_is_named(self):
        sets = good_rulesets()
        sets[1]["rules"][2]["parameters"]["allowed_merge_methods"] = ["merge", "squash"]
        sets[1]["rules"][3]["parameters"]["required_status_checks"] = [{"context": "validate"}]
        problems = ta.check_rulesets(github(sets))
        self.assertIn("ruleset 'main': pull_request allowed_merge_methods is ['merge', 'squash'], expected ['squash']", problems)
        self.assertIn("ruleset 'main': the required check `validate` pinned to the GitHub Actions app is missing", problems)

    def test_a_leftover_probe_pattern_is_named(self):
        sets = good_rulesets()
        sets[2]["conditions"]["ref_name"]["exclude"].append("refs/tags/ruleset-probe-*")
        sets[3]["conditions"]["ref_name"]["include"].append("refs/tags/ruleset-probe-*")
        problems = ta.check_rulesets(github(sets))
        self.assertEqual(len(problems), 2)
        self.assertTrue(problems[0].startswith("ruleset 'tags-locked': exclude is"))
        self.assertTrue(problems[1].startswith("ruleset 'fleet-tags-create': include is"))

    def test_an_update_rule_that_allows_fetch_and_merge_is_named(self):
        sets = good_rulesets()
        sets[4]["rules"][0] = {"type": "update", "parameters": {"update_allows_fetch_and_merge": True}}
        self.assertEqual(ta.check_rulesets(github(sets)),
                         ["ruleset 'fleet-tags-immutable': its update rule allows fetch-and-merge"])

    def test_unreadable_conditions_are_named(self):
        sets = good_rulesets()
        del sets[3]["conditions"]
        self.assertEqual(ta.check_rulesets(github(sets)), ["ruleset 'fleet-tags-create': its ref conditions are not readable"])


class TestSnapshots(unittest.TestCase):
    def test_freeze_lists_every_annotated_fleet_tag_in_order(self):
        git = FakeGit(chain=["c1", "c2"], tags=[fleet_tag(2, "c2"), fleet_tag(1, "c1")])
        self.assertEqual(json.loads(ta.freeze_text(git)),
                         [{"tag": "fleet-v1", "object": fleet_tag(1, "c1")["object"], "commit": "c1"},
                          {"tag": "fleet-v2", "object": fleet_tag(2, "c2")["object"], "commit": "c2"}])
        self.assertTrue(ta.freeze_text(git).endswith("}\n]\n"))

    def test_freeze_refuses_a_lightweight_tag(self):
        git = FakeGit(chain=["c1"], tags=[{"tag": "fleet-v1", "n": 1, "object": "c1", "commit": "c1"}])
        with self.assertRaises(SystemExit):
            ta.freeze_text(git)

    def test_a_moved_or_vanished_tag_is_named_and_a_new_one_is_not(self):
        previous = [{"tag": "fleet-v1", "object": "o1", "commit": "c1"}, {"tag": "fleet-v2", "object": "o2", "commit": "c2"}]
        current = [{"tag": "fleet-v1", "object": "o9", "commit": "c9"}, {"tag": "fleet-v3", "object": "o3", "commit": "c3"}]
        self.assertEqual(ta.compare_previous(previous, current), [
            f"fleet-v1 moved since the last green run: tag object o1 -> o9, commit c1 -> c9; {FROZEN}",
            f"fleet-v2 (tag object o2) existed at the last green run and is gone; re-create it at commit c2, then {FROZEN}"])

    def test_a_change_the_frozen_list_records_is_accepted_and_only_that_exact_change(self):
        previous = [{"tag": "fleet-v1", "object": "o1", "commit": "c1"}, {"tag": "fleet-v2", "object": "o2", "commit": "c2"}]
        current = [{"tag": "fleet-v1", "object": "o9", "commit": "c9"}, {"tag": "fleet-v2", "object": "o8", "commit": "c8"}]
        frozen = [{"tag": "fleet-v1", "object": "o9", "commit": "c9"}, {"tag": "fleet-v2", "object": "o7", "commit": "c7"}]
        problems = ta.compare_previous(previous, current, frozen)
        self.assertEqual(len(problems), 1)
        self.assertTrue(problems[0].startswith("fleet-v2 moved since the last green run"), problems)

    def test_a_deleted_tag_is_not_accepted_by_a_frozen_row(self):
        previous = [{"tag": "fleet-v1", "object": "o1", "commit": "c1"}]
        problems = ta.compare_previous(previous, [], [{"tag": "fleet-v1", "object": "o1", "commit": "c1"}])
        self.assertEqual(len(problems), 1)
        self.assertIn("is gone", problems[0])

    def test_an_unreadable_frozen_list_accepts_nothing(self):
        previous = [{"tag": "fleet-v1", "object": "o1", "commit": "c1"}]
        current = [{"tag": "fleet-v1", "object": "o9", "commit": "c9"}]
        self.assertEqual(len(ta.compare_previous(previous, current, None)), 1)


class TestRunCheck(unittest.TestCase):
    def test_every_source_of_problems_is_reported(self):
        git = FakeGit(chain=["c1"], tags=[fleet_tag(1, "c1")])
        with mock.patch.object(release_checks, "audit_tags", return_value=["fleet-v9 names PR 13, not a bot PR"]) as audit:
            problems = ta.run_check(git, github(good_rulesets()), ".github/fleet-tags.frozen.json",
                                    [{"tag": "fleet-v1", "object": "old", "commit": "c1"}])
        audit.assert_called_once_with("/fake/marketplace", ".github/fleet-tags.frozen.json", check_rulesets=False)
        self.assertEqual(problems[0], "tag ledger: fleet-v9 names PR 13, not a bot PR")
        self.assertTrue(problems[1].startswith("fleet-v1 moved since the last green run"))
        result = ta.as_result(problems)
        self.assertEqual((result.rule, result.label, result.red), ("tag-audit", "tag-audit", True))

    def test_a_change_a_reviewed_refreeze_records_is_accepted(self):
        git = FakeGit(chain=[COMMIT], tags=[fleet_tag(1, COMMIT)])
        moved = [{"tag": "fleet-v1", "object": "f" * 40, "commit": COMMIT}]
        refrozen = frozen_file(self, [{"tag": "fleet-v1", "object": fleet_tag(1, COMMIT)["object"], "commit": COMMIT}])
        stale = frozen_file(self, moved)
        with mock.patch.object(release_checks, "audit_tags", return_value=[]):
            self.assertEqual(ta.run_check(git, github(good_rulesets()), refrozen, moved), [])
            # The same move against a list that does not record it stays red.
            problems = ta.run_check(git, github(good_rulesets()), stale, moved)
        self.assertEqual(len(problems), 1)
        self.assertTrue(problems[0].startswith("fleet-v1 moved since the last green run"), problems)

    def two_tags(self):
        return FakeGit(chain=[COMMIT], tags=[fleet_tag(1, COMMIT), fleet_tag(2, COMMIT)])

    def row(self, n):
        return {"tag": f"fleet-v{n}", "object": fleet_tag(n, COMMIT)["object"], "commit": COMMIT}

    def test_with_no_snapshot_every_tag_must_be_in_the_frozen_list(self):
        short = frozen_file(self, [self.row(1)])
        with mock.patch.object(release_checks, "audit_tags", return_value=[]):
            problems = ta.run_check(self.two_tags(), github(good_rulesets()), short, None, baseline_expected=True)
        self.assertEqual(problems, [
            "no snapshot from an earlier green run to compare against, and the frozen list does not record fleet-v2; "
            "re-freeze every fleet-v tag in a reviewed pull request to set a new baseline"])

    def test_with_no_snapshot_a_complete_frozen_list_is_enough(self):
        complete = frozen_file(self, [self.row(1), self.row(2)])
        with mock.patch.object(release_checks, "audit_tags", return_value=[]):
            self.assertEqual(
                ta.run_check(self.two_tags(), github(good_rulesets()), complete, None, baseline_expected=True), [])

    def test_a_caller_that_does_not_ask_for_a_baseline_gets_neither_rule(self):
        short = frozen_file(self, [self.row(1)])
        with mock.patch.object(release_checks, "audit_tags", return_value=[]):
            self.assertEqual(ta.run_check(self.two_tags(), github(good_rulesets()), short, None), [])

    def test_an_unreadable_frozen_list_adds_no_coverage_problem_of_its_own(self):
        missing = os.path.join(tempfile.gettempdir(), "no-such-dir-for-tag-audit", "frozen.json")
        with mock.patch.object(release_checks, "audit_tags", return_value=["the frozen tag list is unreadable"]):
            problems = ta.run_check(self.two_tags(), github(good_rulesets()), missing, None, baseline_expected=True)
        self.assertEqual(problems, ["tag ledger: the frozen tag list is unreadable"])

    def test_a_clean_audit_is_green(self):
        git = FakeGit(chain=["c1"], tags=[fleet_tag(1, "c1")])
        with mock.patch.object(release_checks, "audit_tags", return_value=[]):
            problems = ta.run_check(git, github(good_rulesets()), ".github/fleet-tags.frozen.json", None)
        self.assertEqual(problems, [])
        self.assertFalse(ta.as_result(problems).red)


class TestMain(unittest.TestCase):
    """main(): which invocations ask for a baseline. tag-release passes no --previous, and must never be
    refused for a tag that only a snapshot (not the frozen list) records."""

    def run_main(self, argv, rows):
        git = FakeGit(chain=[COMMIT], tags=[fleet_tag(1, COMMIT), fleet_tag(2, COMMIT)])
        frozen = frozen_file(self, rows)
        env = {"GITHUB_REPOSITORY": REPO, "GH_TOKEN": "t"}
        out = io.StringIO()
        with mock.patch.dict(os.environ, env), mock.patch.object(ta, "Git", return_value=git), \
                mock.patch.object(ta, "GitHub", return_value=github(good_rulesets())), \
                mock.patch.object(release_checks, "audit_tags", return_value=[]), \
                mock.patch("sys.stdout", out):
            code = ta.main(["check", "--repo-dir", "/fake/marketplace", "--frozen", frozen, *argv])
        return code, out.getvalue()

    ONLY_V1 = [{"tag": "fleet-v1", "object": fleet_tag(1, COMMIT)["object"], "commit": COMMIT}]

    def test_tag_releases_invocation_never_asks_for_a_baseline(self):
        code, out = self.run_main([], self.ONLY_V1)
        self.assertEqual((code, out), (0, ""))

    def test_a_missing_snapshot_file_asks_for_a_complete_frozen_list(self):
        absent = os.path.join(tempfile.gettempdir(), "no-such-dir-for-tag-audit", "previous.json")
        code, out = self.run_main(["--previous", absent], self.ONLY_V1)
        self.assertEqual(code, 1)
        self.assertIn("::notice::no snapshot from an earlier green tag-audit run", out)
        self.assertIn("::error::no snapshot from an earlier green run to compare against, and the frozen list does "
                      "not record fleet-v2", out)

    def test_a_missing_snapshot_file_with_a_complete_frozen_list_is_green(self):
        absent = os.path.join(tempfile.gettempdir(), "no-such-dir-for-tag-audit", "previous.json")
        rows = self.ONLY_V1 + [{"tag": "fleet-v2", "object": fleet_tag(2, COMMIT)["object"], "commit": COMMIT}]
        code, out = self.run_main(["--previous", absent], rows)
        self.assertEqual(code, 0)
        self.assertNotIn("::error::", out)

    def test_a_snapshot_that_exists_is_compared_not_replaced_by_the_coverage_rule(self):
        # fleet-v2 is not in the frozen list, but the snapshot knows it unchanged: the comparison is enough.
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        previous = os.path.join(root.name, "previous.json")
        with open(previous, "w", encoding="utf-8") as handle:
            json.dump([{"tag": "fleet-v2", "object": fleet_tag(2, COMMIT)["object"], "commit": COMMIT}], handle)
        code, out = self.run_main(["--previous", previous], self.ONLY_V1)
        self.assertEqual((code, out), (0, ""))


if __name__ == "__main__":
    unittest.main()
