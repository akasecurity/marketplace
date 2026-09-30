"""Tests for tag_audit.py: the ruleset read, the previous-run comparison and the frozen list."""
import copy
import json
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
            "fleet-v1 moved since the last green run: tag object o1 -> o9, commit c1 -> c9",
            "fleet-v2 (tag object o2) existed at the last green run and is gone"])


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

    def test_a_clean_audit_is_green(self):
        git = FakeGit(chain=["c1"], tags=[fleet_tag(1, "c1")])
        with mock.patch.object(release_checks, "audit_tags", return_value=[]):
            problems = ta.run_check(git, github(good_rulesets()), ".github/fleet-tags.frozen.json", None)
        self.assertEqual(problems, [])
        self.assertFalse(ta.as_result(problems).red)


if __name__ == "__main__":
    unittest.main()
