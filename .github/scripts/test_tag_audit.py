"""Tests for tag_audit.py: the ruleset and environment reads, the previous-run comparison and the frozen list."""
import copy
import io
import json
import os
import re
import tempfile
import unittest
from unittest import mock

import release_checks
import tag_audit as ta
from fakes import REPO, FakeGit, FakeGitHub, fleet_tag, not_found
from ghapi import GitHubError

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


def good_environment():
    return {"name": "marketplace-bot", "deployment_branch_policy": {"protected_branches": False,
                                                                     "custom_branch_policies": True}}


def good_branch_rules():
    return {"total_count": 1, "branch_policies": [{"id": 7, "node_id": "x", "name": "main", "type": "branch"}]}


def github(rulesets, *, environment=None, rules=None):
    """A GitHub whose rulesets are `rulesets` and whose release bot environment is the specified one, unless
    `environment` (its document, or the error its read raises) or `rules` (its deployment branch rules) say
    otherwise."""
    routes = {("GET", R("rulesets")): [{"id": number, "name": body["name"]} for number, body in rulesets.items()],
              ("GET", R("environments/marketplace-bot")): good_environment() if environment is None else environment,
              ("GET", R("environments/marketplace-bot/deployment-branch-policies")):
                  good_branch_rules() if rules is None else rules}
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


class TestEnvironment(unittest.TestCase):
    """The `marketplace-bot` environment holds the release bot's key and must admit deployments from main alone."""

    def problems(self, **kwargs):
        return ta.check_environment(github(good_rulesets(), **kwargs))

    def test_the_specified_environment_passes(self):
        gh = github(good_rulesets())
        self.assertEqual(ta.check_environment(gh), [])
        # Both documents are read, and nothing is written.
        self.assertEqual([call[1] for call in gh.calls if "environments" in call[1]],
                         [R("environments/marketplace-bot"), R("environments/marketplace-bot/deployment-branch-policies")])
        self.assertEqual(gh.writes(), [])

    def test_it_audits_the_environment_the_importer_enters(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "workflows", "import-plugin-release.yml")
        with open(path, encoding="utf-8") as handle:
            entered = re.findall(r"(?m)^    environment: (\S+)$", handle.read())
        self.assertEqual(entered, [ta.ENVIRONMENT])

    def test_an_environment_that_does_not_exist_is_a_problem_and_nothing_more_is_read(self):
        gh = github(good_rulesets(), environment=not_found("environments/marketplace-bot"))
        self.assertEqual(ta.check_environment(gh), ["the marketplace-bot environment does not exist"])
        self.assertEqual(len([call for call in gh.calls if "environments" in call[1]]), 1)

    def test_a_read_that_fails_otherwise_is_an_error_not_a_problem(self):
        # A token that cannot read the environment must fail the run, not report a drift that did not happen.
        for status in (401, 403, 500):
            with self.subTest(status):
                failure = GitHubError(status, "GET", "environments/marketplace-bot", "{}")
                with self.assertRaises(GitHubError):
                    self.problems(environment=failure)
        with self.assertRaises(GitHubError):
            self.problems(rules=GitHubError(403, "GET", "environments/marketplace-bot/deployment-branch-policies", "{}"))

    def test_deployment_branches_other_than_a_custom_list_are_a_problem(self):
        cases = {
            "any branch": None,
            "protected branches": {"protected_branches": True, "custom_branch_policies": False},
            "both": {"protected_branches": True, "custom_branch_policies": True},
            "neither": {"protected_branches": False, "custom_branch_policies": False},
        }
        for label, policy in cases.items():
            with self.subTest(label):
                gh = github(good_rulesets(), environment={"name": "marketplace-bot", "deployment_branch_policy": policy})
                problems = ta.check_environment(gh)
                self.assertEqual(len(problems), 1, problems)
                self.assertTrue(problems[0].startswith("the marketplace-bot environment's deployment_branch_policy is "))
                # GitHub answers 404 for the rule list of an environment with no custom rules: it is not read.
                self.assertEqual(len([call for call in gh.calls if "deployment-branch-policies" in call[1]]), 0)

    def test_anything_but_the_one_branch_rule_for_main_is_a_problem(self):
        def rules(*entries):
            return {"total_count": len(entries), "branch_policies": [dict(id=n, name=name, type=kind)
                                                                      for n, (name, kind) in enumerate(entries)]}

        cases = {
            "no rule": rules(),
            "a second branch": rules(("main", "branch"), ("release", "branch")),
            "a pattern": rules(("*", "branch")),
            "another branch": rules(("release", "branch")),
            "a tag rule": rules(("main", "branch"), ("v*", "tag")),
            "main as a tag": rules(("main", "tag")),
            "a count that disagrees": dict(rules(("main", "branch")), total_count=2),
        }
        for label, listed in cases.items():
            with self.subTest(label):
                problems = self.problems(rules=listed)
                self.assertEqual(len(problems), 1, problems)
                self.assertTrue(problems[0].startswith("the marketplace-bot environment's deployment branch rules are "))

    def test_the_rules_may_be_listed_in_any_order_with_the_extra_fields_github_adds(self):
        self.assertEqual(self.problems(rules={"total_count": 1, "branch_policies": [
            {"id": 3, "node_id": "n", "name": "main", "type": "branch"}]}), [])

    def test_a_run_check_reports_the_environment_with_the_other_problems(self):
        git = FakeGit(chain=["c1"], tags=[fleet_tag(1, "c1")])
        gh = github(good_rulesets(), environment=not_found())
        with mock.patch.object(release_checks, "audit_tags", return_value=["fleet-v9 names PR 13, not a bot PR"]):
            problems = ta.run_check(git, gh, ".github/fleet-tags.frozen.json", None)
        self.assertEqual(problems, ["tag ledger: fleet-v9 names PR 13, not a bot PR",
                                    "the marketplace-bot environment does not exist"])

    def test_a_caller_that_asks_for_no_baseline_is_still_held_to_the_environment(self):
        # tag-release asks for no comparison, and runs in this environment.
        git = FakeGit(chain=["c1"], tags=[fleet_tag(1, "c1")])
        gh = github(good_rulesets(), rules={"total_count": 0, "branch_policies": []})
        with mock.patch.object(release_checks, "audit_tags", return_value=[]):
            problems = ta.run_check(git, gh, ".github/fleet-tags.frozen.json", None)
        self.assertEqual(len(problems), 1)
        self.assertIn("deployment branch rules", problems[0])


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


class TestCommittedFrozenList(unittest.TestCase):
    """The list this repository commits, read the way the audit reads it."""

    def test_it_records_every_tag_cut_by_hand(self):
        # fleet-v1 to fleet-v9 were cut by hand, so they carry no `version:` or `pr:` line, and the audit
        # judges a tag outside this list by those lines: a hand-cut tag missing here is three problems.
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fleet-tags.frozen.json")
        problems = []
        rows = release_checks._tag_rows(path, "frozen tag list", problems)
        self.assertEqual(problems, [])
        names = [row["tag"] for row in rows]
        self.assertEqual(names, [f"fleet-v{n}" for n in range(1, len(names) + 1)])
        self.assertGreaterEqual(len(names), 9)


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
