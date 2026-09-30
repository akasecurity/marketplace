"""Tests for import_release.py (import-plugin-release.yml's logic)."""
from __future__ import annotations

import hashlib
import json
import types
import unittest
from unittest import mock

import _testsupport as ts
import import_release as ir
import release_checks
from fakes import (ATTESTED, INTEGRITY, REPO, FakeGit, FakeGitHub, contents, fleet_tag, manifest,
                   not_found, pull, pulls_route, safety, safety_entry)
from ghapi import GitHubError
from release_checks import MANIFEST, SAFETY_FILE


def R(suffix: str) -> str:
    return f"repos/{REPO}/{suffix}"


def verified(version: str) -> types.SimpleNamespace:
    """What release_checks.verify_release returns, by attribute."""
    return types.SimpleNamespace(version=version, integrity=INTEGRITY[version],
                                 shasum=hashlib.sha1(version.encode()).hexdigest(),
                                 git_commit=ATTESTED[version],
                                 run_url=f"https://github.com/akasecurity/ai-tc/actions/runs/{version.replace('.', '')}/attempts/1")


def entry_json(version: str, integrity: str | None = None) -> dict:
    return ts.ai_tc(json.loads(manifest(version, integrity)))


def forward_plan(version: str = "0.9.15", current: str = "0.9.14", **extra) -> dict:
    fact = verified(version)
    plan = {"mode": "forward", "version": version, "from_version": current, "integrity": fact.integrity,
            "shasum": fact.shasum, "git_commit": fact.git_commit, "run_url": fact.run_url,
            "branch": f"bot/pin-ai-tc-{version}", "title": f"feat: advance the ai-tc pin to {version}",
            "labels": [], "classification": "additive", "migrations": ["0036_add_column"],
            "safety_entry": None, "refused": [], "highest_pinned": current, "floor": None, "crossed": [],
            "target_tag": None, "reimport": False, "below_floor": False, "base_sha": "d" * 40,
            "base_entry": entry_json(current, INTEGRITY[current])}
    plan.update(extra)
    return plan


def rollback_plan(version: str = "0.9.13", current: str = "0.9.14", **extra) -> dict:
    plan = forward_plan(version, current, mode="rollback", branch=f"bot/rollback-ai-tc-{current}-to-{version}",
                        title=f"fix: roll the ai-tc pin back from {current} to {version}", labels=["rollback"],
                        classification="not-rollback-safe", migrations=[], highest_pinned=current,
                        crossed=[current], target_tag="fleet-v7")
    plan.update(extra)
    return plan


class TestEditPin(unittest.TestCase):
    def test_forward_changes_only_the_version_and_the_integrity(self):
        raw = manifest("0.9.14", INTEGRITY["0.9.14"])
        new = ir.edit_pin(raw, forward_plan())
        before, after = json.loads(raw), json.loads(new)
        entry = ts.ai_tc(after)
        self.assertEqual(entry["source"]["version"], "0.9.15")
        self.assertEqual(entry["metadata"], {"integrity": INTEGRITY["0.9.15"]})
        entry["source"]["version"] = "0.9.14"
        entry["metadata"]["integrity"] = INTEGRITY["0.9.14"]
        self.assertEqual(after, before)
        self.assertEqual(new, release_checks.dump_json(json.loads(new)))

    def test_metadata_is_added_after_the_description_when_absent(self):
        new = ir.edit_pin(manifest("0.9.14"), forward_plan())
        self.assertEqual(list(ts.ai_tc(json.loads(new))), ["name", "source", "description", "metadata"])

    def test_a_manifest_that_does_not_round_trip_is_refused(self):
        compact = json.dumps(json.loads(manifest("0.9.14")))
        with self.assertRaisesRegex(ir.Refused, "round-trip"):
            ir.edit_pin(compact, forward_plan())

    def test_forward_must_move_up_and_rollback_down(self):
        with self.assertRaisesRegex(ir.Refused, "must move up"):
            ir.edit_pin(manifest("0.9.15"), forward_plan("0.9.15", "0.9.14"))
        with self.assertRaisesRegex(ir.Refused, "must move down"):
            ir.edit_pin(manifest("0.9.13"), rollback_plan("0.9.14", "0.9.13"))

    def test_rollback_moves_the_version_down_and_rewrites_the_integrity(self):
        new = ts.ai_tc(json.loads(ir.edit_pin(manifest("0.9.14", INTEGRITY["0.9.14"]), rollback_plan())))
        self.assertEqual(new["source"]["version"], "0.9.13")
        self.assertEqual(new["metadata"]["integrity"], INTEGRITY["0.9.13"])

    def test_a_manifest_without_the_entry_is_refused(self):
        with self.assertRaisesRegex(ir.Refused, "no ai-tc entry"):
            ir.edit_pin(manifest(entry=False), forward_plan())


class TestSafetyEntry(unittest.TestCase):
    def test_a_new_version_is_appended_and_the_file_round_trips(self):
        raw = safety({"0.9.14": safety_entry("0.9.14", "0.9.13")})
        new_entry = safety_entry("0.9.15", "0.9.14", "additive", ())
        out = ir.add_safety_entry(raw, "0.9.15", new_entry)
        self.assertEqual(list(json.loads(out)["versions"]), ["0.9.14", "0.9.15"])
        self.assertEqual(json.loads(out)["versions"]["0.9.15"], new_entry)
        self.assertEqual(out, release_checks.dump_json(json.loads(out)))

    def test_an_existing_version_leaves_the_file_alone(self):
        raw = safety({"0.9.15": safety_entry("0.9.15", "0.9.14")})
        self.assertIsNone(ir.add_safety_entry(raw, "0.9.15", safety_entry("0.9.15", "0.9.14", "additive")))

    def test_a_file_that_does_not_round_trip_is_refused(self):
        with self.assertRaisesRegex(ir.Refused, "round-trip"):
            ir.add_safety_entry('{"versions": {}}', "0.9.15", {})


class TestLedgerReads(unittest.TestCase):
    def test_tag_pins_reads_each_tag_and_skips_an_unpinned_one(self):
        repo = ts.Repo(self)  # a real repository: tag_pins is release_checks.pins_by_ref without main
        unpinned = ts.manifest()
        del ts.ai_tc(unpinned)["source"]["version"]
        repo.commit(unpinned)
        repo.tag("fleet-v1")
        repo.commit(ts.manifest("0.9.13"))
        repo.tag("fleet-v7")
        repo.commit(ts.manifest("0.9.14"))
        self.assertEqual(ir.tag_pins(repo.path), {"fleet-v1": None, "fleet-v7": "0.9.13"})

    def test_no_entry_is_none_and_an_ambiguous_manifest_is_refused(self):
        self.assertIsNone(ir.entry_of(json.loads(manifest(entry=False))))
        doc = json.loads(manifest("0.9.14"))
        doc["plugins"].append(dict(ts.ai_tc(doc)))
        with self.assertRaisesRegex(ir.Refused, "ambiguous"):
            ir.entry_of(doc)

    def test_list_pulls_keeps_same_repository_heads_only(self):
        pulls = [pull(3, "bot/pin-ai-tc-0.9.15"), pull(4, "bot/pin-ai-tc-0.9.16", repo="someone/fork"),
                 pull(5, "bot/pin-ai-tc-0.9.13", state="closed")]
        gh = FakeGitHub({("GET", R("pulls")): pulls_route(pulls)})
        listed = ir.list_pulls(gh, "open")
        self.assertEqual([p["number"] for p in listed], [3])
        self.assertEqual(listed[0]["head"], "bot/pin-ai-tc-0.9.15")
        self.assertEqual(gh.calls[0][3], {"state": "open", "base": "main"})


class TestCheckPlan(unittest.TestCase):
    def test_a_well_formed_plan_passes(self):
        ir.check_plan(forward_plan())
        ir.check_plan(rollback_plan())

    def test_malformed_fields_are_refused(self):
        for bad in (dict(integrity="sha512-short"), dict(git_commit="xyz"), dict(version="0.9.15-rc1"),
                    dict(branch="bot/pin-ai-tc-0.9.99"), dict(mode="sideways"), dict(labels=["release"])):
            plan = forward_plan()
            plan.update(bad)
            with self.subTest(bad=bad), self.assertRaises(ir.Refused):
                ir.check_plan(plan)


class TestPrBody(unittest.TestCase):
    def test_a_forward_body_carries_the_verified_facts_and_the_checklist(self):
        plan = forward_plan(safety_entry=safety_entry("0.9.15", "0.9.14", "additive", ("0036_add_column",)))
        body = ir.pr_body(plan, "https://github.com/akasecurity/marketplace/actions/runs/7")
        for text in ("`0.9.14` → `0.9.15`", INTEGRITY["0.9.15"], ATTESTED["0.9.15"], "on ai-tc main: yes",
                     plan["run_url"], "refs/tags/plugin-claude-v0.9.15", "`additive`", "`0036_add_column`",
                     "This PR also adds that entry to `rollback-safety.json`.",
                     "claude plugin marketplace add akasecurity/marketplace#bot/pin-ai-tc-0.9.15",
                     "event `pull_request_target`", "hook fail-open smoke tests",
                     "https://github.com/akasecurity/marketplace/actions/runs/7"):
            self.assertIn(text, body)
        self.assertNotIn("git tag -s", body)

    def test_a_reimport_says_so(self):
        self.assertIn("**Re-import**", ir.pr_body(forward_plan(reimport=True), "u"))

    def test_a_rollback_body_states_the_floor_and_a_below_floor_dispatch(self):
        body = ir.pr_body(rollback_plan(floor="0.9.14", below_floor=True), "u")
        self.assertIn("**Rollback.**", body)
        self.assertIn("(the version `fleet-v7` pins)", body)
        self.assertIn("`0.9.14` is flagged not-rollback-safe", body)
        self.assertIn("`validate` fails this PR", body)
        self.assertIn("claude plugin marketplace add akasecurity/marketplace#bot/rollback-ai-tc-0.9.14-to-0.9.13", body)


PLAN_KEYS = {"mode", "version", "from_version", "integrity", "shasum", "git_commit", "run_url", "branch", "title",
             "labels", "classification", "migrations", "safety_entry", "refused", "highest_pinned", "floor",
             "crossed", "target_tag", "reimport", "below_floor", "base_sha", "base_entry"}
TAGS = [fleet_tag(6, "c6"), fleet_tag(7, "c7"), fleet_tag(8, "c8")]


def repo(main_version: str | None = "0.9.14", entries: dict | None = None) -> FakeGit:
    """main ("m") after fleet-v6/7/8 (0.9.12, 0.9.13, 0.9.14), with main's rollback-safety.json."""
    if entries is None:
        entries = {"0.9.13": safety_entry("0.9.13", "0.9.12", "additive", ()), "0.9.14": safety_entry("0.9.14", "0.9.13")}
    files = {("c6", MANIFEST): manifest("0.9.12"), ("c7", MANIFEST): manifest("0.9.13"),
             ("c8", MANIFEST): manifest("0.9.14"),
             ("m", MANIFEST): manifest(main_version, INTEGRITY.get(main_version), entry=main_version is not None),
             ("m", SAFETY_FILE): safety(entries)}
    return FakeGit(chain=["c6", "c7", "c8", "m"], files=files, tags=TAGS)


class PlanCase(unittest.TestCase):
    def setUp(self):
        self.pinned = {"0.9.12", "0.9.13", "0.9.14"}
        # What release_checks.pins_by_ref reads from main and the tags in repo() (fleet-v6/7/8).
        self.pins = {"main": "0.9.14", "fleet-v6": "0.9.12", "fleet-v7": "0.9.13", "fleet-v8": "0.9.14"}
        self.candidates: list[str] = []
        self.bad: dict[str, tuple[str, str]] = {}
        self.floor = None
        self.pulls: list[dict] = []
        self.gh = FakeGitHub({("GET", R("pulls")): pulls_route(self.pulls)})
        classification = types.SimpleNamespace(classification="additive", migrations=["0036_add_column"])
        stubs = {"pinned_versions": lambda repo_dir: set(self.pinned),
                 "pins_by_ref": lambda repo_dir: dict(self.pins),
                 "npm_candidates": lambda pinned: list(self.candidates),
                 "verify_release": self.fake_verify,
                 "classify_migrations": lambda start, end: classification,
                 "rollback_floor": lambda table, target, highest, pinned=(): self.floor}
        self.stubs = {}
        for name, function in stubs.items():
            patcher = mock.patch.object(release_checks, name, side_effect=function)
            self.stubs[name] = patcher.start()
            self.addCleanup(patcher.stop)

    def fake_verify(self, version):
        if version in self.bad:
            raise release_checks.ReleaseCheckError(*self.bad[version])
        return verified(version)

    def plan(self, git=None, **inputs):
        args = dict(repo_dir="/fake/marketplace", mode="forward", target="", reimport=False, below_floor=False,
                    event="schedule", run_id="42")
        args.update(inputs)
        return ir.make_plan(git or repo(), self.gh, **args)


class TestPlanForward(PlanCase):
    def test_the_schedule_takes_the_highest_candidate_that_passes(self):
        self.candidates = ["0.9.15", "0.9.16"]
        self.bad = {"0.9.16": ("provenance", "ref refs/heads/release is not the version's tag")}
        plan = self.plan()
        self.assertEqual((plan["mode"], plan["version"], plan["from_version"]), ("forward", "0.9.15", "0.9.14"))
        self.assertEqual((plan["branch"], plan["title"]), ("bot/pin-ai-tc-0.9.15", "feat: advance the ai-tc pin to 0.9.15"))
        self.assertEqual(plan["integrity"], INTEGRITY["0.9.15"])
        self.assertEqual(plan["refused"], [{"version": "0.9.16", "reason": "provenance: ref refs/heads/release is not the version's tag"}])
        self.assertEqual(plan["safety_entry"], {"classification": "additive", "from": ATTESTED["0.9.14"],
                                                "to": ATTESTED["0.9.15"], "migrations": ["0036_add_column"]})
        self.stubs["classify_migrations"].assert_called_once_with(ATTESTED["0.9.14"], ATTESTED["0.9.15"])
        self.assertEqual((plan["base_sha"], plan["base_entry"]), ("m", entry_json("0.9.14", INTEGRITY["0.9.14"])))
        self.assertEqual(set(plan), PLAN_KEYS)
        ir.check_plan(plan)

    def test_nothing_new_on_npm_is_a_green_skip(self):
        with self.assertRaisesRegex(ir.Refused, "no exact release above 0.9.14") as caught:
            self.plan()
        self.assertFalse(caught.exception.red)

    def test_every_candidate_refused_is_a_green_skip_that_names_them(self):
        self.candidates = ["0.9.15"]
        self.bad = {"0.9.15": ("commit-on-main", "behind")}
        with self.assertRaisesRegex(ir.Refused, r"refused: 0\.9\.15") as caught:
            self.plan()
        self.assertFalse(caught.exception.red)

    def test_the_schedule_opens_nothing_while_a_rollback_pr_is_open(self):
        self.pulls.append(pull(5, "bot/rollback-ai-tc-0.9.14-to-0.9.13"))
        self.candidates = ["0.9.15"]
        with self.assertRaisesRegex(ir.Refused, "rollback PR #5 is open") as caught:
            self.plan()
        self.assertFalse(caught.exception.red)
        self.stubs["npm_candidates"].assert_not_called()

    def test_an_open_pr_for_the_version_is_a_green_skip(self):
        self.pulls.append(pull(6, "bot/pin-ai-tc-0.9.15"))
        self.candidates = ["0.9.15"]
        with self.assertRaisesRegex(ir.Refused, "PR #6 for 0.9.15 is already open") as caught:
            self.plan()
        self.assertFalse(caught.exception.red)

    def test_a_rejected_version_stays_rejected_until_reimport(self):
        self.pulls.append(pull(7, "bot/pin-ai-tc-0.9.15", state="closed"))
        self.candidates = ["0.9.15"]
        with self.assertRaisesRegex(ir.Refused, "closed unmerged") as scheduled:
            self.plan()
        self.assertFalse(scheduled.exception.red)
        with self.assertRaisesRegex(ir.Refused, "closed unmerged") as dispatched:
            self.plan(event="workflow_dispatch", target="0.9.15")
        self.assertTrue(dispatched.exception.red)
        plan = self.plan(event="workflow_dispatch", target="0.9.15", reimport=True)
        self.assertEqual((plan["version"], plan["reimport"]), ("0.9.15", True))

    def test_a_version_a_rollback_moved_away_from_needs_reimport(self):
        self.pinned = {"0.9.13", "0.9.14", "0.9.15"}  # a fleet-v tag pinned 0.9.15; main was rolled back to 0.9.14
        entries = {"0.9.14": safety_entry("0.9.14", "0.9.13"),
                   "0.9.15": safety_entry("0.9.15", "0.9.14", "additive", ("0036_add_column",))}
        with self.assertRaisesRegex(ir.Refused, "reimport: true") as caught:
            self.plan(repo(entries=entries), event="workflow_dispatch", target="0.9.15")
        self.assertTrue(caught.exception.red)
        plan = self.plan(repo(entries=entries), event="workflow_dispatch", target="0.9.15", reimport=True)
        self.assertIsNone(plan["safety_entry"])
        self.assertEqual((plan["classification"], plan["migrations"]), ("additive", ["0036_add_column"]))
        self.stubs["classify_migrations"].assert_not_called()
        # A fix-forward after that rollback: its entry is computed from 0.9.15, the highest version
        # pinned below it, exactly as validate recomputes it, not from main's 0.9.14.
        self.candidates = ["0.9.16"]
        plan = self.plan(repo(entries=entries))
        self.assertEqual(plan["safety_entry"]["from"], ATTESTED["0.9.15"])
        self.stubs["classify_migrations"].assert_called_once_with(ATTESTED["0.9.15"], ATTESTED["0.9.16"])

    def test_a_dispatched_target_that_fails_verification_is_red(self):
        self.bad = {"0.9.15": ("commit-on-main", "behind")}
        with self.assertRaisesRegex(ir.Refused, "0.9.15 fails the release checks: commit-on-main: behind") as caught:
            self.plan(event="workflow_dispatch", target="0.9.15")
        self.assertTrue(caught.exception.red)

    def test_a_forward_target_must_be_above_the_pin_and_reimport_needs_a_target(self):
        with self.assertRaisesRegex(ir.Refused, "rollback-mode dispatch"):
            self.plan(event="workflow_dispatch", target="0.9.13")
        with self.assertRaisesRegex(ir.Refused, "needs an explicit target"):
            self.plan(event="workflow_dispatch", reimport=True)

    def test_no_entry_on_main_skips_the_schedule(self):
        with self.assertRaisesRegex(ir.Refused, "no ai-tc entry") as caught:
            self.plan(repo(main_version=None, entries={}))
        self.assertFalse(caught.exception.red)


class TestPlanRollback(PlanCase):
    def test_a_tag_name_resolves_to_its_version(self):
        plan = self.plan(mode="rollback", target="fleet-v7", event="workflow_dispatch")
        self.assertEqual((plan["mode"], plan["version"], plan["from_version"]), ("rollback", "0.9.13", "0.9.14"))
        self.assertEqual(plan["branch"], "bot/rollback-ai-tc-0.9.14-to-0.9.13")
        self.assertEqual(plan["title"], "fix: roll the ai-tc pin back from 0.9.14 to 0.9.13")
        self.assertEqual(plan["labels"], ["rollback"])
        self.assertEqual((plan["target_tag"], plan["crossed"], plan["classification"]),
                         ("fleet-v7", ["0.9.14"], "not-rollback-safe"))
        self.assertIsNone(plan["floor"])
        self.assertEqual(self.stubs["rollback_floor"].call_args.args[1:], ("0.9.13", "0.9.14"))
        self.assertEqual(set(plan), PLAN_KEYS)
        ir.check_plan(plan)

    def test_below_the_floor_is_refused_unless_below_floor_is_set(self):
        self.floor = "0.9.14"
        with self.assertRaisesRegex(ir.Refused, "below the rollback floor") as caught:
            self.plan(mode="rollback", target="0.9.13", event="workflow_dispatch")
        self.assertTrue(caught.exception.red)
        plan = self.plan(mode="rollback", target="0.9.13", event="workflow_dispatch", below_floor=True)
        self.assertEqual((plan["floor"], plan["below_floor"]), ("0.9.14", True))

    def test_the_target_must_be_tag_pinned_and_below_main(self):
        for target, message in (("0.9.11", "not a version any fleet-v tag has pinned"),
                                ("0.9.14", "not below main's pin"),
                                ("fleet-v9", "there is no tag fleet-v9"),
                                ("latest", "neither an exact x.y.z nor fleet-v<N>"),
                                ("", "needs a target")):
            with self.subTest(target=target), self.assertRaisesRegex(ir.Refused, message):
                self.plan(mode="rollback", target=target, event="workflow_dispatch")

    def test_an_open_rollback_pr_for_the_same_move_is_a_green_skip(self):
        self.pulls.append(pull(9, "bot/rollback-ai-tc-0.9.14-to-0.9.13"))
        with self.assertRaisesRegex(ir.Refused, "#9") as caught:
            self.plan(mode="rollback", target="fleet-v7", event="workflow_dispatch")
        self.assertFalse(caught.exception.red)


class TestModes(PlanCase):
    def test_remove_and_restore_are_not_built(self):
        for mode in ("remove", "restore"):
            with self.subTest(mode=mode), self.assertRaisesRegex(ir.Refused, "not available") as caught:
                self.plan(mode=mode, event="workflow_dispatch")
            self.assertTrue(caught.exception.red)


if __name__ == "__main__":
    unittest.main()
