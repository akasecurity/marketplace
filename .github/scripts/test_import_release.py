"""Tests for import_release.py (import-plugin-release.yml's logic)."""
from __future__ import annotations

import hashlib
import io
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
        self.down: dict[str, tuple[str, str]] = {}
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
        if version in self.down:
            raise release_checks.InfraError(*self.down[version])
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

    def test_an_outage_on_the_highest_candidate_never_falls_back(self):
        # 0.9.16 could not be checked and 0.9.15 passes: a pin for 0.9.15 must not be opened while a
        # higher release has no verdict, because the outage may be hiding the real newest release.
        self.candidates = ["0.9.15", "0.9.16"]
        self.down = {"0.9.16": ("network", "down")}
        for event in ("schedule", "workflow_dispatch"):
            with self.subTest(event=event):
                self.stubs["verify_release"].reset_mock()
                with self.assertRaisesRegex(ir.Refused, "no verdict on 0.9.16: network: down") as caught:
                    self.plan(event=event)
                self.assertTrue(caught.exception.red)
                self.assertIn("does not fall back to a lower one", str(caught.exception))
                self.stubs["verify_release"].assert_called_once_with("0.9.16")

    def test_an_outage_on_every_candidate_is_red_not_a_green_skip(self):
        self.candidates = ["0.9.15"]
        self.down = {"0.9.15": ("toolchain", "npm did not finish")}
        for event in ("schedule", "workflow_dispatch"):
            with self.subTest(event=event):
                with self.assertRaisesRegex(ir.Refused, "no verdict on 0.9.15") as caught:
                    self.plan(event=event)
                self.assertTrue(caught.exception.red)

    def test_a_verdict_above_an_outage_is_skipped_and_the_outage_stops_the_walk(self):
        self.candidates = ["0.9.15", "0.9.16", "0.9.17"]
        self.bad = {"0.9.17": ("provenance", "ref refs/heads/release is not the version's tag")}
        self.down = {"0.9.16": ("network", "down")}
        with self.assertRaisesRegex(ir.Refused, "no verdict on 0.9.16") as caught:
            self.plan()
        self.assertTrue(caught.exception.red)
        self.assertEqual([call.args[0] for call in self.stubs["verify_release"].call_args_list], ["0.9.17", "0.9.16"])

    def test_a_dispatch_naming_a_lower_target_steps_over_a_version_with_no_verdict(self):
        # What the workflow header promises while a version cannot be verified: a target below it, still
        # above every pin, reads no candidate list and so never meets the outage.
        self.candidates = ["0.9.15", "0.9.16"]
        self.down = {"0.9.16": ("toolchain", "install failed")}
        plan = self.plan(event="workflow_dispatch", target="0.9.15")
        self.assertEqual((plan["mode"], plan["version"], plan["from_version"]), ("forward", "0.9.15", "0.9.14"))
        self.stubs["npm_candidates"].assert_not_called()
        self.assertEqual([call.args[0] for call in self.stubs["verify_release"].call_args_list], ["0.9.15", "0.9.14"])

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

    def test_a_dispatched_target_with_no_verdict_is_red_and_says_so(self):
        self.down = {"0.9.15": ("network", "down")}
        with self.assertRaisesRegex(ir.Refused, "no verdict on 0.9.15: network: down") as caught:
            self.plan(event="workflow_dispatch", target="0.9.15")
        self.assertTrue(caught.exception.red)
        # It is not worded as a failed verification, and it says what to do about it.
        self.assertNotIn("fails the release checks", str(caught.exception))
        self.assertIn("not a verdict on the release", str(caught.exception))
        self.assertIn("retries", str(caught.exception))

    def assert_no_verdict_computing_the_safety_entry(self):
        self.candidates = ["0.9.15"]
        with self.assertRaisesRegex(ir.Refused, "no verdict computing 0.9.15's rollback-safety.json entry: ") as caught:
            self.plan()
        self.assertTrue(caught.exception.red)
        self.assertNotIn("could not compute", str(caught.exception))

    def test_an_outage_in_the_migration_classifier_is_no_verdict(self):
        self.stubs["classify_migrations"].side_effect = release_checks.InfraError("classify", "GET contents answered 502")
        self.assert_no_verdict_computing_the_safety_entry()

    def test_an_outage_verifying_the_version_below_is_no_verdict(self):
        # safety_entry verifies the highest pinned version below the candidate to find where to start from.
        self.down = {"0.9.14": ("network", "down")}
        self.assert_no_verdict_computing_the_safety_entry()

    def test_a_verdict_computing_the_safety_entry_still_says_could_not_compute(self):
        self.candidates = ["0.9.15"]
        self.bad = {"0.9.14": ("provenance", "ref refs/heads/release is not the version's tag")}
        with self.assertRaisesRegex(ir.Refused, "could not compute 0.9.15's rollback-safety.json entry: provenance: ") as caught:
            self.plan()
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

    def test_a_rollback_target_with_no_verdict_is_red_and_says_so(self):
        self.down = {"0.9.13": ("network", "down")}
        with self.assertRaisesRegex(ir.Refused, "no verdict on 0.9.13: network: down") as caught:
            self.plan(mode="rollback", target="fleet-v7", event="workflow_dispatch")
        self.assertTrue(caught.exception.red)
        self.assertNotIn("fails the release checks", str(caught.exception))

    def test_a_rollback_target_that_fails_a_check_is_red(self):
        self.bad = {"0.9.13": ("commit-on-main", "behind")}
        with self.assertRaisesRegex(ir.Refused, "0.9.13 fails the release checks: commit-on-main: behind") as caught:
            self.plan(mode="rollback", target="fleet-v7", event="workflow_dispatch")
        self.assertTrue(caught.exception.red)


class TestModes(PlanCase):
    def test_remove_and_restore_are_not_built(self):
        for mode in ("remove", "restore"):
            with self.subTest(mode=mode), self.assertRaisesRegex(ir.Refused, "not available") as caught:
                self.plan(mode=mode, event="workflow_dispatch")
            self.assertTrue(caught.exception.red)


MAIN = "d" * 40
TREE = "e" * 40


class OpenPrCase(unittest.TestCase):
    def setUp(self):
        self.pulls: list[dict] = []
        self.main_manifest = manifest("0.9.14", INTEGRITY["0.9.14"])
        self.gh = FakeGitHub({
            ("GET", R("git/ref/heads/main")): {"object": {"sha": MAIN}},
            ("GET", R(f"contents/{MANIFEST}")): lambda body, params: contents(self.main_manifest),
            ("GET", R(f"contents/{SAFETY_FILE}")): contents(safety({"0.9.14": safety_entry("0.9.14", "0.9.13")})),
            ("GET", R("pulls")): pulls_route(self.pulls),
            ("GET", R(f"git/commits/{MAIN}")): {"tree": {"sha": TREE}},
            ("POST", R("git/trees")): {"sha": "f" * 40},
            # What GitHub answers an App's commit sent with no author or committer.
            ("POST", R("git/commits")): {"sha": "c" * 40, "committer": {"name": "GitHub", "email": "noreply@github.com"},
                                         "verification": {"verified": True, "reason": "valid"}},
            ("POST", R("git/refs")): {"ref": "created"},
            ("POST", R("pulls")): {"number": 12, "node_id": "PR_12"},
            ("POST", R("issues/12/comments")): {"id": 1},
            ("GRAPHQL", "enablePullRequestAutoMerge"): {"enablePullRequestAutoMerge": {"pullRequest": {"number": 12}}},
        })

    def route_branch(self, branch: str, exists: bool = False) -> None:
        self.gh.routes[("GET", R(f"git/ref/heads/{branch}"))] = {"ref": f"refs/heads/{branch}"} if exists else not_found()

    def open(self, plan: dict) -> str:
        return ir.open_pr(self.gh, plan, "https://github.com/akasecurity/marketplace/actions/runs/7")


class TestOpenPrForward(OpenPrCase):
    def test_writes_both_files_creates_the_branch_opens_the_pr_and_enables_auto_merge(self):
        self.route_branch("bot/pin-ai-tc-0.9.15")
        entry = safety_entry("0.9.15", "0.9.14", "additive", ("0036_add_column",))
        self.assertEqual(self.open(forward_plan(safety_entry=entry)), "opened #12 with auto-merge (squash); superseded []")
        tree = self.gh.called("POST", R("git/trees"))[0][2]
        self.assertEqual(tree["base_tree"], TREE)
        files = {item["path"]: item["content"] for item in tree["tree"]}
        self.assertEqual(ts.ai_tc(json.loads(files[MANIFEST]))["source"]["version"], "0.9.15")
        self.assertEqual(json.loads(files[SAFETY_FILE])["versions"]["0.9.15"], entry)
        self.assertTrue(all(item["mode"] == "100644" and item["type"] == "blob" for item in tree["tree"]))
        # No author or committer key: GitHub then commits as web-flow and signs, which validate accepts.
        self.assertEqual(self.gh.called("POST", R("git/commits"))[0][2],
                         {"message": "feat: advance the ai-tc pin to 0.9.15", "tree": "f" * 40, "parents": [MAIN]})
        self.assertEqual(self.gh.called("POST", R("git/refs"))[0][2],
                         {"ref": "refs/heads/bot/pin-ai-tc-0.9.15", "sha": "c" * 40})
        opened = self.gh.called("POST", R("pulls"))[0][2]
        self.assertEqual((opened["head"], opened["base"], opened["title"]),
                         ("bot/pin-ai-tc-0.9.15", "main", "feat: advance the ai-tc pin to 0.9.15"))
        self.assertIn("**Approver checklist:**", opened["body"])
        self.assertEqual(self.gh.called("GRAPHQL", "enablePullRequestAutoMerge")[0][2], {"id": "PR_12"})
        self.assertEqual(self.gh.called("POST", R("issues/12/labels")), [])

    def test_a_commit_github_committed_but_did_not_sign_gets_no_branch(self):
        self.route_branch("bot/pin-ai-tc-0.9.15")
        self.gh.routes[("POST", R("git/commits"))] = {
            "sha": "c" * 40, "committer": {"name": "GitHub", "email": "noreply@github.com"},
            "verification": {"verified": False, "reason": "unsigned"}}
        with self.assertRaisesRegex(ir.Refused, "without a verified signature, which validate refuses") as caught:
            self.open(forward_plan())
        self.assertTrue(caught.exception.red)
        self.assertEqual(self.gh.called("POST", R("git/refs")), [])
        self.assertEqual(self.gh.called("POST", R("pulls")), [])

    def test_supersedes_lower_forward_prs_only(self):
        self.route_branch("bot/pin-ai-tc-0.9.16")
        self.pulls += [pull(8, "bot/pin-ai-tc-0.9.15"), pull(9, "bot/pin-ai-tc-0.9.17")]
        self.gh.routes[("POST", R("issues/8/comments"))] = {"id": 2}
        self.gh.routes[("PATCH", R("pulls/8"))] = {"state": "closed"}
        self.assertTrue(self.open(forward_plan("0.9.16", "0.9.14")).endswith("superseded [8]"))
        self.assertIn("rollback-mode dispatch", self.gh.called("POST", R("issues/8/comments"))[0][2]["body"])
        self.assertEqual(self.gh.called("PATCH", R("pulls/8"))[0][2], {"state": "closed"})
        self.assertEqual(self.gh.called("PATCH", R("pulls/9")), [])

    def test_no_auto_merge_while_a_rollback_pr_is_open(self):
        self.route_branch("bot/pin-ai-tc-0.9.15")
        self.pulls.append(pull(5, "bot/rollback-ai-tc-0.9.14-to-0.9.13"))
        self.assertIn("without auto-merge (rollback PR #5 is open)", self.open(forward_plan()))
        self.assertEqual(self.gh.called("GRAPHQL", "enablePullRequestAutoMerge"), [])
        self.assertIn("rollback PR #5", self.gh.called("POST", R("issues/12/comments"))[0][2]["body"])
        self.assertEqual(self.gh.called("PATCH", R("pulls/5")), [])

    def test_an_existing_branch_with_an_open_pr_is_a_green_skip_with_no_writes(self):
        self.route_branch("bot/pin-ai-tc-0.9.15", exists=True)
        self.pulls.append(pull(6, "bot/pin-ai-tc-0.9.15"))
        with self.assertRaisesRegex(ir.Refused, "already open") as caught:
            self.open(forward_plan())
        self.assertFalse(caught.exception.red)
        self.assertEqual(self.gh.writes(), [])

    def test_an_existing_branch_without_a_pr_is_skipped_unless_reimport(self):
        self.route_branch("bot/pin-ai-tc-0.9.15", exists=True)
        with self.assertRaisesRegex(ir.Refused, "already exists") as caught:
            self.open(forward_plan())
        self.assertFalse(caught.exception.red)
        self.assertEqual(self.gh.writes(), [])
        self.gh.routes[("DELETE", R("git/refs/heads/bot/pin-ai-tc-0.9.15"))] = None
        self.open(forward_plan(reimport=True))
        order = [f"{call[0]} {call[1]}" for call in self.gh.writes()]
        self.assertLess(order.index(f"DELETE {R('git/refs/heads/bot/pin-ai-tc-0.9.15')}"), order.index(f"POST {R('git/refs')}"))

    def test_a_moved_entry_on_main_is_a_green_skip_with_no_writes(self):
        self.main_manifest = manifest("0.9.15", INTEGRITY["0.9.15"])
        with self.assertRaisesRegex(ir.Refused, "changed after the verify job") as caught:
            self.open(forward_plan("0.9.16", "0.9.14"))
        self.assertFalse(caught.exception.red)
        self.assertEqual(self.gh.writes(), [])

    def test_losing_the_race_for_the_branch_is_a_green_skip(self):
        answers = [not_found(), {"ref": "refs/heads/bot/pin-ai-tc-0.9.15"}]

        def branch(body, params):
            return answers.pop(0)

        self.gh.routes[("GET", R("git/ref/heads/bot/pin-ai-tc-0.9.15"))] = branch
        self.gh.routes[("POST", R("git/refs"))] = GitHubError(422, "POST", "git/refs", "Reference already exists")
        with self.assertRaisesRegex(ir.Refused, "created by another run first") as caught:
            self.open(forward_plan())
        self.assertFalse(caught.exception.red)
        self.assertEqual(self.gh.called("POST", R("pulls")), [])

    def test_a_rejected_ref_with_the_branch_still_absent_is_red_with_the_reason(self):
        self.route_branch("bot/pin-ai-tc-0.9.15")
        self.gh.routes[("POST", R("git/refs"))] = GitHubError(
            422, "POST", "git/refs", '{"message": "Repository rule violations found"}')
        with self.assertRaisesRegex(ir.Refused, "does not exist: .*Repository rule violations") as caught:
            self.open(forward_plan())
        self.assertTrue(caught.exception.red)
        self.assertEqual(self.gh.called("POST", R("pulls")), [])

    def test_a_failed_auto_merge_is_red_and_leaves_the_pr_open(self):
        self.route_branch("bot/pin-ai-tc-0.9.15")
        self.gh.routes[("GRAPHQL", "enablePullRequestAutoMerge")] = GitHubError(200, "POST", "graphql", "not allowed")
        with self.assertRaisesRegex(ir.Refused, "stays open for a person to merge") as caught:
            self.open(forward_plan())
        self.assertTrue(caught.exception.red)
        self.assertEqual(len(self.gh.called("POST", R("pulls"))), 1)
        self.assertEqual(self.gh.called("PATCH", R("pulls/12")), [])

    def test_a_malformed_plan_is_refused_before_any_call(self):
        with self.assertRaises(ir.Refused):
            self.open(forward_plan(integrity="sha512-short"))
        self.assertEqual(self.gh.calls, [])


class TestOpenPrRollback(OpenPrCase):
    def test_labels_enables_auto_merge_holds_forward_prs_and_closes_other_rollbacks(self):
        self.route_branch("bot/rollback-ai-tc-0.9.14-to-0.9.13")
        self.pulls += [pull(8, "bot/pin-ai-tc-0.9.15"), pull(9, "bot/rollback-ai-tc-0.9.14-to-0.9.12")]
        for number in (8, 9):
            self.gh.routes[("POST", R(f"issues/{number}/comments"))] = {"id": number}
        self.gh.routes[("POST", R("issues/12/labels"))] = [{"name": "rollback"}]
        self.gh.routes[("GRAPHQL", "disablePullRequestAutoMerge")] = {"disablePullRequestAutoMerge": {"pullRequest": {"number": 8}}}
        self.gh.routes[("PATCH", R("pulls/9"))] = {"state": "closed"}
        self.assertEqual(self.open(rollback_plan()),
                         "opened rollback #12 with auto-merge (squash); auto-merge off on [8]; closed [9]")
        self.assertEqual(self.gh.called("POST", R("issues/12/labels"))[0][2], {"labels": ["rollback"]})
        self.assertEqual(self.gh.called("GRAPHQL", "disablePullRequestAutoMerge")[0][2], {"id": "PR_8"})
        self.assertEqual([call[1] for call in self.gh.calls if call[0] == "GRAPHQL"],
                         ["disablePullRequestAutoMerge", "enablePullRequestAutoMerge"])
        self.assertIn("rollback PR #12", self.gh.called("POST", R("issues/8/comments"))[0][2]["body"])
        self.assertEqual(self.gh.called("PATCH", R("pulls/8")), [])
        self.assertEqual([item["path"] for item in self.gh.called("POST", R("git/trees"))[0][2]["tree"]], [MANIFEST])
        self.assertEqual(self.gh.called("POST", R("git/commits"))[0][2]["message"],
                         "fix: roll the ai-tc pin back from 0.9.14 to 0.9.13")

    def test_a_stale_rollback_branch_without_a_pr_is_replaced(self):
        self.route_branch("bot/rollback-ai-tc-0.9.14-to-0.9.13", exists=True)
        self.gh.routes[("DELETE", R("git/refs/heads/bot/rollback-ai-tc-0.9.14-to-0.9.13"))] = None
        self.gh.routes[("POST", R("issues/12/labels"))] = [{"name": "rollback"}]
        self.open(rollback_plan())
        self.assertEqual(len(self.gh.called("DELETE", R("git/refs/heads/bot/rollback-ai-tc-0.9.14-to-0.9.13"))), 1)

    def test_an_auto_merge_that_cannot_be_turned_off_is_red(self):
        self.route_branch("bot/rollback-ai-tc-0.9.14-to-0.9.13")
        self.pulls.append(pull(8, "bot/pin-ai-tc-0.9.15"))
        self.gh.routes[("POST", R("issues/12/labels"))] = [{"name": "rollback"}]
        self.gh.routes[("GRAPHQL", "disablePullRequestAutoMerge")] = GitHubError(200, "POST", "graphql", "forbidden")
        self.gh.routes[("GRAPHQL", "repository")] = {"repository": {"pullRequest": {"autoMergeRequest": {"enabledAt": "2026-09-29T00:00:00Z"}}}}
        with self.assertRaisesRegex(ir.Refused, "turn it off by hand") as caught:
            self.open(rollback_plan())
        self.assertTrue(caught.exception.red)


class TestMain(unittest.TestCase):
    def test_a_green_refusal_exits_zero_and_reports_no_proceed(self):
        env = {"GITHUB_REPOSITORY": REPO, "MODE": "forward", "EVENT_NAME": "schedule"}
        with mock.patch.dict(ir.os.environ, env, clear=True), \
                mock.patch.object(ir, "make_plan", side_effect=ir.Refused("nothing new", red=False)), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(ir.main(["plan"]), 0)
        self.assertIn("::notice::nothing new", out.getvalue())
        self.assertIn("proceed=false", out.getvalue())

    def test_a_red_refusal_exits_one(self):
        env = {"GITHUB_REPOSITORY": REPO, "PLAN_JSON": json.dumps(forward_plan(integrity="bad")),
               "GITHUB_SERVER_URL": "https://github.com", "GITHUB_RUN_ID": "7"}
        with mock.patch.dict(ir.os.environ, env, clear=True), mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(ir.main(["open-pr"]), 1)
        self.assertIn("::error::", out.getvalue())

    def test_a_check_error_outside_a_refusal_exits_one_with_no_proceed(self):
        env = {"GITHUB_REPOSITORY": REPO, "MODE": "forward", "EVENT_NAME": "schedule"}
        for error in (release_checks.InfraError("network", "down"),
                      release_checks.ReleaseCheckError("safety", "rollback-safety.json must be a versions table")):
            with self.subTest(error=type(error).__name__):
                with mock.patch.dict(ir.os.environ, env, clear=True), \
                        mock.patch.object(ir, "make_plan", side_effect=error), \
                        mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                    self.assertEqual(ir.main(["plan"]), 1)
                self.assertIn(f"::error::{error.check}: {error.detail}", out.getvalue())
                self.assertIn("proceed=false", out.getvalue())
                self.assertNotIn("proceed=true", out.getvalue())

    def test_the_open_pr_command_reports_a_check_error_the_same_way_without_a_proceed_output(self):
        env = {"GITHUB_REPOSITORY": REPO, "PLAN_JSON": json.dumps(forward_plan()),
               "GITHUB_SERVER_URL": "https://github.com", "GITHUB_RUN_ID": "7"}
        with mock.patch.dict(ir.os.environ, env, clear=True), \
                mock.patch.object(ir, "open_pr", side_effect=release_checks.InfraError("network", "down")), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(ir.main(["open-pr"]), 1)
        self.assertIn("::error::network: down", out.getvalue())
        self.assertNotIn("proceed=", out.getvalue())


class TestMainNet(PlanCase):
    """Calls into release_checks that a planner leaves unwrapped: an outage or a malformed file there
    ends the run as one annotation and `proceed=false`, so open-pr is skipped, not as a traceback."""

    def run_plan(self, **env: str) -> tuple[int, str]:
        variables = {"GITHUB_REPOSITORY": REPO, "MODE": "forward", "EVENT_NAME": "schedule", "TARGET": ""}
        variables.update(env)
        with mock.patch.dict(ir.os.environ, variables, clear=True), \
                mock.patch.object(ir, "Git", return_value=repo()), \
                mock.patch.object(ir, "GitHub", return_value=self.gh), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            code = ir.main(["plan"])
        return code, out.getvalue()

    def assert_stopped(self, code: int, output: str, annotation: str) -> None:
        self.assertEqual(code, 1)
        self.assertIn(f"::error::{annotation}", output)
        self.assertIn("proceed=false", output)
        self.assertNotIn("proceed=true", output)

    def test_an_outage_reading_the_npm_versions_stops_the_run(self):
        self.stubs["npm_candidates"].side_effect = release_checks.InfraError("npm", "the registry answered 503")
        self.assert_stopped(*self.run_plan(), "npm: the registry answered 503")

    def test_an_outage_reading_the_pins_stops_the_run(self):
        self.stubs["pinned_versions"].side_effect = release_checks.InfraError("git", "no fleet-v tags")
        self.assert_stopped(*self.run_plan(), "git: no fleet-v tags")

    def test_an_outage_reading_the_tag_ledger_stops_a_rollback(self):
        self.stubs["pins_by_ref"].side_effect = release_checks.InfraError("git", "cannot read refs/tags/fleet-v7")
        self.assert_stopped(*self.run_plan(MODE="rollback", TARGET="fleet-v7", EVENT_NAME="workflow_dispatch"),
                            "git: cannot read refs/tags/fleet-v7")

    def test_a_malformed_safety_file_stops_a_rollback(self):
        self.stubs["rollback_floor"].side_effect = release_checks.ReleaseCheckError("safety", "not a versions table")
        self.assert_stopped(*self.run_plan(MODE="rollback", TARGET="fleet-v7", EVENT_NAME="workflow_dispatch"),
                            "safety: not a versions table")

    def test_a_refusal_the_planner_wraps_keeps_its_own_wording(self):
        self.candidates = ["0.9.15"]
        self.down = {"0.9.15": ("network", "down")}
        code, output = self.run_plan()
        self.assertEqual(code, 1)
        self.assertIn("::error::no verdict on 0.9.15: network: down", output)
        self.assertIn("proceed=false", output)


class TestDescribe(unittest.TestCase):
    def test_both_kinds_of_check_failure_read_as_check_and_detail(self):
        self.assertEqual(ir.describe(release_checks.ReleaseCheckError("provenance", "no")), "provenance: no")
        self.assertEqual(ir.describe(release_checks.InfraError("network", "down")), "network: down")


if __name__ == "__main__":
    unittest.main()
