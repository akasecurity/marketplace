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


if __name__ == "__main__":
    unittest.main()
