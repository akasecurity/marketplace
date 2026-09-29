"""Unit tests for release_checks.py. Standard library only and no network: every fetch,
npm run and sleep is injected. live_release_checks.py holds the three live checks."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import subprocess
import unittest
from unittest import mock

import _testsupport as ts
import release_checks as rc


class TestJsonHelpers(unittest.TestCase):
    def test_duplicate_keys_are_refused(self):
        with self.assertRaisesRegex(ValueError, "duplicate key 'version'"):
            rc.parse_json('{"version": "0.9.13", "version": "0.9.14"}')

    def test_nan_is_refused(self):
        with self.assertRaisesRegex(ValueError, "NaN"):
            rc.parse_json('{"n": NaN}')

    def test_the_writer_keeps_non_ascii_and_ends_in_a_newline(self):
        text = rc.dump_json(ts.manifest())
        self.assertIn("—", text)
        self.assertTrue(text.endswith("}\n"))
        self.assertEqual(rc.load_round_trip(text), ts.manifest())

    def test_a_reformatted_file_is_refused_before_any_rewrite(self):
        compact = json.dumps(ts.manifest(), ensure_ascii=False)
        with self.assertRaises(rc.ReleaseCheckError) as caught:
            rc.load_round_trip(compact)
        self.assertEqual(caught.exception.check, "round-trip")


class TestSelectEntry(unittest.TestCase):
    def test_selects_the_one_ai_tc_entry(self):
        doc = ts.manifest()
        self.assertIs(rc.select_ai_tc_entry(doc), doc["plugins"][2])

    def test_no_entry_named_ai_tc_is_refused(self):
        doc = ts.manifest()
        doc["plugins"][2]["name"] = "ai-tc-2"
        with self.assertRaisesRegex(rc.ReleaseCheckError, "exactly one entry named 'ai-tc', found 0"):
            rc.select_ai_tc_entry(doc)

    def test_two_entries_named_ai_tc_are_refused(self):
        doc = ts.manifest()
        doc["plugins"].append(copy.deepcopy(doc["plugins"][2]))
        with self.assertRaisesRegex(rc.ReleaseCheckError, "exactly one entry named 'ai-tc', found 2"):
            rc.select_ai_tc_entry(doc)

    def test_a_second_entry_pinning_the_package_is_refused(self):
        doc = ts.manifest()
        twin = copy.deepcopy(doc["plugins"][2])
        twin["name"] = "ai-tc-canary"
        doc["plugins"].append(twin)
        with self.assertRaisesRegex(rc.ReleaseCheckError, "pinning @akasecurity/ai-tc-claude-code, found 2"):
            rc.select_ai_tc_entry(doc)

    def test_the_name_and_the_package_on_different_entries_is_refused(self):
        doc = ts.manifest()
        doc["plugins"][2]["name"] = "renamed"
        doc["plugins"][0]["name"] = "ai-tc"
        with self.assertRaisesRegex(rc.ReleaseCheckError, "is not the entry that pins"):
            rc.select_ai_tc_entry(doc)

    def test_a_path_source_string_is_not_an_error(self):
        doc = ts.manifest()
        doc["plugins"].insert(0, {"name": "local", "source": "./plugins/local"})
        self.assertEqual(rc.select_ai_tc_entry(doc)["name"], "ai-tc")

    def test_find_returns_none_when_nothing_names_or_pins_ai_tc(self):
        doc = ts.manifest()
        del doc["plugins"][2]
        self.assertIsNone(rc.find_ai_tc_entry(doc))

    def test_find_still_refuses_ambiguity(self):
        doc = ts.manifest()
        doc["plugins"].append(copy.deepcopy(doc["plugins"][2]))
        with self.assertRaises(rc.ReleaseCheckError):
            rc.find_ai_tc_entry(doc)

    def test_entry_version_accepts_only_exact_versions(self):
        entry = ts.ai_tc(ts.manifest("0.9.14"))
        self.assertEqual(rc.entry_version(entry), "0.9.14")
        for bad in ("0.9.14-rc1", "0.9.09", "^0.9.14", "0.9", "latest"):
            entry["source"]["version"] = bad
            self.assertIsNone(rc.entry_version(entry), bad)

    def test_versions_order_by_number(self):
        self.assertLess(rc.vkey("0.9.9"), rc.vkey("0.9.10"))
        with self.assertRaises(rc.ReleaseCheckError):
            rc.vkey("latest")


class TestPinnedVersions(unittest.TestCase):
    def setUp(self):
        self.repo = ts.Repo(self)
        unpinned = ts.manifest()
        del ts.ai_tc(unpinned)["source"]["version"]
        self.repo.commit(unpinned)
        self.repo.tag("fleet-v1")
        self.repo.commit(ts.manifest("0.9.6"))
        self.repo.tag("fleet-v2")
        self.repo.commit(ts.manifest("0.9.11"))  # pinned on main once, never tagged
        self.repo.commit(ts.manifest("0.9.12"))
        self.repo.tag("fleet-v10")  # numeric order, not text order
        self.repo.commit(ts.manifest("0.9.13"))
        self.repo.tag("release-1")  # not a fleet tag: ignored here
        self.repo.commit(ts.manifest("0.9.14"))

    def test_main_and_every_fleet_tag(self):
        self.assertEqual(rc.pinned_versions(self.repo.path), {"0.9.6", "0.9.12", "0.9.14"})

    def test_pins_by_ref_names_each_ref_in_numeric_tag_order(self):
        self.assertEqual(
            list(rc.pins_by_ref(self.repo.path).items()),
            [("main", "0.9.14"), ("fleet-v1", None), ("fleet-v2", "0.9.6"), ("fleet-v10", "0.9.12")],
        )

    def test_tag_pinned_versions_leave_out_main(self):
        self.assertEqual(rc.tag_pinned_versions(self.repo.path), {"0.9.6", "0.9.12"})

    def test_origin_main_wins_over_a_stale_local_main(self):
        older = ts.git(self.repo.path, "rev-parse", "HEAD~1").strip()
        ts.git(self.repo.path, "update-ref", "refs/remotes/origin/main", older)
        self.assertEqual(rc.main_ref(self.repo.path), "refs/remotes/origin/main")
        self.assertEqual(rc.pins_by_ref(self.repo.path)["main"], "0.9.13")

    def test_main_without_the_entry_pins_nothing(self):
        doc = ts.manifest()
        del doc["plugins"][2]
        self.repo.commit(doc)
        self.assertIsNone(rc.pins_by_ref(self.repo.path)["main"])

    def test_an_ambiguous_main_is_refused(self):
        doc = ts.manifest()
        doc["plugins"].append(copy.deepcopy(doc["plugins"][2]))
        self.repo.commit(doc)
        with self.assertRaises(rc.ReleaseCheckError):
            rc.pinned_versions(self.repo.path)

    def test_a_repository_without_main_is_infrastructure(self):
        ts.git(self.repo.path, "branch", "-m", "main", "trunk")
        with self.assertRaises(rc.InfraError):
            rc.pinned_versions(self.repo.path)


class TestHttpHeaders(unittest.TestCase):
    def test_a_token_goes_only_to_the_github_api(self):
        self.assertTrue(rc._sends_token_to(f"{rc.AI_TC_API}/compare/a...main"))
        self.assertFalse(rc._sends_token_to(rc.packument_url()))
        self.assertFalse(rc._sends_token_to("https://registry.npmjs.org/api.github.com"))

    def test_github_requests_name_the_api_version(self):
        headers = rc._headers_for(f"{rc.AI_TC_API}/x", {})
        self.assertEqual(headers["X-GitHub-Api-Version"], "2022-11-28")
        self.assertEqual(headers["Accept"], "application/vnd.github+json")

    def test_registry_requests_carry_no_authorization(self):
        headers = rc._headers_for(rc.packument_url(), {"Accept": "application/json"})
        self.assertNotIn("Authorization", headers)
        self.assertEqual(headers["Accept"], "application/json")

    def test_no_token_in_the_environment_means_anonymous(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertNotIn("Authorization", rc._headers_for(f"{rc.AI_TC_API}/x", {}))

    def test_the_packument_url_escapes_the_scope_slash(self):
        self.assertEqual(rc.packument_url(), "https://registry.npmjs.org/@akasecurity%2Fai-tc-claude-code")


class TestNpmCandidates(unittest.TestCase):
    def fetch(self, versions, latest="0.9.14"):
        return ts.FakeFetch(
            {rc.packument_url(): (200, {"versions": versions, "dist-tags": {"latest": latest}})}
        )

    def test_only_exact_versions_above_everything_pinned_ascending(self):
        versions = {v: {} for v in ["0.9.9", "0.9.10", "0.9.14", "0.9.15", "0.10.0-rc1", "0.9.16", "0.10.0"]}
        self.assertEqual(
            rc.npm_candidates({"0.9.6", "0.9.14"}, fetch=self.fetch(versions)),
            ["0.9.15", "0.9.16", "0.10.0"],
        )

    def test_versions_sort_by_number_not_text(self):
        self.assertEqual(
            rc.npm_candidates({"0.9.8"}, fetch=self.fetch({"0.9.10": {}, "0.9.9": {}})), ["0.9.9", "0.9.10"]
        )

    def test_nothing_pinned_yields_every_exact_version(self):
        self.assertEqual(rc.npm_candidates(set(), fetch=self.fetch({"0.9.6": {}, "0.9.0-rc1": {}})), ["0.9.6"])

    def test_nothing_above_the_pin_is_an_empty_list(self):
        self.assertEqual(rc.npm_candidates({"0.9.14"}, fetch=self.fetch({"0.9.13": {}, "0.9.14": {}})), [])

    def test_a_single_version_string_is_accepted(self):
        fetch = ts.FakeFetch({rc.packument_url(): (200, {"versions": "0.9.15"})})
        self.assertEqual(rc.npm_candidates({"0.9.14"}, fetch=fetch), ["0.9.15"])

    def test_npm_latest_is_never_consulted(self):
        self.assertEqual(
            rc.npm_candidates({"0.9.14"}, fetch=self.fetch({"0.9.15": {}}, latest="9.9.9")), ["0.9.15"]
        )

    def test_the_registry_is_read_explicitly(self):
        fetch = self.fetch({"0.9.15": {}})
        rc.npm_candidates({"0.9.14"}, fetch=fetch)
        self.assertEqual(fetch.calls, [(rc.packument_url(), {"Accept": "application/json"})])

    def test_a_registry_error_is_infrastructure(self):
        with self.assertRaises(rc.InfraError):
            rc.npm_candidates(set(), fetch=ts.FakeFetch({rc.packument_url(): (503, b"")}))


class FakeRun:
    """Stands in for subprocess.run, answering by npm sub-command."""

    def __init__(self, *, install=(0,), audit=(1, "{}")):
        self.install = list(install)
        self.audit = audit
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs.get("cwd")))
        if args[:2] == ["npm", "init"]:
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == ["npm", "install"]:
            code = self.install.pop(0) if len(self.install) > 1 else self.install[0]
            return subprocess.CompletedProcess(args, code, "", "npm error 404" if code else "")
        code, out = self.audit
        return subprocess.CompletedProcess(args, code, out, "")


class TestNpmAuditSignatures(unittest.TestCase):
    def test_installs_exactly_the_version_from_npmjs_without_scripts_in_a_scratch_dir(self):
        run = FakeRun(audit=(1, json.dumps(ts.audit_output("0.9.14"))))
        result = rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None)
        install = next(a for a, _ in run.calls if a[:2] == ["npm", "install"])
        self.assertIn("--ignore-scripts", install)
        self.assertIn("--@akasecurity:registry=https://registry.npmjs.org", install)
        self.assertEqual(install[-1], "@akasecurity/ai-tc-claude-code@0.9.14")
        self.assertEqual(result["verified"][0]["version"], "0.9.14")
        cwds = {cwd for _, cwd in run.calls}
        self.assertEqual(len(cwds), 1)
        self.assertNotEqual(cwds.pop(), os.getcwd())

    def test_the_audit_asks_for_attestations(self):
        run = FakeRun(audit=(0, json.dumps(ts.audit_output("0.9.14"))))
        rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None)
        self.assertEqual(run.calls[-1][0], ["npm", "audit", "signatures", "--json", "--include-attestations"])

    def test_install_is_retried_then_reported_as_toolchain(self):
        sleeps = []
        with self.assertRaises(rc.InfraError) as caught:
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=FakeRun(install=(1,)), sleep=sleeps.append)
        self.assertEqual(caught.exception.check, "toolchain")
        self.assertIn("NOT a signature result", caught.exception.detail)
        self.assertEqual(sleeps, [20, 20, 20, 20])

    def test_a_late_install_success_is_used(self):
        run = FakeRun(install=(1, 1, 0), audit=(0, json.dumps(ts.audit_output("0.9.14"))))
        rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None)
        self.assertEqual(sum(1 for a, _ in run.calls if a[:2] == ["npm", "install"]), 3)

    def test_empty_audit_output_is_toolchain(self):
        with self.assertRaises(rc.InfraError):
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=FakeRun(audit=(1, "  ")), sleep=lambda s: None)

    def test_non_json_audit_output_is_toolchain(self):
        with self.assertRaises(rc.InfraError):
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=FakeRun(audit=(1, "oops")), sleep=lambda s: None)

    def test_missing_npm_is_toolchain(self):
        def run(args, **kwargs):
            raise FileNotFoundError("npm")

        with self.assertRaises(rc.InfraError):
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None)
