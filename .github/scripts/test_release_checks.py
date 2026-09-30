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


class TestErrorClasses(unittest.TestCase):
    def test_no_verdict_is_never_caught_as_a_verdict(self):
        self.assertFalse(issubclass(rc.InfraError, rc.ReleaseCheckError))
        self.assertFalse(issubclass(rc.ReleaseCheckError, rc.InfraError))

    def test_both_carry_the_check_and_the_detail(self):
        for cls in (rc.ReleaseCheckError, rc.InfraError):
            with self.subTest(cls=cls.__name__):
                error = cls("npm", "the registry is down")
                self.assertEqual(error.check, "npm")
                self.assertEqual(error.detail, "the registry is down")
                self.assertEqual(str(error), "npm: the registry is down")

    def test_a_handler_written_for_a_verdict_lets_an_outage_through(self):
        # _tag_pin is lenient about what a tag's manifest says, so every verdict-shaped
        # failure pins nothing. A failed read is no verdict and must not be dropped with them.
        with mock.patch.object(rc, "_read_manifest", side_effect=rc.InfraError("git", "show failed")):
            with self.assertRaises(rc.InfraError):
                rc._tag_pin("unused", "fleet-v1")
        for verdict in (rc.ReleaseCheckError("manifest", "no plugins list"), ValueError("does not parse")):
            with self.subTest(verdict=repr(verdict)):
                with mock.patch.object(rc, "_read_manifest", side_effect=verdict):
                    self.assertIsNone(rc._tag_pin("unused", "fleet-v1"))


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

    def test_a_registry_document_that_is_not_a_versions_object_is_no_verdict(self):
        # The registry's packument always holds "versions" as an object keyed by version.
        # The list and string shapes belong to `npm view ... versions --json`, which this
        # module never reads, so they are a wrong answer and not a second accepted format.
        not_json = "answered non-JSON"
        no_object = "no versions object"
        for label, body, expected in (
            ("an array", b"[]", no_object),
            ("a string", b'"0.9.15"', no_object),
            ("null", b"null", no_object),
            ("no versions key", {"dist-tags": {"latest": "0.9.14"}}, no_object),
            ("a null versions", {"versions": None}, no_object),
            ("a versions list", {"versions": ["0.9.15"]}, no_object),
            ("a versions string", {"versions": "0.9.15"}, no_object),
            ("text that is not JSON", b"not json", not_json),
            ("bytes that are not UTF-8", b"\xff", not_json),
            ("a duplicated key", b'{"versions": {"0.9.15": {}}, "versions": {"0.9.16": {}}}', not_json),
        ):
            with self.subTest(label):
                fetch = ts.FakeFetch({rc.packument_url(): (200, body)})
                with self.assertRaises(rc.InfraError) as caught:
                    rc.npm_candidates({"0.9.14"}, fetch=fetch)
                self.assertEqual(caught.exception.check, "npm")
                self.assertIn(expected, caught.exception.detail)

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


class TestVerifyRelease(unittest.TestCase):
    def verify(self, version="0.9.14", *, routes=None, audits=None, sleeps=None):
        fetch = ts.FakeFetch(routes if routes is not None else ts.release_routes(version))
        queue = list(audits if audits is not None else [ts.audit_output(version)])

        def audit(package, v):
            self.assertEqual((package, v), (rc.PACKAGE, version))
            return queue.pop(0) if len(queue) > 1 else queue[0]

        recorded = sleeps if sleeps is not None else []
        return rc.verify_release(version, fetch=fetch, audit=audit, sleep=recorded.append), fetch

    def refused(self, check, **kwargs):
        with self.assertRaises(rc.ReleaseCheckError) as caught:
            self.verify(**kwargs)
        self.assertEqual(caught.exception.check, check)
        self.assertNotIsInstance(caught.exception, rc.InfraError)
        return caught.exception

    def test_a_tag_built_release_on_main_passes(self):
        release, _ = self.verify()
        self.assertEqual(
            release, rc.VerifiedRelease("0.9.14", ts.INTEGRITY, ts.SHASUM, ts.ATTESTED["0.9.14"], ts.RUN_URL)
        )

    def test_the_commit_check_asks_whether_main_is_ahead_of_the_commit(self):
        _, fetch = self.verify()
        self.assertIn(f"{rc.AI_TC_API}/compare/{ts.ATTESTED['0.9.14']}...main?per_page=1", fetch.urls())

    def test_identical_to_main_passes(self):
        self.verify(routes=ts.release_routes("0.9.14", compare="identical"))

    def test_behind_main_is_refused(self):
        # Built on main's tip and never merged: the attacker's case.
        self.refused("commit-on-main", routes=ts.release_routes("0.9.14", compare="behind"))

    def test_diverged_is_refused(self):
        self.refused("commit-on-main", routes=ts.release_routes("0.9.14", compare="diverged"))

    def test_an_unknown_commit_is_refused(self):
        routes = ts.release_routes("0.9.14")
        routes[ts.compare_url(ts.ATTESTED["0.9.14"])] = (404, {"message": "Not Found"})
        self.refused("commit-on-main", routes=routes)

    def test_a_github_outage_is_no_verdict(self):
        routes = ts.release_routes("0.9.14")
        routes[ts.compare_url(ts.ATTESTED["0.9.14"])] = (502, b"")
        with self.assertRaises(rc.InfraError):
            self.verify(routes=routes)

    def test_a_non_exact_version_is_refused_before_any_request(self):
        fetch = ts.FakeFetch()
        with self.assertRaises(rc.ReleaseCheckError) as caught:
            rc.verify_release("0.9.15-rc1", fetch=fetch, audit=lambda p, v: {}, sleep=lambda s: None)
        self.assertEqual((caught.exception.check, fetch.calls), ("version", []))

    def test_registry_lag_is_retried(self):
        routes = ts.release_routes("0.9.14")
        url = ts.dist_url("0.9.14")
        routes[url] = [(404, b'"version not found"'), (404, b'"version not found"'), routes[url]]
        sleeps = []
        self.verify(routes=routes, sleeps=sleeps)
        self.assertEqual(sleeps, [20, 20])

    def test_a_version_npm_never_serves_is_refused(self):
        routes = ts.release_routes("0.9.14")
        routes[ts.dist_url("0.9.14")] = (404, b'"version not found"')
        sleeps = []
        self.refused("dist", routes=routes, sleeps=sleeps)
        self.assertEqual(sleeps, [20, 20, 20, 20])

    def test_an_integrity_that_is_not_one_sha512_is_refused(self):
        self.refused("dist", routes=ts.release_routes("0.9.14", integrity="sha1-abc"))

    def test_an_unindexed_attestation_is_retried(self):
        sleeps = []
        self.verify(audits=[ts.audit_output("0.9.14", verified=False), ts.audit_output("0.9.14")], sleeps=sleeps)
        self.assertEqual(sleeps, [20])

    def test_no_attestation_after_five_tries_is_refused(self):
        sleeps = []
        error = self.refused("provenance", audits=[ts.audit_output("0.9.14", verified=False)], sleeps=sleeps)
        self.assertIn("no VERIFIED attestation", error.detail)
        self.assertEqual(sleeps, [20, 20, 20, 20])

    def test_npm_reporting_invalid_is_refused(self):
        self.refused("provenance", audits=[ts.audit_output("0.9.14", invalid=[{"code": "EINTEGRITYSIGNATURE"}])])

    def test_an_off_tag_branch_publish_is_refused_without_crying_theft(self):
        # The certificate and the statement both say the workflow ran from a branch.
        ref = "refs/heads/release/0.9.x"
        uri = f"{rc.PROV_REPO}/{ts.WORKFLOW}@{ref}"
        stmt = ts.statement("0.9.14", ref=ref)
        cert = ts.signing_cert("0.9.14", san=uri, build_signer=uri, build_config=uri, ref=ref, trigger="workflow_dispatch")
        error = self.refused("provenance", audits=[ts.audit_output("0.9.14", stmt, cert=cert)])
        self.assertIn("not a stolen npm credential", error.detail)

    def test_another_repository_is_refused(self):
        other = "https://github.com/someone/ai-tc"
        uri = f"{other}/{ts.WORKFLOW}@refs/tags/plugin-claude-v0.9.14"
        stmt = ts.statement("0.9.14", repository=other)
        cert = ts.signing_cert("0.9.14", san=uri, build_signer=uri, build_config=uri, repository=other)
        error = self.refused("provenance", audits=[ts.audit_output("0.9.14", stmt, cert=cert)])
        self.assertIn("anyone can publish with provenance", error.detail)

    def test_another_workflow_is_refused(self):
        path = ".github/workflows/other.yml"
        uri = f"{rc.PROV_REPO}/{path}@refs/tags/plugin-claude-v0.9.14"
        stmt = ts.statement("0.9.14", path=path)
        cert = ts.signing_cert("0.9.14", san=uri, build_signer=uri, build_config=uri)
        self.refused("provenance", audits=[ts.audit_output("0.9.14", stmt, cert=cert)])

    def test_a_self_hosted_builder_is_refused(self):
        stmt = ts.statement("0.9.14", builder="https://github.com/actions/runner/self-hosted")
        cert = ts.signing_cert("0.9.14", runner="self-hosted")
        error = self.refused("provenance", audits=[ts.audit_output("0.9.14", stmt, cert=cert)])
        self.assertIn("github-hosted", error.detail)

    def test_an_attestation_for_different_bytes_is_refused(self):
        stmt = ts.statement("0.9.14", sha512="00" * 64)
        error = self.refused("provenance", audits=[ts.audit_output("0.9.14", stmt)])
        self.assertIn("different tarball", error.detail)

    def test_a_statement_without_the_tag_dependency_is_refused(self):
        stmt = ts.statement("0.9.14", dependency_uri=f"git+{rc.PROV_REPO}@refs/heads/main")
        self.refused("attested-commit", audits=[ts.audit_output("0.9.14", stmt)])

    def test_a_short_commit_is_refused(self):
        stmt = ts.statement("0.9.14", commit="a75532b9")
        self.refused("attested-commit", audits=[ts.audit_output("0.9.14", stmt)])

    def test_a_foreign_run_url_is_refused(self):
        stmt = ts.statement("0.9.14", run_url="https://example.com/actions/runs/1")
        self.refused("run-url", audits=[ts.audit_output("0.9.14", stmt)])


SQL_GENERATED = (
    "ALTER TABLE `events` ADD `elapsed_ms` integer GENERATED ALWAYS AS "
    "(json_extract(attributes, '$.elapsed_ms')) VIRTUAL;"
)
SQL_DEFAULTED = "ALTER TABLE `widgets` ADD `approved` integer DEFAULT 0 NOT NULL;"
SQL_DROP_INDEX = """DROP INDEX IF EXISTS `idx_widgets_key`;--> statement-breakpoint
CREATE INDEX `idx_widgets_key_created` ON `widgets` (`key`,`created_at`);"""
SQL_COMMENTED = """CREATE INDEX `idx_events_ended` ON `events` (`ended_at`) WHERE ended_at IS NOT NULL;--> statement-breakpoint
-- An expression index, written by hand: the generator cannot emit an
-- expression that contains a comma.
CREATE INDEX `idx_events_run` ON `events` (`session_id`, json_extract(`attributes`, '$.run_key')) WHERE `kind` = 'call';
"""
SQL_NULLABLE = "ALTER TABLE `widgets` ADD `provider_id` text;"
SQL_REBUILD = """PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_widgets` (`id` text PRIMARY KEY NOT NULL, `mode` text NOT NULL);--> statement-breakpoint
INSERT INTO `__new_widgets`("id", "mode") SELECT "id", "mode" FROM `widgets`;--> statement-breakpoint
DROP TABLE `widgets`;--> statement-breakpoint
ALTER TABLE `__new_widgets` RENAME TO `widgets`;--> statement-breakpoint
PRAGMA foreign_keys=ON;"""


class TestMigrationKind(unittest.TestCase):
    def test_generated_and_nullable_columns_are_additive(self):
        self.assertEqual(rc.migration_kind(SQL_GENERATED), "additive")
        self.assertEqual(rc.migration_kind(SQL_NULLABLE), "additive")

    def test_a_defaulted_not_null_column_is_additive(self):
        self.assertEqual(rc.migration_kind(SQL_DEFAULTED), "additive")

    def test_indexes_and_comments_are_additive(self):
        self.assertEqual(rc.migration_kind(SQL_COMMENTED), "additive")

    def test_a_new_table_is_additive(self):
        self.assertEqual(rc.migration_kind("CREATE TABLE `gadgets` (`id` integer PRIMARY KEY);"), "additive")

    def test_dropping_an_index_is_not(self):
        self.assertEqual(rc.migration_kind(SQL_DROP_INDEX), "non-additive: a drop (drop index)")

    def test_not_null_without_a_default_is_not(self):
        self.assertEqual(
            rc.migration_kind("ALTER TABLE `widgets` ADD `c` text NOT NULL;"),
            "non-additive: a NOT NULL column without a default",
        )

    def test_a_table_rebuild_is_not(self):
        self.assertEqual(rc.migration_kind(SQL_REBUILD), "non-additive: a table rebuild (drizzle's __new_ copy)")

    def test_every_other_change_is_not(self):
        cases = {
            "ALTER TABLE `widgets` RENAME COLUMN `a` TO `b`;": "a rename",
            "ALTER TABLE `widgets` DROP COLUMN `a`;": "a dropped column",
            "DROP TABLE `widgets`;": "a drop (drop table)",
            "CREATE VIEW `widgets` AS SELECT 1;": "a view",
            "CREATE TRIGGER `w` AFTER INSERT ON `widgets` BEGIN SELECT 1; END;": "a trigger",
            "CREATE UNIQUE INDEX `u` ON `widgets` (`a`);": "a UNIQUE index",
            "UPDATE `widgets` SET `c` = 1;": "an unrecognised statement",
        }
        for sql, reason in cases.items():
            with self.subTest(sql):
                self.assertTrue(rc.migration_kind(sql).startswith(f"non-additive: {reason}"), rc.migration_kind(sql))

    def test_an_empty_file_is_not_additive(self):
        self.assertEqual(rc.migration_kind("-- nothing\n"), "non-additive: no statements")


JOURNAL = f"{rc.MIGRATIONS_DIR}/meta/_journal.json"
FROM, TO = ts.ATTESTED["0.9.13"], ts.ATTESTED["0.9.14"]
BASE_TAGS = ("0000_initial", "0034_migration")


def journal(*tags):
    return {"version": "7", "dialect": "sqlite", "entries": [{"idx": i, "tag": t} for i, t in enumerate(tags)]}


class TestClassifyMigrations(unittest.TestCase):
    def fetch(self, from_tags, to_tags, sql):
        routes = {
            ts.contents_url(JOURNAL, FROM): (200, journal(*from_tags)),
            ts.contents_url(JOURNAL, TO): (200, journal(*to_tags)),
        }
        for tag, text in sql.items():
            routes[ts.contents_url(f"{rc.MIGRATIONS_DIR}/{tag}.sql", TO)] = (200, text.encode())
        return ts.FakeFetch(routes)

    def test_no_new_migration_is_additive(self):
        result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS, {}))
        self.assertEqual((result.classification, result.migrations), ("additive", []))

    def test_every_migration_counts_until_downgrades_are_measured(self):
        tag = "0035_migration"
        result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS + (tag,), {tag: SQL_NULLABLE}))
        self.assertEqual((result.classification, result.migrations), ("not-rollback-safe", [tag]))
        self.assertEqual(result.kinds, {tag: "additive"})

    def test_once_measured_only_non_additive_kinds_count(self):
        additive, dropping = "0035_migration", "0036_migration"
        with mock.patch.object(rc, "EVERY_MIGRATION_COUNTS", False):
            first = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS + (additive,), {additive: SQL_NULLABLE}))
            second = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS + (dropping,), {dropping: SQL_DROP_INDEX}))
        self.assertEqual((first.classification, second.classification), ("additive", "not-rollback-safe"))

    def test_reads_use_the_raw_media_type(self):
        fetch = self.fetch(BASE_TAGS, BASE_TAGS, {})
        rc.classify_migrations(FROM, TO, fetch=fetch)
        self.assertTrue(all(h.get("Accept") == "application/vnd.github.raw+json" for _, h in fetch.calls))

    def test_an_unreadable_journal_counts_as_not_rollback_safe(self):
        fetch = ts.FakeFetch({ts.contents_url(JOURNAL, TO): (200, journal(*BASE_TAGS))})
        result = rc.classify_migrations(FROM, TO, fetch=fetch)
        self.assertEqual((result.classification, result.migrations), ("not-rollback-safe", []))
        self.assertIn("cannot be read", result.note)

    def test_an_unreadable_migration_file_is_not_additive(self):
        tag = "0036_migration"
        with mock.patch.object(rc, "EVERY_MIGRATION_COUNTS", False):
            result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS + (tag,), {}))
        self.assertEqual(result.classification, "not-rollback-safe")
        self.assertIn("cannot be read", result.kinds[tag])

    def test_a_tag_dropped_from_the_journal_is_not_rollback_safe(self):
        tag = "0035_migration"
        with mock.patch.object(rc, "EVERY_MIGRATION_COUNTS", False):
            result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS + (tag,), BASE_TAGS, {}))
        self.assertEqual((result.classification, result.migrations), ("not-rollback-safe", [tag]))

    def test_a_github_error_is_no_verdict(self):
        fetch = ts.FakeFetch({ts.contents_url(JOURNAL, FROM): (502, b"")})
        with self.assertRaises(rc.InfraError):
            rc.classify_migrations(FROM, TO, fetch=fetch)

    def test_only_full_commit_ids_are_accepted(self):
        fetch = ts.FakeFetch()
        with self.assertRaises(rc.ReleaseCheckError):
            rc.classify_migrations("a75532b9", TO, fetch=fetch)
        self.assertEqual(fetch.calls, [])

    def test_a_journal_tag_that_is_not_a_migration_name_is_refused(self):
        with self.assertRaises(rc.ReleaseCheckError):
            rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS + ("../../x",), {}))


def fake_verify(version):
    return rc.VerifiedRelease(version, ts.INTEGRITY, ts.SHASUM, ts.ATTESTED[version], ts.RUN_URL)


class TestSafetyEntry(unittest.TestCase):
    def test_computed_from_the_highest_pinned_version_below(self):
        calls = []

        def classify(start, end):
            calls.append((start, end))
            return rc.Classification("not-rollback-safe", ["0029_migration"])

        entry = rc.safety_entry("0.9.12", {"0.9.9", "0.9.10", "0.9.14"}, verify=fake_verify, classify=classify)
        self.assertEqual(calls, [(ts.ATTESTED["0.9.10"], ts.ATTESTED["0.9.12"])])
        self.assertEqual(list(entry), ["classification", "from", "to", "migrations"])
        self.assertEqual(
            entry,
            {
                "classification": "not-rollback-safe",
                "from": ts.ATTESTED["0.9.10"],
                "to": ts.ATTESTED["0.9.12"],
                "migrations": ["0029_migration"],
            },
        )

    def test_nothing_pinned_below_is_refused(self):
        with self.assertRaises(rc.ReleaseCheckError):
            rc.safety_entry("0.9.8", {"0.9.9"}, verify=fake_verify, classify=lambda a, b: None)


class TestRollbackFloor(unittest.TestCase):
    SAFETY = {"versions": copy.deepcopy(ts.SEED)}

    def test_the_seed_refuses_a_rollback_from_0_9_14_to_0_9_13(self):
        self.assertEqual(rc.rollback_floor(self.SAFETY, "0.9.13", "0.9.14"), "0.9.14")

    def test_the_lowest_flagged_version_in_range_is_the_floor(self):
        self.assertEqual(rc.rollback_floor(self.SAFETY, "0.9.8", "0.9.14"), "0.9.9")

    def test_additive_versions_set_no_floor(self):
        self.assertIsNone(rc.rollback_floor({"versions": {"0.9.13": dict(ts.SEED["0.9.13"])}}, "0.9.12", "0.9.13"))

    def test_the_target_itself_is_never_the_floor(self):
        self.assertIsNone(rc.rollback_floor({"versions": {"0.9.12": dict(ts.SEED["0.9.12"])}}, "0.9.12", "0.9.13"))

    def test_a_flag_above_the_highest_pinned_version_is_ignored(self):
        self.assertIsNone(rc.rollback_floor({"versions": {"0.9.15": dict(ts.SEED["0.9.14"])}}, "0.9.13", "0.9.14"))

    def test_a_malformed_or_missing_entry_counts_as_flagged(self):
        self.assertEqual(rc.rollback_floor({"versions": {"0.9.14": "additive"}}, "0.9.13", "0.9.14"), "0.9.14")
        # A pinned version with no entry at all (a break-glass pin, a restore) is flagged too.
        additive = {"versions": {"0.9.13": dict(ts.SEED["0.9.13"])}}
        pinned = {"0.9.12", "0.9.13", "0.9.14"}
        self.assertEqual(rc.rollback_floor(additive, "0.9.12", "0.9.14", pinned=pinned), "0.9.14")
        self.assertIsNone(rc.rollback_floor(additive, "0.9.12", "0.9.13", pinned=pinned))

    def test_a_malformed_file_is_refused(self):
        with self.assertRaises(rc.ReleaseCheckError):
            rc.rollback_floor({"0.9.14": {}}, "0.9.13", "0.9.14")


class TestSafetyProblems(unittest.TestCase):
    def test_the_seed_is_well_formed(self):
        self.assertEqual(rc.safety_problems({"versions": ts.SEED}), [])

    def test_each_malformation_is_named(self):
        good = dict(ts.SEED["0.9.14"])
        cases = {
            "shape": {"versions": []},
            "extra top-level key": {"versions": {}, "notes": "x"},
            "version": {"versions": {"0.9": good}},
            "key order": {"versions": {"0.9.14": {k: good[k] for k in ("from", "classification", "to", "migrations")}}},
            "classification": {"versions": {"0.9.14": {**good, "classification": "safe"}}},
            "commit": {"versions": {"0.9.14": {**good, "from": "abc"}}},
            "migration": {"versions": {"0.9.14": {**good, "migrations": ["../x"]}}},
        }
        for name, doc in cases.items():
            with self.subTest(name):
                self.assertNotEqual(rc.safety_problems(doc), [])


class TestDiffMode(unittest.TestCase):
    def removed(self):
        doc = ts.manifest()
        del doc["plugins"][2]
        return doc

    def test_identical_is_none(self):
        self.assertEqual(rc.diff_mode(ts.manifest(), ts.manifest()), "none")

    def test_other_entries_and_top_level_edits_alone_are_none(self):
        head = ts.manifest()
        head["plugins"][0]["description"] = "new words"
        head["metadata"]["version"] = "0.2.0"
        self.assertEqual(rc.diff_mode(ts.manifest(), head), "none")

    def test_reordered_plugins_are_none(self):
        head = ts.manifest()
        head["plugins"].reverse()
        self.assertEqual(rc.diff_mode(ts.manifest(), head), "none")

    def test_up_with_its_integrity_is_advance(self):
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), ts.manifest("0.9.15", integrity=ts.OTHER_INTEGRITY)), "advance")

    def test_down_is_rollback(self):
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), ts.manifest("0.9.13", integrity=ts.OTHER_INTEGRITY)), "rollback")

    def test_a_base_without_metadata_still_advances(self):
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14", integrity=None), ts.manifest("0.9.15")), "advance")

    def test_an_advance_that_also_touches_another_entry_is_human(self):
        head = ts.manifest("0.9.15")
        head["plugins"][0]["description"] = "new words"
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), head), "human")

    def test_an_advance_that_changes_a_top_level_key_is_human(self):
        head = ts.manifest("0.9.15")
        head["metadata"]["version"] = "0.2.0"
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), head), "human")

    def test_an_advance_that_changes_the_registry_is_human(self):
        head = ts.manifest("0.9.15")
        ts.ai_tc(head)["source"]["registry"] = "https://npm.pkg.github.com"
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), head), "human")

    def test_an_advance_that_adds_a_key_is_human(self):
        head = ts.manifest("0.9.15")
        ts.ai_tc(head)["hooks"] = "./hooks/extra.json"
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), head), "human")

    def test_a_version_move_without_integrity_is_human(self):
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), ts.manifest("0.9.15", integrity=None)), "human")

    def test_extra_metadata_is_human(self):
        head = ts.manifest("0.9.15")
        ts.ai_tc(head)["metadata"]["note"] = "x"
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), head), "human")

    def test_a_new_integrity_at_the_same_version_is_human(self):
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), ts.manifest("0.9.14", integrity=ts.OTHER_INTEGRITY)), "human")

    def test_a_description_edit_is_human(self):
        self.assertEqual(rc.diff_mode(ts.manifest(), ts.manifest(description="Better words.")), "human")

    def test_removing_only_the_entry_is_remove(self):
        self.assertEqual(rc.diff_mode(ts.manifest(), self.removed()), "remove")

    def test_removing_the_entry_and_editing_another_is_human(self):
        head = self.removed()
        head["plugins"][0]["description"] = "new words"
        self.assertEqual(rc.diff_mode(ts.manifest(), head), "human")

    def test_the_fixed_restore_shape_is_restore(self):
        self.assertEqual(rc.diff_mode(self.removed(), ts.manifest("0.9.14")), "restore")

    def test_a_restore_without_the_registry_is_human(self):
        self.assertEqual(rc.diff_mode(self.removed(), ts.manifest("0.9.14", registry=False)), "human")

    def test_a_restore_with_an_extra_key_is_human(self):
        head = ts.manifest("0.9.14")
        ts.ai_tc(head)["strict"] = False
        self.assertEqual(rc.diff_mode(self.removed(), head), "human")

    def test_nothing_before_or_after_is_none(self):
        self.assertEqual(rc.diff_mode(self.removed(), self.removed()), "none")

    def test_an_ambiguous_head_is_refused(self):
        head = ts.manifest("0.9.15")
        head["plugins"].append(copy.deepcopy(head["plugins"][2]))
        with self.assertRaises(rc.ReleaseCheckError):
            rc.diff_mode(ts.manifest(), head)
