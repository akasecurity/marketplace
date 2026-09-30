"""What the release checks do with the registry's answers and with npm's audit report:
the registry signature, a throttled or garbled registry read, and a report whose shape
is not one npm prints."""

from __future__ import annotations

import base64
import copy
import json
import unittest

import _testsupport as ts
import release_checks as rc

VERSION = "0.9.14"


def missing_item(version=VERSION, name=rc.PACKAGE):
    return {"name": name, "version": version, "location": f"node_modules/{name}", "registry": rc.REGISTRY}


class TestRegistrySignature(ts.VerifyMixin, unittest.TestCase):
    def test_a_package_npm_lists_as_missing_is_refused_even_when_verified(self):
        # npm fills `missing` and `verified` independently, so a release can be in both.
        sleeps = []
        error = self.refused("signature", audits=[ts.audit_output(VERSION, missing=[missing_item()])], sleeps=sleeps)
        self.assertIn("registry signature", error.detail)
        self.assertEqual(sleeps, [], "a missing signature is a verdict, not a lag to wait out")

    def test_another_package_or_version_in_missing_does_not_matter(self):
        missing = [missing_item(name="left-pad"), missing_item(version="0.9.13")]
        release, _ = self.verify(audits=[ts.audit_output(VERSION, missing=missing)])
        self.assertEqual(release.version, VERSION)

    def test_a_verified_entry_without_the_registry_publish_attestation_is_refused(self):
        # An empty `missing` only means something once npm held the registry's keys, and
        # the registry's publish attestation verifying is what shows it did.
        error = self.refused("signature", audits=[ts.audit_output(VERSION, publish=False)])
        self.assertIn("publish attestation", error.detail)

    def test_a_missing_list_that_is_not_a_list_of_objects_is_toolchain(self):
        for name, value in {"a string": "none", "an object": {}, "null": None, "a string item": ["x"]}.items():
            with self.subTest(name):
                out = ts.audit_output(VERSION)
                out["missing"] = value
                self.no_verdict("toolchain", audits=[out])

    def test_a_report_without_a_missing_list_is_toolchain(self):
        out = ts.audit_output(VERSION)
        del out["missing"]
        self.no_verdict("toolchain", audits=[out])

    def test_the_not_indexed_explanation_does_not_blame_the_registry_signature(self):
        error = self.refused("provenance", audits=[ts.audit_output(VERSION, verified=False)])
        self.assertIn("no VERIFIED attestation", error.detail)
        self.assertNotIn("registry signature", error.detail)


class TestRegistryDist(ts.VerifyMixin, unittest.TestCase):
    def routes_answering(self, *answers):
        routes = ts.release_routes(VERSION)
        routes[ts.dist_url(VERSION)] = list(answers)
        return routes

    def good_answer(self):
        return ts.release_routes(VERSION)[ts.dist_url(VERSION)]

    def test_a_rate_limited_dist_read_is_retried_then_no_verdict(self):
        sleeps = []
        error = self.no_verdict("dist", routes=self.routes_answering((429, b"slow down")), sleeps=sleeps)
        self.assertIn("429", error.detail)
        self.assertEqual(sleeps, [20, 20, 20, 20])

    def test_a_late_success_after_throttling_is_used(self):
        sleeps = []
        routes = self.routes_answering((429, b""), (429, b""), self.good_answer())
        release, _ = self.verify(routes=routes, sleeps=sleeps)
        self.assertEqual(release.integrity, ts.INTEGRITY)
        self.assertEqual(sleeps, [20, 20])

    def test_a_forbidden_dist_read_is_no_verdict(self):
        self.no_verdict("dist", routes=self.routes_answering((403, b"forbidden")))

    def test_every_unexpected_status_is_retried_and_ends_as_no_verdict(self):
        for status in (400, 401, 403, 408, 429, 500, 502, 503):
            with self.subTest(status):
                sleeps = []
                self.no_verdict("dist", routes=self.routes_answering((status, b"")), sleeps=sleeps)
                self.assertEqual(sleeps, [20, 20, 20, 20])

    def test_a_version_npm_never_serves_is_still_a_verdict(self):
        sleeps = []
        self.refused("dist", routes=self.routes_answering((404, b'"version not found"')), sleeps=sleeps)
        self.assertEqual(sleeps, [20, 20, 20, 20])

    def test_a_non_json_dist_body_is_no_verdict(self):
        for body in (b"<html>bad gateway</html>", b"", b"\xff\xfe", b'{"version": "0.9.14", "version": "0.9.14"}'):
            with self.subTest(body):
                self.no_verdict("dist", routes=self.routes_answering((200, body)))

    def test_a_dist_body_nested_too_deep_to_parse_is_no_verdict(self):
        self.no_verdict("dist", routes=self.routes_answering((200, b"[" * 200000)))

    def test_a_dist_body_that_is_not_an_object_is_no_verdict(self):
        for body in (b"[]", b'"text"', b"null", b"7"):
            with self.subTest(body):
                self.no_verdict("dist", routes=self.routes_answering((200, body)))

    def test_a_dist_document_without_a_dist_or_for_another_version_is_still_a_verdict(self):
        for doc in ({"version": VERSION}, {"version": "0.9.13", "dist": {}}, {"dist": {}}):
            with self.subTest(doc):
                self.refused("dist", routes=self.routes_answering((200, doc)))


def with_payload(out, payload):
    """A copy of an audit report whose SLSA bundle carries this raw payload (str or bytes)."""
    out = copy.deepcopy(out)
    raw = payload if isinstance(payload, bytes) else payload.encode()
    bundles = out["verified"][0]["attestationBundles"]
    next(b for b in bundles if b["predicateType"] == rc.SLSA)["bundle"]["dsseEnvelope"]["payload"] = (
        base64.b64encode(raw).decode()
    )
    return out


def with_statement_at(path, value, version=VERSION):
    """An audit report for `version` whose statement holds `value` at path (a tuple of keys)."""
    stmt = ts.statement(version)
    node = stmt
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return ts.audit_output(version, stmt)


class TestMalformedReports(ts.VerifyMixin, unittest.TestCase):
    """A report whose shape is wrong says npm misbehaved, not that the package is bad (no
    verdict); a statement whose shape is wrong is the publisher's, and is refused."""

    def report(self):
        return ts.audit_output(VERSION)

    def test_a_report_that_is_not_an_object_is_toolchain(self):
        for report in ([], "text", 7, None):
            with self.subTest(repr(report)):
                self.no_verdict("toolchain", audits=[report])

    def test_a_verified_list_that_is_not_a_list_of_objects_is_toolchain(self):
        for name, value in {
            "an object": {},
            "a string": "x",
            "a number": 5,
            "null": None,
            "a string item": ["x"],
            "a null item": [None],
            "a number item": [5],
        }.items():
            with self.subTest(name):
                out = self.report()
                out["verified"] = value
                self.no_verdict("toolchain", audits=[out])

    def test_attestation_bundles_that_are_not_a_list_of_objects_are_toolchain(self):
        for name, value in {
            "an object": {},
            "a string": "x",
            "a number": 5,
            "null": None,
            "a string item": ["x"],
            "a null item": [None],
        }.items():
            with self.subTest(name):
                out = self.report()
                out["verified"][0]["attestationBundles"] = value
                self.no_verdict("toolchain", audits=[out])

    def test_an_entry_without_attestation_bundles_is_toolchain(self):
        out = self.report()
        del out["verified"][0]["attestationBundles"]
        self.no_verdict("toolchain", audits=[out])

    def test_a_report_without_a_verified_list_is_toolchain_not_a_missing_attestation(self):
        # npm prints `verified` whenever it honours --include-attestations (npm 11.12 and
        # later). An older npm prints none, and that says nothing about the release.
        for name, out in {
            "no verified key": {"invalid": [], "missing": []},
            "the key dropped from a full report": {k: v for k, v in ts.audit_output(VERSION).items() if k != "verified"},
        }.items():
            with self.subTest(name):
                sleeps = []
                error = self.no_verdict("toolchain", audits=[out], sleeps=sleeps)
                self.assertIn("include-attestations", error.detail)
                self.assertIn("11.12", error.detail)
                self.assertEqual(sleeps, [], "a report npm cannot have meant is not waited out")

    def test_an_empty_verified_list_is_still_a_missing_attestation(self):
        sleeps = []
        error = self.refused("provenance", audits=[ts.audit_output(VERSION, verified=False)], sleeps=sleeps)
        self.assertIn("no VERIFIED attestation", error.detail)
        self.assertEqual(sleeps, [20, 20, 20, 20])

    def test_two_verified_entries_for_the_package_are_toolchain(self):
        out = self.report()
        out["verified"].append(copy.deepcopy(out["verified"][0]))
        self.no_verdict("toolchain", audits=[out])

    def test_other_packages_in_the_verified_list_are_ignored(self):
        out = self.report()
        out["verified"].insert(0, {"name": "left-pad", "version": VERSION, "attestationBundles": []})
        release, _ = self.verify(audits=[out])
        self.assertEqual(release.version, VERSION)

    def test_a_payload_that_is_not_an_object_is_refused(self):
        for payload in ("[]", '"text"', "null", "7", "true"):
            with self.subTest(payload):
                error = self.refused("provenance", audits=[with_payload(self.report(), payload)])
                self.assertIn("unreadable", error.detail)

    def test_a_payload_that_is_not_one_clean_json_document_is_refused(self):
        for name, payload in {
            "text": b"not json",
            "invalid UTF-8": b"\xff\xfe",
            "a duplicate key": b'{"subject": [], "subject": []}',
            "NaN": b'{"subject": NaN}',
            "nesting too deep to parse": b"[" * 200000,
        }.items():
            with self.subTest(name):
                error = self.refused("provenance", audits=[with_payload(self.report(), payload)])
                self.assertIn("unreadable", error.detail)

    def test_an_envelope_without_a_string_payload_is_refused(self):
        for name, envelope in {
            "no envelope": None,
            "an envelope that is a string": "x",
            "no payload": {"signatures": []},
            "a null payload": {"payload": None},
            "a numeric payload": {"payload": 5},
            "a list payload": {"payload": []},
        }.items():
            with self.subTest(name):
                out = self.report()
                bundles = out["verified"][0]["attestationBundles"]
                slsa = next(b for b in bundles if b["predicateType"] == rc.SLSA)["bundle"]
                if envelope is None:
                    del slsa["dsseEnvelope"]
                else:
                    slsa["dsseEnvelope"] = envelope
                error = self.refused("provenance", audits=[out])
                self.assertIn("unreadable", error.detail)

    def test_a_payload_that_is_not_strict_base64_is_refused(self):
        out = self.report()
        bundles = out["verified"][0]["attestationBundles"]
        slsa = next(b for b in bundles if b["predicateType"] == rc.SLSA)["bundle"]["dsseEnvelope"]
        good = slsa["payload"]
        for name, payload in {"a stray character": good[:40] + "!" + good[40:], "a line break": good[:40] + "\n" + good[40:]}.items():
            with self.subTest(name):
                slsa["payload"] = payload
                error = self.refused("provenance", audits=[out])
                self.assertIn("unreadable", error.detail)

    def test_a_statement_with_a_level_that_is_not_an_object_is_refused_not_a_crash(self):
        cases = {
            "predicate": (("predicate",), "x", "provenance"),
            "buildDefinition": (("predicate", "buildDefinition"), [], "provenance"),
            "externalParameters": (("predicate", "buildDefinition", "externalParameters"), "x", "provenance"),
            "workflow": (("predicate", "buildDefinition", "externalParameters", "workflow"), "x", "provenance"),
            "runDetails": (("predicate", "runDetails"), 5, "provenance"),
            "builder": (("predicate", "runDetails", "builder"), "x", "provenance"),
            "subject as a number": (("subject",), 5, "provenance"),
            "subject as a string": (("subject",), "x", "provenance"),
            "subject items": (("subject",), ["x", 5, None], "provenance"),
            "subject digest": (("subject",), [{"name": "x", "digest": "abc"}], "provenance"),
            "resolvedDependencies as a string": (("predicate", "buildDefinition", "resolvedDependencies"), "x", "attested-commit"),
            "resolvedDependencies as an object": (("predicate", "buildDefinition", "resolvedDependencies"), {}, "attested-commit"),
            "resolvedDependencies as a number": (("predicate", "buildDefinition", "resolvedDependencies"), 5, "attested-commit"),
            "a dependency that is not an object": (("predicate", "buildDefinition", "resolvedDependencies"), ["x"], "attested-commit"),
            "a dependency digest that is a string": (
                ("predicate", "buildDefinition", "resolvedDependencies"),
                [{"uri": f"git+{rc.PROV_REPO}@refs/tags/plugin-claude-v{VERSION}", "digest": "abc"}],
                "attested-commit",
            ),
            "metadata": (("predicate", "runDetails", "metadata"), "x", "run-url"),
        }
        for name, (path, value, check) in cases.items():
            with self.subTest(name):
                self.refused(check, audits=[with_statement_at(path, value)])


if __name__ == "__main__":
    unittest.main()
