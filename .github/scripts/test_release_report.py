"""What the release checks do with the registry's answers and with npm's audit report:
the registry signature, a throttled or garbled registry read, and a report whose shape
is not one npm prints."""

from __future__ import annotations

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

    def test_a_dist_body_that_is_not_an_object_is_no_verdict(self):
        for body in (b"[]", b'"text"', b"null", b"7"):
            with self.subTest(body):
                self.no_verdict("dist", routes=self.routes_answering((200, body)))

    def test_a_dist_document_without_a_dist_or_for_another_version_is_still_a_verdict(self):
        for doc in ({"version": VERSION}, {"version": "0.9.13", "dist": {}}, {"dist": {}}):
            with self.subTest(doc):
                self.refused("dist", routes=self.routes_answering((200, doc)))


if __name__ == "__main__":
    unittest.main()
