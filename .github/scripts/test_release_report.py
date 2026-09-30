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


if __name__ == "__main__":
    unittest.main()
