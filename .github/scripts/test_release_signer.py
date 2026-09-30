"""Who signed a release. npm verifies the Sigstore certificate in a provenance bundle;
release_checks reads which workflow that certificate names, with the standard library, and
refuses a release unless it is ai-tc's release workflow at the version's own tag."""

from __future__ import annotations

import base64
import unittest

import _testsupport as ts
import release_checks as rc

VERSION = "0.9.14"
AI_TC = "https://github.com/akasecurity/ai-tc"
OTHER = "https://github.com/someone/ai-tc"


def real_leaf():
    return base64.b64decode(ts.REAL_LEAF_0_9_14)


def workflow_uri(version=VERSION, repository=AI_TC, path=ts.WORKFLOW):
    return f"{repository}/{path}@refs/tags/plugin-claude-v{version}"


class TestSignerIdentity(unittest.TestCase):
    def test_the_real_0_9_14_leaf_names_ai_tcs_release_workflow_at_its_tag(self):
        # Pins every constant release_checks requires to a release that really happened.
        signer = rc.signer_identity(real_leaf())
        for name, value in rc.required_signer(VERSION).items():
            self.assertEqual(signer[name], value, name)
        self.assertEqual(signer["san"], workflow_uri())
        self.assertEqual((signer["repository_id"], signer["owner_id"]), ("1296880286", "300515195"))
        self.assertEqual((signer["commit"], signer["run_url"]), (ts.ATTESTED[VERSION], ts.RUN_URL))

    def test_the_fixture_certificate_reads_back_as_the_real_one_does(self):
        self.assertEqual(rc.signer_identity(ts.signing_cert(VERSION)), rc.signer_identity(real_leaf()))

    def test_extensions_the_checks_do_not_read_are_skipped_unread(self):
        # The fixture carries key usage, the deprecated raw-string Fulcio OIDs (holding bytes
        # that are not UTF-8), a future Fulcio arc and an SCT list. None is read, so a new
        # Fulcio OID cannot break the reader.
        self.assertEqual(
            set(rc.signer_identity(ts.signing_cert(VERSION))),
            {"san", *ts.LEAF_ARCS},
        )

    def test_the_required_signer_follows_the_version(self):
        required = rc.required_signer("0.9.13")
        self.assertEqual(required["san"], workflow_uri("0.9.13"))
        self.assertEqual(required["ref"], "refs/tags/plugin-claude-v0.9.13")
        self.assertEqual(required["trigger"], "push")
        self.assertNotIn("commit", required)
        self.assertNotIn("run_url", required)


def unreadable_certificates():
    """Certificates the reader must refuse: {what is wrong: (DER, what the refusal says)}."""
    good = ts.leaf_extensions(VERSION)
    leaf = real_leaf()
    uri = ts.san_uri(workflow_uri())
    no_san = ts.leaf_extensions(VERSION, san=None)
    no_repository = ts.leaf_extensions(VERSION, repository=None)
    wrong = ts.der(0x30, ts.der_oid("2.5.29.19"))
    return {
        "empty": (b"", "truncated element"),
        "truncated": (leaf[:-1], "overruns its parent"),
        "trailing byte": (leaf + b"\x00", "not exactly one certificate SEQUENCE"),
        "indefinite length": (b"\x30\x80" + ts.signing_cert(VERSION)[4:] + b"\x00\x00", "indefinite length"),
        "nested indefinite length": (
            ts.der_cert([ts.der(0x30, ts.der_oid("2.5.29.19") + ts.der(0x04, b""))]).replace(
                b"\x30\x0a\x06", b"\x30\x80\x06", 1
            ),
            "indefinite length",
        ),
        "non-minimal length": (leaf[:1] + b"\x83\x00" + leaf[2:], "length not minimal"),
        "length over four bytes": (b"\x30\x85\x00\x00\x00\x00\x01\x00", "length over four bytes"),
        "high tag number": (b"\x1f\x01\x00", "high tag number form"),
        "not a sequence": (b"\x31" + leaf[1:], "not exactly one certificate SEQUENCE"),
        "no tbs, algorithm and signature": (ts.der(0x30, b""), "a tbsCertificate, an algorithm and a signature"),
        "no extensions": (
            ts.der(0x30, ts.der(0x30, ts.der(0x02, b"\x01")) + ts.der(0x30, b"") + ts.der(0x03, b"\x00")),
            "no extensions field",
        ),
        "two extension lists": (
            ts.der(0x30, ts.der(0x30, ts.der(0xA3, ts.der(0x30, b"") * 2)) + ts.der(0x30, b"") + ts.der(0x03, b"\x00")),
            "extensions field is not one SEQUENCE",
        ),
        "duplicate extension": (
            ts.der_cert([*good, ts.fulcio_extension("8", ts.leaf_fields(VERSION)["issuer"])]),
            "appears twice",
        ),
        "two subject alternative names": (
            ts.der_cert([*no_san, ts.san_extension(uri, uri)]),
            "not exactly one URI",
        ),
        "a name that is not a URI": (
            ts.der_cert([*no_san, ts.san_extension(ts.der(0x82, b"example.com"))]),
            "not exactly one URI",
        ),
        "a URI that is not printable": (
            ts.der_cert([*no_san, ts.san_extension(ts.der(0x86, b"https://a b"))]),
            "not printable ASCII",
        ),
        "a subject alternative name that is not a sequence": (
            ts.der_cert([*no_san, ts.extension(ts.SAN_OID, ts.der(0x31, uri))]),
            "not one SEQUENCE",
        ),
        "no subject alternative name": (ts.signing_cert(VERSION, san=None), "does not carry certificate subject alternative name"),
        "a required field missing": (ts.signing_cert(VERSION, commit=None), "does not carry certificate source repository digest"),
        "a field not a UTF8String": (
            ts.der_cert([*no_repository, ts.fulcio_extension("12", AI_TC, tag=0x13)]),
            "not exactly one UTF8String",
        ),
        "a field holding two strings": (
            ts.der_cert([*no_repository, ts.extension(ts.FULCIO + "12", ts.der(0x0C, b"a") + ts.der(0x0C, b"b"))]),
            "not exactly one UTF8String",
        ),
        "a field that is not UTF-8": (
            ts.der_cert([*no_repository, ts.extension(ts.FULCIO + "12", ts.der(0x0C, b"\xff"))]),
            "is not UTF-8",
        ),
        "an extension that is not a sequence": (ts.der_cert([*good, ts.der(0x04, b"x")]), "is not a SEQUENCE"),
        "an extension with no value": (ts.der_cert([*good, wrong]), "an OID, an optional flag and an OCTET STRING"),
        "a critical flag that is not a boolean": (
            ts.der_cert([*good, ts.der(0x30, ts.der_oid("2.5.29.19") + ts.der(0x02, b"\x01") + ts.der(0x04, b""))]),
            "critical flag is not a BOOLEAN",
        ),
        "an OID that is not minimal": (
            ts.der_cert([*good, ts.der(0x30, ts.der(0x06, b"\x80\x01") + ts.der(0x04, b""))]),
            "OID arc not minimal",
        ),
        "an OID that does not end": (
            ts.der_cert([*good, ts.der(0x30, ts.der(0x06, b"\x2a\x81") + ts.der(0x04, b""))]),
            "malformed OID",
        ),
        "an empty OID": (ts.der_cert([*good, ts.der(0x30, ts.der(0x06, b"") + ts.der(0x04, b""))]), "malformed OID"),
    }


def unreadable_materials():
    """verificationMaterial the reader must refuse: {what is wrong: (material, what the
    refusal says)}. The right shape is exactly one certificate."""
    raw = ts.REAL_LEAF_0_9_14
    return {
        "a public key": ({"publicKey": {"hint": "x"}}, "holds ['publicKey']"),
        "nothing": ({}, "holds nothing"),
        "not an object": ([], "no verification material"),
        "a certificate and a chain": (
            {"certificate": {"rawBytes": raw}, "x509CertificateChain": {"certificates": [{"rawBytes": raw}]}},
            "holds ['certificate', 'x509CertificateChain']",
        ),
        "a certificate and a public key": (
            {"certificate": {"rawBytes": raw}, "publicKey": {"hint": "x"}},
            "holds ['certificate', 'publicKey']",
        ),
        "rawBytes that is not base64": ({"certificate": {"rawBytes": "not base64!!"}}, "is not base64"),
        "rawBytes with a stray character": ({"certificate": {"rawBytes": raw[:100] + "!" + raw[100:]}}, "is not base64"),
        "rawBytes with a line break": ({"certificate": {"rawBytes": raw[:100] + "\n" + raw[100:]}}, "is not base64"),
        "rawBytes that is not a string": ({"certificate": {"rawBytes": 5}}, "no rawBytes"),
        "no rawBytes": ({"certificate": {}}, "no rawBytes"),
        "an empty chain": ({"x509CertificateChain": {"certificates": []}}, "no rawBytes"),
        "a chain that is not a list": ({"x509CertificateChain": {"certificates": "x"}}, "no rawBytes"),
    }


class TestUnreadableCertificates(ts.VerifyMixin, unittest.TestCase):
    def test_each_malformed_certificate_is_refused_by_the_reader_for_its_own_reason(self):
        for name, (der, reason) in unreadable_certificates().items():
            with self.subTest(name):
                with self.assertRaises(rc._CertError) as caught:
                    rc.signer_identity(der)
                self.assertIn(reason, str(caught.exception))

    def test_each_malformed_certificate_is_a_provenance_verdict_and_nothing_else(self):
        for name, (der, reason) in unreadable_certificates().items():
            with self.subTest(name):
                error = self.refused("provenance", audits=[ts.audit_output(VERSION, cert=der)])
                self.assertIn("signing certificate is unreadable", error.detail)
                self.assertIn(reason, error.detail)

    def test_each_malformed_verification_material_is_refused_by_the_reader_for_its_own_reason(self):
        for name, (material, reason) in unreadable_materials().items():
            with self.subTest(name):
                with self.assertRaises(rc._CertError) as caught:
                    rc._leaf_der({"verificationMaterial": material})
                self.assertIn(reason, str(caught.exception))

    def test_each_malformed_verification_material_is_a_provenance_verdict(self):
        for name, (material, reason) in unreadable_materials().items():
            with self.subTest(name):
                error = self.refused("provenance", audits=[ts.audit_output(VERSION, material=material)])
                self.assertIn("signing certificate is unreadable", error.detail)
                self.assertIn(reason, error.detail)

    def test_a_bundle_with_no_material_key_is_refused_by_the_reader(self):
        for bundle in ({}, None, []):
            with self.subTest(repr(bundle)):
                with self.assertRaises(rc._CertError):
                    rc._leaf_der(bundle)

    def test_a_damaged_leaf_is_refused_or_read_and_never_crashes(self):
        # Whatever is done to the real leaf, only the reader's own error may come out.
        leaf = real_leaf()
        damaged = [leaf[:n] for n in range(len(leaf))]
        damaged += [leaf[:i] + bytes([leaf[i] ^ 0xFF]) + leaf[i + 1 :] for i in range(len(leaf))]
        damaged += [leaf[:i] + leaf[i + 1 :] for i in range(0, len(leaf), 5)]
        damaged += [leaf[:i] + b"\x00\x30\x80" + leaf[i:] for i in range(0, len(leaf), 97)]
        for blob in damaged:
            try:
                rc.signer_identity(blob)
            except rc._CertError:
                pass


class TestSignerBinding(ts.VerifyMixin, unittest.TestCase):
    def test_a_release_signed_by_the_real_certificate_passes(self):
        release, _ = self.verify(audits=[ts.audit_output(VERSION, cert=real_leaf())])
        self.assertEqual(
            release, rc.VerifiedRelease(VERSION, ts.INTEGRITY, ts.SHASUM, ts.ATTESTED[VERSION], ts.RUN_URL)
        )

    def test_a_body_claiming_ai_tc_under_another_identity_is_refused(self):
        # The statement is the publisher's own words. The certificate says who signed.
        uri = workflow_uri(repository=OTHER)
        cert = ts.signing_cert(
            VERSION, san=uri, build_signer=uri, build_config=uri, repository=OTHER, repository_id="4242"
        )
        error = self.refused("provenance", audits=[ts.audit_output(VERSION, cert=cert)])
        self.assertIn("anyone can publish with provenance", error.detail)
        for mentioned in (OTHER, "4242", "1296880286"):
            self.assertIn(mentioned, error.detail)

    def test_each_identity_the_certificate_does_not_have_is_refused(self):
        uri = workflow_uri(path=".github/workflows/other.yml")
        cases = {
            "another OIDC issuer": ({"issuer": "https://example.com"}, "OIDC issuer"),
            "a self-hosted runner": ({"runner": "self-hosted"}, "runner environment"),
            "another versions tag": (
                {
                    "san": workflow_uri("0.9.13"),
                    "build_signer": workflow_uri("0.9.13"),
                    "build_config": workflow_uri("0.9.13"),
                    "ref": "refs/tags/plugin-claude-v0.9.13",
                },
                "source repository ref",
            ),
            "a dispatch on the tag": ({"trigger": "workflow_dispatch"}, "build trigger"),
            "another subject alternative name": ({"san": workflow_uri("0.9.13")}, "subject alternative name"),
            "another source repository": ({"repository": OTHER}, "source repository URI"),
            "a source ref of another tag": ({"ref": "refs/tags/plugin-claude-v0.9.13"}, "source repository ref"),
            "a re-created repository": ({"repository_id": "1"}, "source repository id"),
            "another owner": ({"owner_id": "2"}, "source repository owner id"),
            "another workflow": ({"san": uri, "build_signer": uri, "build_config": uri}, "subject alternative name"),
            "another build signer": ({"build_signer": workflow_uri("0.9.13")}, "build signer"),
            "another build config": ({"build_config": workflow_uri("0.9.13")}, "build config"),
        }
        for name, (overrides, mentioned) in cases.items():
            with self.subTest(name):
                cert = ts.signing_cert(VERSION, **overrides)
                error = self.refused("provenance", audits=[ts.audit_output(VERSION, cert=cert)])
                self.assertIn(mentioned, error.detail)

    def test_the_commit_checked_against_main_is_the_certificates(self):
        # A body that names a commit of main while the certificate names the unmerged commit
        # the workflow really ran at.
        unmerged = "d" * 40
        cert = ts.signing_cert(VERSION, commit=unmerged)
        error = self.refused("attested-commit", audits=[ts.audit_output(VERSION, cert=cert)])
        self.assertIn(unmerged, error.detail)

    def test_the_commit_the_certificate_and_the_statement_agree_on_is_the_one_compared(self):
        commit = "d" * 40
        routes = ts.release_routes(VERSION, commit=commit)
        audits = [ts.audit_output(VERSION, ts.statement(VERSION, commit=commit), cert=ts.signing_cert(VERSION, commit=commit))]
        release, fetch = self.verify(routes=routes, audits=audits)
        self.assertEqual(release.git_commit, commit)
        self.assertIn(ts.compare_url(commit), fetch.urls())
        self.assertNotIn(ts.compare_url(ts.ATTESTED[VERSION]), fetch.urls())

    def test_a_run_url_the_certificate_does_not_name_is_refused(self):
        other_run = "https://github.com/akasecurity/ai-tc/actions/runs/1/attempts/1"
        self.refused("run-url", audits=[ts.audit_output(VERSION, cert=ts.signing_cert(VERSION, run_url=other_run))])

    def test_a_run_url_that_is_not_an_ai_tc_run_is_refused(self):
        foreign = "https://example.com/actions/runs/1"
        cert = ts.signing_cert(VERSION, run_url=foreign)
        self.refused("run-url", audits=[ts.audit_output(VERSION, ts.statement(VERSION, run_url=foreign), cert=cert)])

    def test_a_statement_that_contradicts_its_signer_is_refused(self):
        for name, overrides in {
            "repository": {"repository": OTHER},
            "workflow path": {"path": ".github/workflows/other.yml"},
            "ref": {"ref": "refs/tags/plugin-claude-v0.9.13"},
        }.items():
            with self.subTest(name):
                stmt = ts.statement(VERSION, **overrides)
                error = self.refused("provenance", audits=[ts.audit_output(VERSION, stmt)])
                self.assertIn("disagrees with the certificate", error.detail)

    def test_two_slsa_bundles_are_refused(self):
        out = ts.audit_output(VERSION)
        bundles = out["verified"][0]["attestationBundles"]
        bundles.append(bundles[-1])
        error = self.refused("provenance", audits=[out])
        self.assertIn("exactly one", error.detail)

    def test_the_chain_form_is_read_as_sigstore_reads_it(self):
        # x509CertificateChain.certificates[0] is the leaf; the rest is not read.
        chain = {"certificates": [{"rawBytes": ts.REAL_LEAF_0_9_14}, {"rawBytes": "AAAA"}]}
        release, _ = self.verify(audits=[ts.audit_output(VERSION, material={"x509CertificateChain": chain})])
        self.assertEqual(release.git_commit, ts.ATTESTED[VERSION])
        stranger = ts.signing_cert(VERSION, repository=OTHER)
        chain = {"certificates": [{"rawBytes": base64.b64encode(stranger).decode()}, {"rawBytes": ts.REAL_LEAF_0_9_14}]}
        self.refused("provenance", audits=[ts.audit_output(VERSION, material={"x509CertificateChain": chain})])


if __name__ == "__main__":
    unittest.main()
