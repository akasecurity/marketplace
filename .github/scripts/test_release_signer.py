"""Who signed a release. npm verifies the Sigstore certificate in a provenance bundle;
release_checks reads which workflow that certificate names, with the standard library, and
refuses a release unless it is ai-tc's release workflow at the version's own tag."""

from __future__ import annotations

import base64
import pathlib
import re
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


def name_carriers(*names):
    """Extensions that are not the subject alternative name, each holding in its value the
    encoding of one: {where: (extension, the bytes it holds)}. The whole extension, OID and
    all, and the bare names are the two shapes a reader that searched the certificate for a
    name, instead of walking to the one extension that holds it, would pick up. The OIDs are
    ones a leaf from ts.leaf_extensions does not already carry."""
    whole = ts.san_extension(*names)
    bare = ts.der(0x30, b"".join(names))
    return {
        "basic constraints": (ts.extension("2.5.29.19", whole, critical=True), whole),
        "extended key usage": (ts.extension("2.5.29.37", whole), whole),
        "an unassigned Fulcio arc": (ts.extension(ts.FULCIO + "98", whole), whole),
        "an unassigned Fulcio arc, in a list of extensions": (
            ts.extension(ts.FULCIO + "98", ts.der(0x30, whole)),
            whole,
        ),
        "an unassigned Fulcio arc, as the bare names": (ts.extension(ts.FULCIO + "97", bare), bare),
    }


def hiding_places(extensions, *names):
    """{where and in what position: (certificate, the bytes hidden in it)}: a certificate
    with these extensions and one more that holds the encoding of `names`, put before the
    others and after them."""
    places = {}
    for where, (carrier, hidden) in name_carriers(*names).items():
        places[f"{where}, first"] = (ts.der_cert([carrier, *extensions]), hidden)
        places[f"{where}, last"] = (ts.der_cert([*extensions, carrier]), hidden)
    return places


class TestNameInAnotherExtension(ts.VerifyMixin, unittest.TestCase):
    """The name is whatever the extension with OID 2.5.29.17 holds, and nothing else in the
    certificate is read for it, even bytes that are exactly that extension."""

    def test_a_name_in_another_extension_does_not_stand_in_for_a_missing_one(self):
        right = ts.san_uri(workflow_uri())
        places = hiding_places(ts.leaf_extensions(VERSION, san=None), right)
        self.assertEqual(len(places), 10)
        for name, (cert, hidden) in places.items():
            with self.subTest(name):
                self.assertIn(hidden, cert)
                with self.assertRaises(rc._CertError) as caught:
                    rc.signer_identity(cert)
                self.assertIn("does not carry certificate subject alternative name", str(caught.exception))
                error = self.refused("provenance", audits=[ts.audit_output(VERSION, cert=cert)])
                self.assertIn("signing certificate is unreadable", error.detail)
                self.assertIn("does not carry certificate subject alternative name", error.detail)

    def test_a_name_in_another_extension_does_not_replace_a_different_real_one(self):
        right = ts.san_uri(workflow_uri())
        for real_name, real in {
            "another versions tag": workflow_uri("0.9.13"),
            "another repository": workflow_uri(repository=OTHER),
        }.items():
            for name, (cert, hidden) in hiding_places(ts.leaf_extensions(VERSION, san=real), right).items():
                with self.subTest(f"{real_name}; {name}"):
                    self.assertIn(hidden, cert)
                    self.assertEqual(rc.signer_identity(cert)["san"], real)
                    error = self.refused("provenance", audits=[ts.audit_output(VERSION, cert=cert)])
                    self.assertIn("certificate subject alternative name", error.detail)
                    self.assertIn(real, error.detail)

    def test_the_real_extension_with_the_right_name_is_accepted_whatever_another_holds(self):
        wrong = ts.san_uri(workflow_uri(repository=OTHER))
        for hidden_name, names in {
            "someone else's workflow": (wrong,),
            "two names": (wrong, wrong),
            "a name that is not a URI": (ts.der(0x82, b"example.com"),),
        }.items():
            for name, (cert, hidden) in hiding_places(ts.leaf_extensions(VERSION), *names).items():
                with self.subTest(f"{hidden_name}; {name}"):
                    self.assertIn(hidden, cert)
                    self.assertEqual(rc.signer_identity(cert)["san"], workflow_uri())
                    release, _ = self.verify(audits=[ts.audit_output(VERSION, cert=cert)])
                    self.assertEqual(release.git_commit, ts.ATTESTED[VERSION])


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

    def branch_cert(self, branch="refs/heads/main", **overrides):
        """A certificate for ai-tc's release workflow dispatched on a branch, as an older copy
        of the workflow could be."""
        uri = f"{AI_TC}/{ts.WORKFLOW}@{branch}"
        fields = {"san": uri, "build_signer": uri, "build_config": uri, "ref": branch, "trigger": "workflow_dispatch"}
        fields.update(overrides)
        return ts.signing_cert(VERSION, **fields)

    def test_off_tag_text_names_only_a_ref_difference(self):
        ref = "refs/heads/main"
        audits = [ts.audit_output(VERSION, ts.statement(VERSION, ref=ref), cert=self.branch_cert(ref))]
        error = self.refused("provenance", audits=audits)
        self.assertIn(ref, error.detail)
        self.assertIn(f"refs/tags/plugin-claude-v{VERSION}", error.detail)
        ts.assert_off_tag_text_is_truthful(self, error.detail)
        self.assertIn("only from a tag push", error.detail)
        self.assertIn("maintainers", error.detail)
        self.assertNotIn("anyone can publish", error.detail)

    def test_an_off_tag_publish_is_described_by_the_trigger_the_certificate_records(self):
        # The certificate carries how the run began. A dispatch and a push are different
        # facts for ai-tc's maintainers, so the text may say only the one that happened.
        ref = "refs/heads/release-hotfix"
        for trigger, said, unsaid in (
            ("workflow_dispatch", "dispatched on a branch", "pushed on"),
            ("push", "pushed on that branch", "dispatched"),
        ):
            with self.subTest(trigger):
                cert = self.branch_cert(ref, trigger=trigger)
                error = self.refused("provenance", audits=[ts.audit_output(VERSION, ts.statement(VERSION, ref=ref), cert=cert)])
                self.assertIn(ref, error.detail)
                self.assertIn("only from a tag push", error.detail)
                ts.assert_off_tag_text_is_truthful(self, error.detail)
                self.assertIn("maintainers", error.detail)
                self.assertIn(said, error.detail)
                self.assertNotIn(unsaid, error.detail)

    def test_an_off_tag_publish_from_a_trigger_the_text_does_not_know_is_not_described(self):
        ref = "refs/heads/main"
        for trigger in ("schedule", "workflow_run", "pull_request_target"):
            with self.subTest(trigger):
                cert = self.branch_cert(ref, trigger=trigger)
                error = self.refused("provenance", audits=[ts.audit_output(VERSION, ts.statement(VERSION, ref=ref), cert=cert)])
                self.assertNotIn("dispatched", error.detail)
                self.assertNotIn("pushed on", error.detail)
                self.assertNotIn("stolen", error.detail)
                self.assertIn("anyone can publish with provenance", error.detail)

    def test_an_off_tag_publish_that_is_also_something_else_is_not_excused(self):
        ref = "refs/heads/main"
        cases = {
            "a self-hosted runner": {"runner": "self-hosted"},
            "another issuer": {"issuer": "https://example.com"},
            "another repository id": {"repository_id": "1"},
            "another owner id": {"owner_id": "2"},
            "another source repository": {"repository": OTHER},
        }
        for name, overrides in cases.items():
            with self.subTest(name):
                cert = self.branch_cert(ref, **overrides)
                error = self.refused("provenance", audits=[ts.audit_output(VERSION, ts.statement(VERSION, ref=ref), cert=cert)])
                self.assertNotIn("stolen", error.detail)
                self.assertIn("anyone can publish with provenance", error.detail)

    def test_an_off_tag_publish_whose_certificate_is_not_consistent_is_not_excused(self):
        ref = "refs/heads/main"
        audits_for = lambda cert: [ts.audit_output(VERSION, ts.statement(VERSION, ref=ref), cert=cert)]
        for name, cert in {
            "a subject alternative name on another branch": self.branch_cert(ref, san=f"{AI_TC}/{ts.WORKFLOW}@refs/heads/other"),
            "a build signer on another workflow": self.branch_cert(ref, build_signer=f"{AI_TC}/.github/workflows/x.yml@{ref}"),
            "a source ref that is a tag": self.branch_cert(ref, ref=f"refs/tags/plugin-claude-v{VERSION}"),
        }.items():
            with self.subTest(name):
                error = self.refused("provenance", audits=audits_for(cert))
                self.assertNotIn("stolen", error.detail)

    def test_an_off_tag_publish_the_statement_contradicts_is_not_excused(self):
        # The certificate says branch; the statement still claims the tag.
        error = self.refused("provenance", audits=[ts.audit_output(VERSION, cert=self.branch_cert())])
        self.assertNotIn("stolen", error.detail)

    def test_a_tag_that_is_not_the_versions_is_not_called_off_tag(self):
        for name, overrides in {
            "another versions tag": {"ref": "refs/tags/plugin-claude-v0.9.13", "san": workflow_uri("0.9.13")},
            "a dispatch on the tag": {"trigger": "workflow_dispatch"},
        }.items():
            with self.subTest(name):
                cert = ts.signing_cert(VERSION, **overrides)
                error = self.refused("provenance", audits=[ts.audit_output(VERSION, cert=cert)])
                self.assertNotIn("stolen", error.detail)
                self.assertNotIn("branch", error.detail)

    def test_a_builder_that_only_contains_github_hosted_is_refused(self):
        # The certificate is fine; the statement's builder id must be GitHub's exactly.
        for builder in (
            "https://evil.example/not-github-hosted",
            "https://github.com/actions/runner/github-hosted-extra",
            "https://github.com/actions/runner/self-hosted/github-hosted",
            "github-hosted",
            "",
        ):
            with self.subTest(builder):
                stmt = ts.statement(VERSION, builder=builder)
                error = self.refused("provenance", audits=[ts.audit_output(VERSION, stmt)])
                self.assertIn("disagrees with the certificate", error.detail)
                self.assertIn("builder", error.detail)

    def test_a_statement_with_no_builder_is_refused(self):
        stmt = ts.statement(VERSION)
        del stmt["predicate"]["runDetails"]["builder"]
        self.refused("provenance", audits=[ts.audit_output(VERSION, stmt)])

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


class TestRetiredWording(unittest.TestCase):
    def test_nothing_that_runs_says_a_branch_publish_is_not_a_stolen_credential(self):
        # A certificate naming ai-tc's workflow rules out an npm token alone, not a stolen
        # GitHub credential with write access to ai-tc. Neither the script nor a workflow may
        # say otherwise, in any of the places the text has been written.
        root = pathlib.Path(__file__).resolve().parents[2]
        runs = [root / ".github/scripts/release_checks.py", *sorted((root / ".github/workflows").glob("*.yml"))]
        self.assertGreater(len(runs), 1)
        for path in runs:
            # Strings broken over lines are joined first, so a claim split across them is found.
            text = re.sub(r'["\s]+', " ", path.read_text(encoding="utf-8")).lower()
            for retired in ("not a stolen npm credential", "not a stolen-token signal", "not a stolen token"):
                with self.subTest(f"{path.name}: {retired}"):
                    self.assertNotIn(retired, text)


if __name__ == "__main__":
    unittest.main()
