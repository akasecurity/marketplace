"""Fixtures shared by the .github/scripts tests. Not a test module (no test_ prefix)."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import tempfile

import release_checks as rc

# A fake tarball whose sha512 is the integrity every fake registry read returns, so a
# statement built by statement() binds unless a test changes one side.
TARBALL = b"ai-tc-claude-code test tarball"
INTEGRITY = "sha512-" + base64.b64encode(hashlib.sha512(TARBALL).digest()).decode()
SHA512_HEX = hashlib.sha512(TARBALL).hexdigest()
SHASUM = hashlib.sha1(TARBALL).hexdigest()
OTHER_INTEGRITY = "sha512-" + base64.b64encode(hashlib.sha512(b"other bytes").digest()).decode()

# Real values, read from npmjs and akasecurity/ai-tc on 2026-09-29 (0.9.15's on 2026-10-02).
REAL_INTEGRITY_0_9_14 = (
    "sha512-jdUG6HKR+SdhBi0+7jguLGuGjtFOkxLpTJu3/zBZ3wpN+t9XckzykjzV37YVhWBiQjGDGz8BbMquDwajG4rb7Q=="
)
ATTESTED = {
    "0.9.8": "94cc75d98b26a0e998929e49e56dc6790c19e222",
    "0.9.9": "2ff9a50d899d3820a3718f9e086dc281d4fa1d86",
    "0.9.10": "ec81a843b0eb500000eff4cf3d29863b481ad01f",
    "0.9.11": "5b51163cf21dc40a010bb945b90b66b83c559cdf",
    "0.9.12": "1d69b0e82602a64da4bc8aee0c48916774e65f15",
    "0.9.13": "1cef4ad151acee9a6d6df745060378b75a744262",
    "0.9.14": "a75532b98a70546d3825cbc237769aefe4dcc074",
    "0.9.15": "b65d0ab867e7827e21d0532ae2e1845885933449",
}
RUN_URL = "https://github.com/akasecurity/ai-tc/actions/runs/36005098741/attempts/1"
WORKFLOW = ".github/workflows/release-plugin-claude.yml"
DESCRIPTION = "AI Traffic Control (ai-tc) — an open-source control plane for coding agents."

PREFLIGHT = {
    "name": "preflight",
    "source": {"source": "github", "repo": "akasecurity/preflight-skills"},
    "description": "An independent multi-model review crew for coding agents.",
}
CLAUDE_TOOLS = {
    "name": "claude-tools",
    "source": {
        "source": "git-subdir",
        "url": "https://github.com/akasecurity/claude-tools.git",
        "path": "plugins/claude-tools",
    },
    "description": "Guard hooks that block pipe-to-shell and catch secrets.",
}
AGENTS_MANIFEST = {
    "name": "akasecurity",
    "interface": {"displayName": "AKA Security"},
    "plugins": [
        {
            "name": "preflight",
            "source": {"source": "url", "url": "https://github.com/akasecurity/preflight-skills.git"},
        }
    ],
}
PLUGINS_INDEX = {
    "name": "akasecurity-marketplace",
    "version": "0.1.0",
    "plugins": [{"name": "preflight"}, {"name": "claude-tools"}, {"name": "ai-tc"}],
}


def migrations(*numbers):
    """Migration tags for unit fixtures: the journal's number with a neutral name."""
    return [f"{n:04d}_migration" for n in numbers]


# rollback-safety.json as the seed computes it: every version main or a fleet-v tag pins
# from 0.9.9 to 0.9.14 (0.9.11 is pinned by neither, so it has no entry). The committed
# file carries ai-tc's real migration names; tests compare their journal numbers.
SEED = {
    "0.9.9": {
        "classification": "not-rollback-safe",
        "from": ATTESTED["0.9.8"],
        "to": ATTESTED["0.9.9"],
        "migrations": migrations(22),
    },
    "0.9.10": {
        "classification": "not-rollback-safe",
        "from": ATTESTED["0.9.9"],
        "to": ATTESTED["0.9.10"],
        "migrations": migrations(23, 24, 25, 26, 27, 28),
    },
    "0.9.12": {
        "classification": "not-rollback-safe",
        "from": ATTESTED["0.9.10"],
        "to": ATTESTED["0.9.12"],
        "migrations": migrations(29, 30, 31, 32, 33, 34),
    },
    "0.9.13": {
        "classification": "additive",
        "from": ATTESTED["0.9.12"],
        "to": ATTESTED["0.9.13"],
        "migrations": [],
    },
    "0.9.14": {
        "classification": "not-rollback-safe",
        "from": ATTESTED["0.9.13"],
        "to": ATTESTED["0.9.14"],
        "migrations": migrations(35),
    },
}

# What main and each fleet-v tag pinned on 2026-09-29.
PINS = {
    "main": "0.9.14",
    "fleet-v1": None,
    "fleet-v2": "0.9.6",
    "fleet-v3": "0.9.8",
    "fleet-v4": "0.9.9",
    "fleet-v5": "0.9.10",
    "fleet-v6": "0.9.12",
    "fleet-v7": "0.9.13",
    "fleet-v8": "0.9.14",
}


def manifest(version="0.9.14", *, integrity=INTEGRITY, registry=True, description=DESCRIPTION):
    """The Claude Code manifest as main holds it once the registry and integrity are seeded.
    integrity=None leaves the entry without metadata (main before the seed)."""
    source = {"source": "npm", "package": rc.PACKAGE, "version": version}
    if registry:
        source["registry"] = rc.REGISTRY
    entry = {"name": "ai-tc", "source": source, "description": description}
    if integrity is not None:
        entry["metadata"] = {"integrity": integrity}
    return {
        "name": "akasecurity",
        "owner": {"name": "AKA Security", "url": "https://github.com/akasecurity"},
        "metadata": {"description": "AKA Security tools for coding agents", "version": "0.1.0"},
        "plugins": [copy.deepcopy(PREFLIGHT), copy.deepcopy(CLAUDE_TOOLS), entry],
    }


def ai_tc(doc):
    return rc.select_ai_tc_entry(doc)


def statement(
    version,
    *,
    ref=None,
    repository=rc.PROV_REPO,
    path=WORKFLOW,
    builder="https://github.com/actions/runner/github-hosted",
    sha512=SHA512_HEX,
    commit=None,
    dependency_uri=None,
    run_url=RUN_URL,
):
    """An in-toto SLSA statement shaped like the ones npm serves for ai-tc releases."""
    tag_ref = f"refs/tags/plugin-claude-v{version}"
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": f"pkg:npm/%40akasecurity/ai-tc-claude-code@{version}", "digest": {"sha512": sha512}}
        ],
        "predicateType": rc.SLSA,
        "predicate": {
            "buildDefinition": {
                "externalParameters": {
                    "workflow": {"ref": ref or tag_ref, "repository": repository, "path": path}
                },
                "resolvedDependencies": [
                    {
                        "uri": dependency_uri or f"git+{rc.PROV_REPO}@{tag_ref}",
                        "digest": {"gitCommit": commit or ATTESTED.get(version, "c" * 40)},
                    }
                ],
            },
            "runDetails": {"builder": {"id": builder}, "metadata": {"invocationId": run_url}},
        },
    }


# --- Signing-certificate fixtures -------------------------------------------------------
# release_checks reads WHO signed a release from the Sigstore leaf certificate in the
# provenance bundle. The unit tests never verify a signature (npm does that), so this is a
# minimal DER encoder: a structurally valid certificate with a dummy signature.

FULCIO = "1.3.6.1.4.1.57264.1."
SAN_OID = "2.5.29.17"
PUBLISH = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
PUBLISH_KEYID = "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U"

# The leaf certificate of the real 0.9.14 provenance bundle (verificationMaterial.certificate
# .rawBytes), as npmjs served it on 2026-09-30 from
# https://registry.npmjs.org/-/npm/v1/attestations/@akasecurity%2fai-tc-claude-code@0.9.14
# Public registry data. It pins the constants in release_checks to a real release.
REAL_LEAF_0_9_14 = (
    "MIIHhTCCBwygAwIBAgIUXjaB1oPwC+9nth3LUzZkfN/CnM4wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3Rv"
    "cmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjYwOTI0MTMyOTI3WhcNMjYwOTI0MTMz"
    "OTI3WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQntk9M92Ok7f3L90u4Z8hN2N6nTgMt9/d73tXnk65xR2"
    "Z0fR6pxWdifkm59Lju96i278rFjKrklc+lSP4FCp5aOCBiswggYnMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAK"
    "BggrBgEFBQcDAzAdBgNVHQ4EFgQUn8Au28dnJI24ZNyhgzMdcIMXA5YwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjp"
    "KFWixi4YZD8wfgYDVR0RAQH/BHQwcoZwaHR0cHM6Ly9naXRodWIuY29tL2FrYXNlY3VyaXR5L2FpLXRjLy5naXRo"
    "dWIvd29ya2Zsb3dzL3JlbGVhc2UtcGx1Z2luLWNsYXVkZS55bWxAcmVmcy90YWdzL3BsdWdpbi1jbGF1ZGUtdjAu"
    "OS4xNDA5BgorBgEEAYO/MAEBBCtodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tMBIG"
    "CisGAQQBg78wAQIEBHB1c2gwNgYKKwYBBAGDvzABAwQoYTc1NTMyYjk4YTcwNTQ2ZDM4MjVjYmMyMzc3NjlhZWZl"
    "NGRjYzA3NDAqBgorBgEEAYO/MAEEBBxSZWxlYXNlIHBsdWdpbiAoQ2xhdWRlIENvZGUpMB8GCisGAQQBg78wAQUE"
    "EWFrYXNlY3VyaXR5L2FpLXRjMC0GCisGAQQBg78wAQYEH3JlZnMvdGFncy9wbHVnaW4tY2xhdWRlLXYwLjkuMTQw"
    "OwYKKwYBBAGDvzABCAQtDCtodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tMIGABgor"
    "BgEEAYO/MAEJBHIMcGh0dHBzOi8vZ2l0aHViLmNvbS9ha2FzZWN1cml0eS9haS10Yy8uZ2l0aHViL3dvcmtmbG93"
    "cy9yZWxlYXNlLXBsdWdpbi1jbGF1ZGUueW1sQHJlZnMvdGFncy9wbHVnaW4tY2xhdWRlLXYwLjkuMTQwOAYKKwYB"
    "BAGDvzABCgQqDChhNzU1MzJiOThhNzA1NDZkMzgyNWNiYzIzNzc2OWFlZmU0ZGNjMDc0MB0GCisGAQQBg78wAQsE"
    "DwwNZ2l0aHViLWhvc3RlZDA0BgorBgEEAYO/MAEMBCYMJGh0dHBzOi8vZ2l0aHViLmNvbS9ha2FzZWN1cml0eS9h"
    "aS10YzA4BgorBgEEAYO/MAENBCoMKGE3NTUzMmI5OGE3MDU0NmQzODI1Y2JjMjM3NzY5YWVmZTRkY2MwNzQwLwYK"
    "KwYBBAGDvzABDgQhDB9yZWZzL3RhZ3MvcGx1Z2luLWNsYXVkZS12MC45LjE0MBoGCisGAQQBg78wAQ8EDAwKMTI5"
    "Njg4MDI4NjAuBgorBgEEAYO/MAEQBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9ha2FzZWN1cml0eTAZBgorBgEEAYO/"
    "MAERBAsMCTMwMDUxNTE5NTCBgAYKKwYBBAGDvzABEgRyDHBodHRwczovL2dpdGh1Yi5jb20vYWthc2VjdXJpdHkv"
    "YWktdGMvLmdpdGh1Yi93b3JrZmxvd3MvcmVsZWFzZS1wbHVnaW4tY2xhdWRlLnltbEByZWZzL3RhZ3MvcGx1Z2lu"
    "LWNsYXVkZS12MC45LjE0MDgGCisGAQQBg78wARMEKgwoYTc1NTMyYjk4YTcwNTQ2ZDM4MjVjYmMyMzc3NjlhZWZl"
    "NGRjYzA3NDAUBgorBgEEAYO/MAEUBAYMBHB1c2gwWAYKKwYBBAGDvzABFQRKDEhodHRwczovL2dpdGh1Yi5jb20v"
    "YWthc2VjdXJpdHkvYWktdGMvYWN0aW9ucy9ydW5zLzM2MDA1MDk4NzQxL2F0dGVtcHRzLzEwFgYKKwYBBAGDvzAB"
    "FgQIDAZwdWJsaWMwSgYKKwYBBAGDvzABGAQ8DDpyZXBvOmFrYXNlY3VyaXR5L2FpLXRjOnJlZjpyZWZzL3RhZ3Mv"
    "cGx1Z2luLWNsYXVkZS12MC45LjE0MIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrje"
    "PK3/h4pygC8p7o4AAAGg05tVPgAABAMARzBFAiBqsaXmfFVPTDSCd46yePrBymyOqA49sRrNfVncOCDHmAIhANkM"
    "XuKhLX4zoPyrBbw+RYVOOc0HQLcoXVIVujIPRXngMAoGCCqGSM49BAMDA2cAMGQCMAN1QlxepU4Bwrxe/C3PUlCJ"
    "KYf6JOgefMWUilAx2M7q9WB6xOSyDKhpSJA0mR5vpgIwUG976c6D9pBAR3cu4NR0aN3+shgyB/TJZLQNUGyRuqxY"
    "VAyZWXdZ827pW40rkJVh"
)

# The fields a leaf carries that the release checks read, by the name release_checks
# gives them, and the Fulcio extension arc (under 1.3.6.1.4.1.57264.1) each one is in.
LEAF_ARCS = {
    "issuer": "8",
    "build_signer": "9",
    "runner": "11",
    "repository": "12",
    "commit": "13",
    "ref": "14",
    "repository_id": "15",
    "owner_id": "17",
    "build_config": "18",
    "trigger": "20",
    "run_url": "21",
}


def der(tag, content):
    """One DER element: tag, definite minimal length, content."""
    size = len(content)
    if size < 0x80:
        length = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def der_oid(dotted):
    arcs = [int(part) for part in dotted.split(".")]
    body = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body.extend(reversed(chunk))
    return der(0x06, bytes(body))


def extension(oid, value, *, critical=False):
    """One X.509 extension: OID, optional critical flag, OCTET STRING holding value."""
    flag = der(0x01, b"\xff") if critical else b""
    return der(0x30, der_oid(oid) + flag + der(0x04, value))


def san_uri(uri):
    return der(0x86, uri.encode())


def san_extension(*names):
    """A subjectAltName extension holding the given GeneralNames (already encoded)."""
    return extension(SAN_OID, der(0x30, b"".join(names)), critical=True)


def fulcio_extension(arc, value, *, tag=0x0C):
    """A Fulcio v2 extension: its value is one DER string (UTF8String unless tag says otherwise)."""
    return extension(FULCIO + arc, der(tag, value.encode()))


def der_cert(extensions):
    """A certificate holding exactly these (already encoded) extensions."""
    algorithm = der(0x30, der_oid("1.2.840.10045.4.3.2"))
    name = der(0x30, b"")
    validity = der(0x30, der(0x17, b"260924132927Z") + der(0x17, b"260924133927Z"))
    key = der(
        0x30,
        der(0x30, der_oid("1.2.840.10045.2.1") + der_oid("1.2.840.10045.3.1.7"))
        + der(0x03, b"\x00\x04" + b"\x01" * 64),
    )
    tbs = der(
        0x30,
        der(0xA0, der(0x02, b"\x02"))
        + der(0x02, b"\x01\x02\x03")
        + algorithm
        + name
        + validity
        + name
        + key
        + der(0xA3, der(0x30, b"".join(extensions))),
    )
    return der(0x30, tbs + algorithm + der(0x03, b"\x00signature"))


def leaf_fields(version, **overrides):
    """What the Fulcio leaf of a correct release of `version` says, by field name. A field
    overridden with None is left out of the certificate."""
    tag_ref = f"refs/tags/plugin-claude-v{version}"
    workflow_uri = f"https://github.com/akasecurity/ai-tc/{WORKFLOW}@{tag_ref}"
    fields = {
        "san": workflow_uri,
        "issuer": "https://token.actions.githubusercontent.com",
        "build_signer": workflow_uri,
        "runner": "github-hosted",
        "repository": "https://github.com/akasecurity/ai-tc",
        "commit": ATTESTED.get(version, "c" * 40),
        "ref": tag_ref,
        "repository_id": "1296880286",
        "owner_id": "300515195",
        "build_config": workflow_uri,
        "trigger": "push",
        "run_url": RUN_URL,
    }
    unknown = set(overrides) - set(fields)
    if unknown:
        raise KeyError(f"not a leaf field: {sorted(unknown)}")
    fields.update(overrides)
    return fields


def leaf_extensions(version, **overrides):
    """The extensions of a correct leaf, plus the ones a real leaf carries that the checks
    must skip unread: key usage, the deprecated raw-string Fulcio OIDs (here holding bytes
    that are not UTF-8), a future Fulcio arc, and the SCT list."""
    fields = leaf_fields(version, **overrides)
    extensions = [extension("2.5.29.15", der(0x03, b"\x07\x80"), critical=True)]
    if fields["san"] is not None:
        extensions.append(san_extension(san_uri(fields["san"])))
    extensions += [extension(f"{FULCIO}{arc}", b"\xff\xfe raw") for arc in ("1", "2", "3", "4", "5", "6")]
    for name, arc in LEAF_ARCS.items():
        if fields[name] is not None:
            extensions.append(fulcio_extension(arc, fields[name]))
    extensions += [
        fulcio_extension("10", "a" * 40),
        fulcio_extension("16", "https://github.com/akasecurity"),
        fulcio_extension("19", "a" * 40),
        fulcio_extension("22", "public"),
        fulcio_extension("24", f"repo:akasecurity/ai-tc:ref:refs/tags/plugin-claude-v{version}"),
        fulcio_extension("99", "an arc Fulcio has not assigned yet"),
        extension("1.3.6.1.4.1.11129.2.4.2", b"sct list"),
    ]
    return extensions


def signing_cert(version="0.9.14", **overrides):
    """The DER of a correct Fulcio leaf for `version`, with any field overridden."""
    return der_cert(leaf_extensions(version, **overrides))


def cert_material(cert):
    """The verificationMaterial of a bundle signed with this certificate (bundle v0.3)."""
    return {"certificate": {"rawBytes": base64.b64encode(cert).decode()}, "tlogEntries": []}


def audit_output(
    version, stmt=None, *, invalid=None, verified=True, cert=None, material=None, missing=None, publish=True
):
    """What `npm audit signatures --json --include-attestations` prints for PACKAGE@version:
    the registry's publish attestation and the SLSA bundle, whose certificate (`cert`, DER,
    or `material`, the whole verificationMaterial) defaults to a correct one for `version`."""
    publish_bundle = {
        "predicateType": PUBLISH,
        "bundle": {
            "verificationMaterial": {"publicKey": {"hint": PUBLISH_KEYID}},
            "dsseEnvelope": {
                "payload": base64.b64encode(b"{}").decode(),
                "signatures": [{"keyid": PUBLISH_KEYID, "sig": "AA=="}],
            },
        },
    }
    slsa = {
        "predicateType": rc.SLSA,
        "bundle": {
            "verificationMaterial": material
            if material is not None
            else cert_material(cert if cert is not None else signing_cert(version)),
            "dsseEnvelope": {
                "payload": base64.b64encode(json.dumps(stmt or statement(version)).encode()).decode(),
                "signatures": [{"keyid": "", "sig": "AA=="}],
            },
        },
    }
    out = {"invalid": invalid or [], "missing": missing if missing is not None else []}
    out["verified"] = (
        [{"name": rc.PACKAGE, "version": version, "attestationBundles": [*([publish_bundle] if publish else []), slsa]}]
        if verified
        else []
    )
    return out


def dist_url(version):
    return f"{rc.packument_url()}/{version}"


# The commit ai-tc's main branch points at in the fakes. Not any release's attested commit.
MAIN_SHA = "e" * 40


def main_ref_url():
    return f"{rc.AI_TC_API}/git/ref/heads/main"


def main_ref_body(sha=MAIN_SHA):
    """What GET git/ref/heads/main answers."""
    return {"ref": "refs/heads/main", "object": {"sha": sha, "type": "commit"}}


def compare_url(commit, main_sha=MAIN_SHA):
    return f"{rc.AI_TC_API}/compare/{commit}...{main_sha}?per_page=1"


def contents_url(path, commit):
    return f"{rc.AI_TC_API}/contents/{path}?ref={commit}"


def release_routes(version, *, compare="ahead", commit=None, integrity=INTEGRITY, main_sha=MAIN_SHA):
    """The registry and GitHub answers for a release that passes every check: main's head
    read, then the comparison against the sha that read returned."""
    commit = commit or ATTESTED.get(version, "c" * 40)
    return {
        dist_url(version): (200, {"version": version, "dist": {"integrity": integrity, "shasum": SHASUM}}),
        main_ref_url(): (200, main_ref_body(main_sha)),
        compare_url(commit, main_sha): (200, {"status": compare, "ahead_by": 1, "behind_by": 0}),
    }


class FakeFetch:
    """Stands in for release_checks.http_fetch: url -> (status, body), or a list of them
    served in order (the last one repeats). Records every request."""

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        response = self.routes.get(url, (404, {"message": "Not Found"}))
        if isinstance(response, list):
            response = response.pop(0) if len(response) > 1 else response[0]
        status, body = response
        if not isinstance(body, bytes):
            body = (body if isinstance(body, str) else json.dumps(body)).encode()
        return status, body

    def urls(self):
        return [url for url, _ in self.calls]


# Hermetic git: no global or system config (so no signing prompt), a fixed identity.
GIT_ENV = dict(os.environ)
GIT_ENV.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
for _role in ("AUTHOR", "COMMITTER"):
    GIT_ENV[f"GIT_{_role}_NAME"] = "test"
    GIT_ENV[f"GIT_{_role}_EMAIL"] = "test"


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", repo, *args], check=True, capture_output=True, text=True, env=GIT_ENV
    ).stdout


class Repo:
    """A throwaway git repository shaped like the marketplace, on branch main."""

    def __init__(self, testcase):
        holder = tempfile.TemporaryDirectory()
        testcase.addCleanup(holder.cleanup)
        self.path = holder.name
        git(self.path, "init", "-q", "-b", "main")

    def write(self, rel, text):
        full = os.path.join(self.path, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as handle:
            handle.write(text)
        return full

    def commit(self, doc=None, *, files=None, message="change"):
        if doc is not None:
            self.write(rc.MANIFEST, rc.dump_json(doc))
        for rel, text in (files or {}).items():
            self.write(rel, text)
        git(self.path, "add", "-A")
        git(self.path, "commit", "-q", "--allow-empty", "-m", message)
        return self.head()

    def head(self):
        return git(self.path, "rev-parse", "HEAD").strip()

    def tag(self, name, message=None, *, rev="HEAD", lightweight=False):
        if lightweight:
            git(self.path, "tag", name, rev)
        else:
            git(self.path, "tag", "-a", name, "-m", message or name, rev)


def scripted_audit(testcase, version, reports, sleep):
    """An `audit` for verify_release that serves the scripted reports in order (the last one
    repeats) through the production retry loop, so the waits and the number of audits are the
    real ones. It stands in for npm_audit_signatures below the judge: nothing here installs
    anything or checks a report's shape, so a malformed report reaches the judge as it is."""
    queue = list(reports)

    def audit(package, v, judge):
        testcase.assertEqual((package, v), (rc.PACKAGE, version))
        return rc._audit_until_judged(lambda: queue.pop(0) if len(queue) > 1 else queue[0], judge, sleep)

    return audit


class VerifyMixin:
    """verify() and its outcomes for a TestCase that drives release_checks.verify_release
    with a fake registry, a fake GitHub and a scripted npm audit."""

    def verify(self, version="0.9.14", *, routes=None, audits=None, sleeps=None):
        fetch = FakeFetch(routes if routes is not None else release_routes(version))
        recorded = sleeps if sleeps is not None else []
        audit = scripted_audit(self, version, audits if audits is not None else [audit_output(version)], recorded.append)
        return rc.verify_release(version, fetch=fetch, audit=audit, sleep=recorded.append), fetch

    def refused(self, check, **kwargs):
        """The verdict is no, under this check."""
        with self.assertRaises(rc.ReleaseCheckError) as caught:
            self.verify(**kwargs)
        self.assertEqual(caught.exception.check, check)
        return caught.exception

    def no_verdict(self, check, **kwargs):
        """No verdict could be reached, under this check."""
        with self.assertRaises(rc.InfraError) as caught:
            self.verify(**kwargs)
        self.assertEqual(caught.exception.check, check)
        return caught.exception
