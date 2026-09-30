#!/usr/bin/env python3
"""The marketplace's one release-verification module (standard library only).

Every workflow that verifies an ai-tc release, or judges a change to the ai-tc pin,
imports THIS file from main's copy: validate through validate_pr.py, and the importer,
tag-release, staleness and tag-audit directly. The command line below is for a person,
and for a copy run outside this repository.

It has no third-party dependency on purpose. Nothing is installed before it runs, so
nothing outside this reviewed file can change a verdict.

    python3 .github/scripts/release_checks.py <command> [args]

prints one JSON document on stdout. The exit status is 0 when the check passes, 1 when
it fails, and 2 on a usage error or when no verdict could be reached (network, npm, git
or GitHub API trouble). Human-readable detail goes to stderr.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

# The one plugin this marketplace pins, and what a publish of it must attest to. These
# are constants of this reviewed file: nothing read from a PR, the registry or an
# attestation may nominate the workflow that is supposed to vouch for a release. Who
# signed a release is read from the Sigstore certificate npm verified, never from the
# statement the publisher wrote.
PACKAGE = "@akasecurity/ai-tc-claude-code"
ENTRY_NAME = "ai-tc"
REGISTRY = "https://registry.npmjs.org"
PROV_REPO = "https://github.com/akasecurity/ai-tc"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
RELEASE_PIPELINE = {
    PACKAGE: {
        "workflow": ".github/workflows/release-plugin-claude.yml",
        "tag_prefix": "plugin-claude-v",
        # GitHub's numeric ids of ai-tc and of the account that owns it. A name can be
        # taken over after a rename, a transfer or a deleted and re-created repository;
        # an id cannot.
        "repository_id": "1296880286",
        "owner_id": "300515195",
    },
}
AI_TC_API = "https://api.github.com/repos/akasecurity/ai-tc"
MARKETPLACE_API = "https://api.github.com/repos/akasecurity/marketplace"
MIGRATIONS_DIR = "packages/schema/drizzle/local-sqlite"

MANIFEST = ".claude-plugin/marketplace.json"
SAFETY_FILE = "rollback-safety.json"
FROZEN_TAGS_FILE = ".github/fleet-tags.frozen.json"

SLSA = "https://slsa.dev/provenance/v1"
# The attestation the npm registry itself signs at publish time. npm verifies it against
# the registry's keys, so it verifying shows npm held them.
PUBLISH = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
GITHUB_ACTIONS_APP_ID = 15368

# The bot App's login, "<app-slug>[bot]". None until the App exists. While it is None, no
# PR is judged as the bot's, so every change to the ai-tc pin fails validate.
BOT_LOGIN: str | None = None

# Until a measured downgrade shows that an older build keeps working on a store an
# additive migration touched, EVERY migration marks its release not rollback-safe.
# Flip this only in a reviewed change that cites that measurement. The per-statement
# kinds are computed and shown either way.
EVERY_MIGRATION_COUNTS = True

# Exact x.y.z: ASCII, canonical, no leading zeros. "0.9.09" would otherwise reach the
# registry, which serves 0.9.9's bytes for it.
SEMVER = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}")
FLEET_TAG = re.compile(r"fleet-v([1-9][0-9]*)")
SHA40 = re.compile(r"[0-9a-f]{40}")
SHASUM = re.compile(r"[0-9a-f]{40}")
INTEGRITY = re.compile(r"sha512-[A-Za-z0-9+/]{86}==")
RUN_URL = re.compile(r"https://github\.com/akasecurity/ai-tc/actions/runs/[0-9]+(?:/attempts/[0-9]+)?")
MIGRATION_TAG = re.compile(r"[0-9]{4}_[a-z0-9_]+")

# Read-replica lag after a publish, and attestation indexing lag: five tries, 20 s apart.
ATTEMPTS = 5
RETRY_SECONDS = 20


class _CheckFailure(Exception):
    """What every release-check failure carries: the check's name and a detail. It exists
    to share the constructor. Nothing catches it: a handler names ReleaseCheckError or
    InfraError, whichever it means."""

    def __init__(self, check: str, detail: str) -> None:
        super().__init__(f"{check}: {detail}")
        self.check = check
        self.detail = detail


class ReleaseCheckError(_CheckFailure):
    """A check reached a verdict, and the verdict is no (CLI exit 1)."""


class InfraError(_CheckFailure):
    """No verdict: the network, npm, git or an API failed (CLI exit 2). Deliberately NOT a
    ReleaseCheckError: a handler written for a verdict never catches an outage, so an
    unhandled one stops the run instead of reading as a refusal."""


def _reject_duplicates(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def _reject_constant(name):
    raise ValueError(f"non-standard JSON constant {name}")


def parse_json(text: str):
    """json.loads that refuses duplicate keys and NaN/Infinity, which jq and json.loads accept."""
    return json.loads(text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)


def dump_json(doc) -> str:
    """The one serialisation for every file this module writes: the manifest's own format."""
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def load_round_trip(raw: str) -> dict:
    """Parse a file that is about to be rewritten, proving the rewrite changes only the edit."""
    doc = parse_json(raw)
    if dump_json(doc) != raw:
        raise ReleaseCheckError(
            "round-trip",
            "the file does not round-trip through json.dumps(indent=2, ensure_ascii=False); "
            "rewriting it would churn unrelated bytes",
        )
    return doc


def pinned_package(plugin) -> str | None:
    """The npm package a manifest entry pins, or None (a path source is a bare string)."""
    source = plugin.get("source") if isinstance(plugin, dict) else None
    return source.get("package") if isinstance(source, dict) else None


def _plugins(manifest) -> list:
    plugins = manifest.get("plugins") if isinstance(manifest, dict) else None
    if not isinstance(plugins, list):
        raise ReleaseCheckError("manifest", "the manifest has no plugins list")
    return plugins


def _is_ai_tc(plugin) -> bool:
    return isinstance(plugin, dict) and (
        plugin.get("name") == ENTRY_NAME or pinned_package(plugin) == PACKAGE
    )


def select_ai_tc_entry(manifest: dict) -> dict:
    """Exactly one entry named ai-tc, exactly one pinning the package, and the same entry."""
    plugins = _plugins(manifest)
    named = [p for p in plugins if isinstance(p, dict) and p.get("name") == ENTRY_NAME]
    pinning = [p for p in plugins if pinned_package(p) == PACKAGE]
    if len(named) != 1:
        raise ReleaseCheckError(
            "entry", f"expected exactly one entry named {ENTRY_NAME!r}, found {len(named)}"
        )
    if len(pinning) != 1:
        raise ReleaseCheckError(
            "entry", f"expected exactly one entry pinning {PACKAGE}, found {len(pinning)}"
        )
    if named[0] is not pinning[0]:
        raise ReleaseCheckError(
            "entry", f"the entry named {ENTRY_NAME!r} is not the entry that pins {PACKAGE}"
        )
    return named[0]


def find_ai_tc_entry(manifest: dict) -> dict | None:
    """select_ai_tc_entry, except that a manifest naming and pinning nothing gives None."""
    if not any(_is_ai_tc(p) for p in _plugins(manifest)):
        return None
    return select_ai_tc_entry(manifest)


def entry_version(entry) -> str | None:
    """The exact x.y.z an entry pins, or None."""
    source = entry.get("source") if isinstance(entry, dict) else None
    version = source.get("version") if isinstance(source, dict) else None
    return version if isinstance(version, str) and SEMVER.fullmatch(version) else None


def vkey(version: str) -> tuple:
    """Sort key for an exact x.y.z; anything else is refused."""
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise ReleaseCheckError("version", f"{version!r} is not an exact x.y.z")
    return tuple(int(part) for part in version.split("."))


def _git(repo_dir: str, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, *args], check=True, capture_output=True, text=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise InfraError("git", f"git {' '.join(args)} failed: {detail.strip()[:500]}") from exc
    return result.stdout


def main_ref(repo_dir: str) -> str:
    """origin/main when the checkout has it (fresh in CI), else a local main (a test repo)."""
    for ref in ("refs/remotes/origin/main", "refs/heads/main"):
        probe = subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0:
            return ref
    raise InfraError("git", f"{repo_dir} has neither refs/remotes/origin/main nor refs/heads/main")


def fleet_tags(repo_dir: str) -> list:
    """Every fleet-v<N> tag, in numeric order."""
    names = _git(repo_dir, "for-each-ref", "--format=%(refname:strip=2)", "refs/tags/fleet-v*").split()
    return sorted((n for n in names if FLEET_TAG.fullmatch(n)), key=lambda n: int(n[len("fleet-v"):]))


def _read_manifest(repo_dir: str, rev: str):
    return parse_json(_git(repo_dir, "show", f"{rev}:{MANIFEST}"))


def _tag_pin(repo_dir: str, tag: str) -> str | None:
    """What a historical tag pins. Lenient about content: a tag whose manifest does not
    parse, or does not pin the package exactly once, pins nothing. NOT lenient about the
    read itself: a git failure (a missing object, an unfetched blob) is InfraError, since
    dropping that tag's pin would hide a version from the candidate and rollback floors."""
    try:
        doc = _read_manifest(repo_dir, f"refs/tags/{tag}")
        pins = [p for p in _plugins(doc) if pinned_package(p) == PACKAGE]
    except (ReleaseCheckError, ValueError):
        return None
    return entry_version(pins[0]) if len(pins) == 1 else None


def pins_by_ref(repo_dir: str) -> dict:
    """{"main": <pin>, "fleet-v1": <pin>, ...}. Strict for main, lenient for history."""
    try:
        main_doc = _read_manifest(repo_dir, main_ref(repo_dir))
    except ValueError as exc:
        raise ReleaseCheckError("manifest", f"main's {MANIFEST} does not parse: {exc}") from exc
    pins = {"main": entry_version(find_ai_tc_entry(main_doc))}
    for tag in fleet_tags(repo_dir):
        pins[tag] = _tag_pin(repo_dir, tag)
    return pins


def pinned_versions(repo_dir: str) -> set:
    """Every exact version main or any fleet-v tag pins."""
    return {v for v in pins_by_ref(repo_dir).values() if v}


def tag_pinned_versions(repo_dir: str) -> set:
    """Every exact version some fleet-v tag pins: the only rollback targets."""
    return {v for ref, v in pins_by_ref(repo_dir).items() if ref != "main" and v}


Fetch = Callable[[str, dict], tuple]


def _sends_token_to(url: str) -> bool:
    """Only api.github.com ever sees the job's token; the registry is read anonymously."""
    return urllib.parse.urlsplit(url).hostname == "api.github.com"


def _headers_for(url: str, extra: dict) -> dict:
    headers = {"User-Agent": "akasecurity-marketplace-release-checks", **extra}
    if _sends_token_to(url):
        headers.setdefault("Accept", "application/vnd.github+json")
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        if os.environ.get("GITHUB_TOKEN"):
            headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    return headers


def http_fetch(url: str, headers: dict) -> tuple:
    """GET url. An HTTP error status is returned, not raised; no answer at all is InfraError."""
    request = urllib.request.Request(url, headers=_headers_for(url, headers))
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, OSError) as exc:
        raise InfraError("network", f"GET {url} failed: {exc}") from exc


def packument_url() -> str:
    return f"{REGISTRY}/{urllib.parse.quote(PACKAGE, safe='@')}"


def npm_candidates(pinned: set, *, fetch: Fetch = http_fetch) -> list:
    """Exact x.y.z versions on npmjs above everything pinned, ascending. Never npm latest:
    a dist-tag can name a version published from a branch."""
    status, body = fetch(packument_url(), {"Accept": "application/json"})
    if status != 200:
        raise InfraError("npm", f"{REGISTRY} answered {status} for {PACKAGE}")
    try:
        document = parse_json(body.decode("utf-8"))
    except ValueError as exc:
        raise InfraError("npm", f"{REGISTRY} answered non-JSON for {PACKAGE}: {exc}") from exc
    versions = document.get("versions") if isinstance(document, dict) else None
    if not isinstance(versions, dict):
        # The packument keys "versions" by version. A list or a bare string is what
        # `npm view ... versions --json` prints, not what the registry serves.
        raise InfraError("npm", f"{REGISTRY} returned no versions object for {PACKAGE}")
    exact = {v for v in versions if SEMVER.fullmatch(v)}
    floor = max((vkey(v) for v in pinned), default=None)
    return sorted((v for v in exact if floor is None or vkey(v) > floor), key=vkey)


def _npm(run, args: list, work: str):
    try:
        return run(["npm", *args], cwd=work, capture_output=True, text=True)
    except OSError as exc:
        raise InfraError("toolchain", f"could not run npm {args[0]}: {exc}") from exc


def npm_audit_signatures(package: str, version: str, *, run=subprocess.run, sleep=time.sleep) -> dict:
    """Run `npm audit signatures --json --include-attestations` over a scratch,
    --ignore-scripts install of exactly package@version from npmjs.

    npm does the cryptography (the registry signature and the sigstore bundle); the
    caller judges what the attestation binds. Needs npm 11 (Node 24): an older npm
    returns an EMPTY verified set, which reads as "no attestation" and would refuse a
    good release."""
    registry_flag = f"--{package.split('/')[0]}:registry={REGISTRY}"
    with tempfile.TemporaryDirectory() as work:
        init = _npm(run, ["init", "-y"], work)
        if init.returncode != 0:
            raise InfraError("toolchain", f"npm init failed: {init.stderr[:2000]}")
        for attempt in range(1, ATTEMPTS + 1):
            install = _npm(
                run,
                ["install", "--ignore-scripts", "--no-audit", "--no-fund", registry_flag, f"{package}@{version}"],
                work,
            )
            if install.returncode == 0:
                break
            if attempt == ATTEMPTS:
                raise InfraError(
                    "toolchain",
                    f"npm could not install {package}@{version} after {ATTEMPTS} attempts "
                    f"(a registry or network problem, NOT a signature result): {install.stderr[:2000]}",
                )
            sleep(RETRY_SECONDS)
        # npm exits 1 when anything is invalid or missing: the JSON is the verdict, the
        # exit status is not.
        audit = _npm(run, ["audit", "signatures", "--json", "--include-attestations"], work)
    if not audit.stdout.strip():
        raise InfraError("toolchain", "npm audit signatures printed nothing (NOT a signature result)")
    try:
        return json.loads(audit.stdout)
    except ValueError as exc:
        raise InfraError("toolchain", f"npm audit signatures printed non-JSON: {audit.stdout[:500]}") from exc


@dataclasses.dataclass(frozen=True)
class VerifiedRelease:
    version: str
    integrity: str
    shasum: str
    git_commit: str
    run_url: str


class _NotIndexedYet(Exception):
    """No verified attestation yet: indexing lags a publish, so this verdict is retried."""


def registry_dist(version: str, *, fetch: Fetch = http_fetch, sleep=time.sleep) -> tuple:
    """(integrity, shasum) npmjs serves for PACKAGE@version, from ONE registry read.

    Only a 404 that outlasts the read-replica lag is a verdict (the registry does not serve
    this version), and so is a document that is not a dist for this version. Every other
    answer that is not a 200 (a 429, a 403, a 5xx), and a 200 that is not a JSON object, says
    nothing about the release: it is retried and then reported as no verdict."""
    url = f"{packument_url()}/{version}"
    for attempt in range(1, ATTEMPTS + 1):
        status, body = fetch(url, {"Accept": "application/json"})
        if status == 200:
            break
        if attempt == ATTEMPTS:
            if status == 404:
                raise ReleaseCheckError("dist", f"{REGISTRY} does not serve {PACKAGE}@{version}")
            raise InfraError("dist", f"{REGISTRY} answered {status} for {PACKAGE}@{version}")
        sleep(RETRY_SECONDS)
    try:
        doc = parse_json(body.decode("utf-8"))
    except ValueError as exc:
        raise InfraError("dist", f"{REGISTRY} answered non-JSON for {PACKAGE}@{version}: {exc}") from exc
    if not isinstance(doc, dict):
        raise InfraError("dist", f"{REGISTRY} did not answer a JSON object for {PACKAGE}@{version}")
    dist = doc.get("dist")
    if not isinstance(dist, dict) or doc.get("version") != version:
        raise ReleaseCheckError("dist", f"{REGISTRY} returned no dist for {PACKAGE}@{version}")
    integrity, shasum = dist.get("integrity"), dist.get("shasum")
    if not isinstance(integrity, str) or not INTEGRITY.fullmatch(integrity):
        raise ReleaseCheckError("dist", f"integrity {integrity!r} is not one sha512 SRI")
    if not isinstance(shasum, str) or not SHASUM.fullmatch(shasum):
        raise ReleaseCheckError("dist", f"shasum {shasum!r} is not 40 hex")
    return integrity, shasum


class _CertError(ValueError):
    """The signing certificate could not be read as a Fulcio leaf certificate."""


# What the release checks read from the signing certificate beyond its subject alternative
# name: the Fulcio v2 extensions, each one DER UTF8String under 1.3.6.1.4.1.57264.1.<arc>,
# filled by Fulcio from the claims of the GitHub OIDC token, so a workflow cannot choose
# them. Every other extension is skipped unread (the deprecated raw-string arcs 1-6, 7, 10,
# 16, 19, 22 and 24, key usage, the SCT list), so a new Fulcio arc cannot break the reader.
# Arc 23, the deployment environment, is not pinned: the release job names no GitHub
# environment. Pin it in the commit that adds one.
FULCIO_ARC = "1.3.6.1.4.1.57264.1."
SAN_OID = "2.5.29.17"
SIGNER_FIELDS = {
    "issuer": ("8", "OIDC issuer"),
    "build_signer": ("9", "build signer URI"),
    "runner": ("11", "runner environment"),
    "repository": ("12", "source repository URI"),
    "commit": ("13", "source repository digest"),
    "ref": ("14", "source repository ref"),
    "repository_id": ("15", "source repository id"),
    "owner_id": ("17", "source repository owner id"),
    "build_config": ("18", "build config URI"),
    "trigger": ("20", "build trigger"),
    "run_url": ("21", "run invocation URI"),
}


def _field_label(name: str) -> str:
    if name == "san":
        return "certificate subject alternative name"
    arc, what = SIGNER_FIELDS[name]
    return f"certificate {what} (Fulcio {FULCIO_ARC}{arc})"


def _der(buf: bytes, pos: int, end: int) -> tuple:
    """(tag, value_start, value_end) of the DER element at buf[pos:end]. Only definite,
    minimal lengths and single-byte tags, and no element may outrun its parent."""
    if pos + 2 > end:
        raise _CertError("truncated element")
    tag, first = buf[pos], buf[pos + 1]
    pos += 2
    if tag & 0x1F == 0x1F:
        raise _CertError("high tag number form")
    if first < 0x80:
        size = first
    elif first == 0x80:
        raise _CertError("indefinite length")
    else:
        count = first & 0x7F
        if count > 4 or pos + count > end:
            raise _CertError("length over four bytes or truncated")
        size = int.from_bytes(buf[pos : pos + count], "big")
        if buf[pos] == 0 or size < 0x80:
            raise _CertError("length not minimal")
        pos += count
    if pos + size > end:
        raise _CertError("element overruns its parent")
    return tag, pos, pos + size


def _der_items(buf: bytes, start: int, stop: int) -> list:
    """The children of the constructed element whose content is buf[start:stop]. They must
    fill it exactly."""
    items, pos = [], start
    while pos < stop:
        tag, content_start, content_end = _der(buf, pos, stop)
        items.append((tag, content_start, content_end))
        pos = content_end
    return items


def _der_oid(raw: bytes) -> str:
    if not raw or raw[-1] & 0x80:
        raise _CertError("malformed OID")
    arcs, value = [], 0
    for byte in raw:
        if value == 0 and byte == 0x80:
            raise _CertError("OID arc not minimal")
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    head = min(arcs[0] // 40, 2)
    return ".".join(str(arc) for arc in [head, arcs[0] - 40 * head, *arcs[1:]])


def _san_uri(der: bytes, start: int, stop: int) -> str:
    """The one URI a Fulcio leaf's subjectAltName holds."""
    tag, content_start, content_end = _der(der, start, stop)
    if tag != 0x30 or content_end != stop:
        raise _CertError("the subject alternative name is not one SEQUENCE")
    names = _der_items(der, content_start, content_end)
    if len(names) != 1 or names[0][0] != 0x86:
        raise _CertError("the subject alternative name is not exactly one URI")
    raw = der[names[0][1] : names[0][2]]
    if not raw or any(byte < 0x21 or byte > 0x7E for byte in raw):
        raise _CertError("the subject alternative name URI is not printable ASCII")
    return raw.decode("ascii")


def _fulcio_string(der: bytes, start: int, stop: int, oid: str) -> str:
    tag, content_start, content_end = _der(der, start, stop)
    if tag != 0x0C or content_end != stop:
        raise _CertError(f"extension {oid} is not exactly one UTF8String")
    try:
        return der[content_start:content_end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _CertError(f"extension {oid} is not UTF-8") from exc


def signer_identity(der: bytes) -> dict:
    """Who a Fulcio leaf certificate (DER) names: {"san": <URI>, "issuer": ..., "commit": ...,
    one key per SIGNER_FIELDS name}. Reads the standard library only, verifies nothing
    cryptographic (npm did: the chain to Fulcio's CA, the signed certificate timestamp,
    Rekor, and the envelope signature made with this leaf's key), and refuses anything it
    does not expect with _CertError."""
    tag, start, stop = _der(der, 0, len(der))
    if tag != 0x30 or stop != len(der):
        raise _CertError("not exactly one certificate SEQUENCE")
    parts = _der_items(der, start, stop)
    if len(parts) != 3 or parts[0][0] != 0x30:
        raise _CertError("a certificate is a tbsCertificate, an algorithm and a signature")
    tbs = _der_items(der, parts[0][1], parts[0][2])
    if not tbs or tbs[-1][0] != 0xA3:
        raise _CertError("the certificate has no extensions field")
    wrapper = _der_items(der, tbs[-1][1], tbs[-1][2])
    if len(wrapper) != 1 or wrapper[0][0] != 0x30:
        raise _CertError("the extensions field is not one SEQUENCE")
    wanted = {FULCIO_ARC + arc: name for name, (arc, _) in SIGNER_FIELDS.items()}
    seen, found = set(), {}
    for tag, extension_start, extension_end in _der_items(der, wrapper[0][1], wrapper[0][2]):
        if tag != 0x30:
            raise _CertError("an extension is not a SEQUENCE")
        extension = _der_items(der, extension_start, extension_end)
        if len(extension) not in (2, 3) or extension[0][0] != 0x06 or extension[-1][0] != 0x04:
            raise _CertError("an extension is not an OID, an optional flag and an OCTET STRING")
        if len(extension) == 3 and extension[1][0] != 0x01:
            raise _CertError("an extension's critical flag is not a BOOLEAN")
        oid = _der_oid(der[extension[0][1] : extension[0][2]])
        if oid in seen:
            raise _CertError(f"extension {oid} appears twice")
        seen.add(oid)
        value_start, value_end = extension[-1][1], extension[-1][2]
        if oid == SAN_OID:
            found["san"] = _san_uri(der, value_start, value_end)
        elif oid in wanted:
            found[wanted[oid]] = _fulcio_string(der, value_start, value_end, oid)
    absent = [name for name in ("san", *SIGNER_FIELDS) if name not in found]
    if absent:
        raise _CertError(f"the certificate does not carry {', '.join(_field_label(n) for n in absent)}")
    return found


def _leaf_der(bundle) -> bytes:
    """The DER of the certificate a sigstore bundle was signed with: verificationMaterial
    must hold exactly one of `certificate` or `x509CertificateChain` (whose first entry is
    the leaf, as sigstore reads it). A public key, both, or neither is refused."""
    material = bundle.get("verificationMaterial") if isinstance(bundle, dict) else None
    if not isinstance(material, dict):
        raise _CertError("the bundle has no verification material")
    present = [key for key in ("certificate", "x509CertificateChain", "publicKey") if key in material]
    if present == ["certificate"]:
        holder = material["certificate"]
    elif present == ["x509CertificateChain"]:
        chain = material["x509CertificateChain"]
        certificates = chain.get("certificates") if isinstance(chain, dict) else None
        holder = certificates[0] if isinstance(certificates, list) and certificates else None
    else:
        raise _CertError(f"the verification material holds {present or 'nothing'}, not one signing certificate")
    raw = holder.get("rawBytes") if isinstance(holder, dict) else None
    if not isinstance(raw, str):
        raise _CertError("the signing certificate has no rawBytes")
    try:
        return base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise _CertError(f"the signing certificate is not base64: {exc}") from exc


def required_signer(version: str) -> dict:
    """What the signing certificate of PACKAGE@version must say: ai-tc's release workflow,
    at the version's own tag, pushed by the tag, from ai-tc's own repository, on a
    GitHub-hosted runner. The commit and the run are bound to the statement instead."""
    pipeline = RELEASE_PIPELINE[PACKAGE]
    tag_ref = f"refs/tags/{pipeline['tag_prefix']}{version}"
    workflow = f"{PROV_REPO}/{pipeline['workflow']}@{tag_ref}"
    return {
        "san": workflow,
        "issuer": OIDC_ISSUER,
        "build_signer": workflow,
        "runner": "github-hosted",
        "repository": PROV_REPO,
        "ref": tag_ref,
        "repository_id": pipeline["repository_id"],
        "owner_id": pipeline["owner_id"],
        "build_config": workflow,
        "trigger": "push",
    }


@dataclasses.dataclass(frozen=True)
class SignedStatement:
    """The in-toto statement a provenance bundle carries, with who signed it. `signer` is
    read from the certificate npm verified; `body` is what the publisher wrote."""

    body: dict
    signer: dict


def provenance_verdict(sig: dict, version: str, integrity: str) -> SignedStatement:
    """The SLSA statement for PACKAGE@version and the certificate that signed it, once the
    certificate binds the tarball the dist read saw to ai-tc's release workflow, at the
    version's own tag, pushed by that tag, on a GitHub-hosted runner.

    npm checks the signature and the certificate's chain, but no identity: an attestation
    that verifies proves only that SOMEONE published with provenance. So who signed is read
    from the signing certificate (Fulcio fills it from GitHub's token, and the envelope is
    signed with that certificate's key), never from the statement, which the publisher
    wrote. The statement must then agree with the certificate."""
    pipeline = RELEASE_PIPELINE[PACKAGE]
    if sig.get("invalid"):
        raise ReleaseCheckError("provenance", f"npm reports INVALID signatures or attestations: {sig['invalid']}")
    # npm fills `missing` (no registry signature) and `verified` (a verified attestation)
    # independently, so one package can be in both.
    missing = sig.get("missing")
    if not isinstance(missing, list) or not all(isinstance(item, dict) for item in missing):
        raise InfraError(
            "toolchain", f"npm audit signatures printed no list of missing signatures (NOT a signature result): {missing!r}"
        )
    if any(item.get("name") == PACKAGE and item.get("version") == version for item in missing):
        raise ReleaseCheckError(
            "signature",
            f"npm reports no registry signature for {PACKAGE}@{version}: the registry's own "
            "signature over this tarball is missing, so the attestation alone cannot be relied on",
        )
    entry = next(
        (v for v in sig.get("verified") or [] if v.get("name") == PACKAGE and v.get("version") == version),
        None,
    )
    if entry is None:
        raise _NotIndexedYet(f"{PACKAGE}@{version} carries no VERIFIED attestation in npm's report")
    if not any(b.get("predicateType") == PUBLISH for b in entry.get("attestationBundles") or []):
        # Absent from `missing` means something only if npm held the registry's keys, and
        # the registry's own publish attestation verifying is what shows it did.
        raise ReleaseCheckError(
            "signature",
            f"{PACKAGE}@{version} has no verified registry publish attestation, so nothing shows "
            "that npm checked the registry's signature",
        )
    bundles = [b for b in entry.get("attestationBundles") or [] if b.get("predicateType") == SLSA]
    if not bundles:
        raise ReleaseCheckError("provenance", f"{PACKAGE}@{version} has no {SLSA} attestation")
    if len(bundles) > 1:
        raise ReleaseCheckError(
            "provenance",
            f"{PACKAGE}@{version} has {len(bundles)} {SLSA} attestations, not exactly one, so "
            "there is no single signer to read",
        )
    try:
        signer = signer_identity(_leaf_der(bundles[0].get("bundle")))
    except _CertError as exc:
        raise ReleaseCheckError("provenance", f"the SLSA bundle's signing certificate is unreadable: {exc}") from exc
    try:
        statement = json.loads(base64.b64decode(bundles[0]["bundle"]["dsseEnvelope"]["payload"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ReleaseCheckError("provenance", f"the SLSA bundle is unreadable: {exc}") from exc
    predicate = statement.get("predicate") or {}
    got = ((predicate.get("buildDefinition") or {}).get("externalParameters") or {}).get("workflow") or {}
    builder = str(((predicate.get("runDetails") or {}).get("builder") or {}).get("id", ""))
    dist_hex = base64.b64decode(integrity.split("-", 1)[1]).hex()
    attested = {
        (s.get("digest") or {}).get("sha512", "") for s in statement.get("subject") or [] if isinstance(s, dict)
    }
    bad = [
        f"{_field_label(name)}: attested {signer[name]!r} != required {value!r}"
        for name, value in required_signer(version).items()
        if signer[name] != value
    ]
    if bad:
        if (
            signer["repository"] == PROV_REPO
            and signer["san"].startswith(f"{PROV_REPO}/{pipeline['workflow']}@refs/heads/")
            and signer["ref"].startswith("refs/heads/")
        ):
            raise ReleaseCheckError(
                "provenance",
                f"{PACKAGE}@{version} was published by {PROV_REPO} :: {pipeline['workflow']} from "
                f"{signer['ref']!r}, not from its tag refs/tags/{pipeline['tag_prefix']}{version}: an "
                "off-tag publish from a branch dispatch. An attestation is immutable, so this "
                "version can never be imported. This is NOT a stolen-token signal.",
            )
        raise ReleaseCheckError(
            "provenance",
            "the signing certificate does not bind this tarball to ai-tc's release workflow: "
            + "; ".join(bad)
            + ". A cryptographically valid attestation is NOT sufficient: anyone can publish "
            "with provenance from their own repository.",
        )
    if dist_hex not in attested:
        raise ReleaseCheckError(
            "provenance",
            f"the attestation covers a different tarball than the dist read ({integrity}); "
            "the two registry reads disagree about the bytes",
        )
    claimed = {"repository": signer["repository"], "path": pipeline["workflow"], "ref": signer["ref"]}
    disagree = [f"{k}: statement {got.get(k)!r} != certificate {v!r}" for k, v in claimed.items() if got.get(k) != v]
    if "github-hosted" not in builder:
        disagree.append(f"builder {builder!r} is not a github-hosted runner")
    if disagree:
        raise ReleaseCheckError(
            "provenance",
            "the signed statement disagrees with the certificate that signed it: "
            + "; ".join(disagree)
            + ". A statement that contradicts its own signer is forged.",
        )
    return SignedStatement(statement, signer)


def attested_commit(statement: SignedStatement, version: str) -> str:
    """The git commit the release was built from: the signing certificate's source
    repository digest, which the statement's own commit for the tag's URI must equal."""
    tag_ref = f"refs/tags/{RELEASE_PIPELINE[PACKAGE]['tag_prefix']}{version}"
    uri = f"git+{PROV_REPO}@{tag_ref}"
    dependencies = ((statement.body.get("predicate") or {}).get("buildDefinition") or {}).get("resolvedDependencies") or []
    commits = [
        (d.get("digest") or {}).get("gitCommit")
        for d in dependencies
        if isinstance(d, dict) and d.get("uri") == uri
    ]
    if len(commits) != 1 or not isinstance(commits[0], str) or not SHA40.fullmatch(commits[0]):
        raise ReleaseCheckError("attested-commit", f"the provenance names no single commit for {uri} (found {commits!r})")
    if commits[0] != statement.signer["commit"]:
        raise ReleaseCheckError(
            "attested-commit",
            f"the statement builds {uri} at {commits[0]} but the signing certificate names "
            f"{statement.signer['commit']} as the commit the workflow ran at",
        )
    return statement.signer["commit"]


def release_run_url(statement: SignedStatement) -> str:
    """The ai-tc release run that built the tarball, for the PR body: the signing
    certificate's run invocation URI, which the statement's own must equal."""
    url = statement.signer["run_url"]
    if not RUN_URL.fullmatch(url):
        raise ReleaseCheckError("run-url", f"the signing certificate names no ai-tc Actions run: {url!r}")
    claimed = (((statement.body.get("predicate") or {}).get("runDetails") or {}).get("metadata") or {}).get("invocationId")
    if claimed != url:
        raise ReleaseCheckError(
            "run-url", f"the statement names the run {claimed!r} but the signing certificate names {url!r}"
        )
    return url


def commit_on_ai_tc_main(git_commit: str, *, fetch: Fetch = http_fetch) -> str:
    """Returns 'ahead' or 'identical' when the attested commit is on ai-tc main. Refuses
    behind (built on main's tip, never merged), diverged, 404 and every error."""
    url = f"{AI_TC_API}/compare/{git_commit}...main?per_page=1"
    status, body = fetch(url, {})
    if status in (404, 422):
        raise ReleaseCheckError("commit-on-main", f"GitHub cannot compare {git_commit} with ai-tc main ({status})")
    if status != 200:
        raise InfraError("commit-on-main", f"GET {url} answered {status}")
    result = json.loads(body).get("status")
    if result not in ("ahead", "identical"):
        raise ReleaseCheckError(
            "commit-on-main",
            f"compare {git_commit}...main is {result!r}: the attested commit is not on ai-tc main",
        )
    return result


def verify_release(version: str, *, fetch: Fetch = http_fetch, audit=npm_audit_signatures, sleep=time.sleep) -> VerifiedRelease:
    """Every check a version must pass before any PR pins it, re-derived from npmjs and
    GitHub. Nothing the publisher wrote is taken on trust. What is trusted is npm's
    cryptography (the registry signature and the sigstore bundle, including the signing
    certificate it verified) and GitHub's answer about ai-tc main."""
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise ReleaseCheckError("version", f"{version!r} is not an exact x.y.z (pre-releases are never pinned)")
    integrity, shasum = registry_dist(version, fetch=fetch, sleep=sleep)
    for attempt in range(1, ATTEMPTS + 1):
        try:
            statement = provenance_verdict(audit(PACKAGE, version), version, integrity)
            break
        except _NotIndexedYet as exc:
            if attempt == ATTEMPTS:
                raise ReleaseCheckError(
                    "provenance",
                    f"{exc}. Every release of this package is published by GitHub Actions with "
                    f"provenance; one without it after {ATTEMPTS} attempts did not come from the "
                    "release pipeline.",
                ) from None
            sleep(RETRY_SECONDS)
    git_commit = attested_commit(statement, version)
    run_url = release_run_url(statement)
    commit_on_ai_tc_main(git_commit, fetch=fetch)
    return VerifiedRelease(version, integrity, shasum, git_commit, run_url)
