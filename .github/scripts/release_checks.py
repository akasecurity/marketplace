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
it fails, and 2 on a usage error, when no verdict could be reached (network, npm, git or
GitHub API trouble), or on any unexpected error (reported as the check "internal"). Only
a verdict exits 1, so a caller that fails on any non-zero status never reads a defect in
this tool as a release that failed its checks. The argument parser reports its own usage
errors on stderr alone, with no JSON. Human-readable detail goes to stderr.
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
# The builder id of a GitHub-hosted runner in a SLSA statement. Matched exactly: a
# substring would accept any id that merely mentions it.
GITHUB_HOSTED_BUILDER = "https://github.com/actions/runner/github-hosted"
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
    except InfraError:
        raise
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
    tags = fleet_tags(repo_dir)
    if not tags:
        # fleet-v1.. can never be deleted, so an empty list means a checkout that did not
        # fetch tags, and main's pin alone would silently stand for the whole history.
        raise InfraError("git", f"{repo_dir} holds no fleet-v<N> tag (was the checkout fetched with tags?)")
    for tag in tags:
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


def _require_npm_11(result) -> None:
    """An npm older than 11 audits without attestations and reports an empty verified set,
    which would read as a release with no provenance."""
    match = re.match(r"(\d+)\.", (result.stdout or "").strip()) if result.returncode == 0 else None
    if match is None:
        raise InfraError("toolchain", f"could not read npm's version: {(result.stdout or result.stderr or '')[:200]}")
    if int(match.group(1)) < 11:
        raise InfraError(
            "toolchain",
            f"npm {result.stdout.strip()} is older than 11, whose audit output cannot show attestations "
            "(NOT a signature result)",
        )


def npm_audit_signatures(package: str, version: str, *, run=subprocess.run, sleep=time.sleep) -> dict:
    """Run `npm audit signatures --json --include-attestations` over a scratch,
    --ignore-scripts install of exactly package@version from npmjs.

    npm does the cryptography (the registry signature and the sigstore bundle); the
    caller judges what the attestation binds. Needs an npm that honours
    --include-attestations (11.12 or later). An older one prints no `verified` list at all,
    which provenance_verdict reports as a toolchain failure, not as a missing attestation."""
    registry_flag = f"--{package.split('/')[0]}:registry={REGISTRY}"
    with tempfile.TemporaryDirectory() as work:
        init = _npm(run, ["init", "-y"], work)
        if init.returncode != 0:
            raise InfraError("toolchain", f"npm init failed: {init.stderr[:2000]}")
        _require_npm_11(_npm(run, ["--version"], work))
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
        for attempt in range(1, ATTEMPTS + 1):
            audit = _npm(run, ["audit", "signatures", "--json", "--include-attestations"], work)
            if audit.stdout.strip():
                break
            if attempt == ATTEMPTS:
                raise InfraError(
                    "toolchain",
                    f"npm audit signatures printed nothing after {ATTEMPTS} attempts (NOT a signature result)",
                )
            sleep(RETRY_SECONDS)
    try:
        report = json.loads(audit.stdout)
    except ValueError as exc:
        raise InfraError("toolchain", f"npm audit signatures printed non-JSON: {audit.stdout[:500]}") from exc
    # A verdict always carries an "invalid" list (and a "verified" list when there is
    # anything verified). npm prints its own failures ({"error": {...}}) on the same
    # stream with the same exit status, and those are not a statement about the package.
    if (
        not isinstance(report, dict)
        or "error" in report
        or not isinstance(report.get("invalid"), list)
        or not isinstance(report.get("verified", []), list)
    ):
        raise InfraError(
            "toolchain",
            f"npm audit signatures did not print a verified/invalid report (NOT a signature result): {audit.stdout[:500]}",
        )
    return report


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
    except (ValueError, RecursionError) as exc:
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
# them. Every other extension is skipped unread: the deprecated raw-string arcs 1 to 6, the
# v2 arcs the checks do not use (7, 10, 16, 19, 22, 24), key usage and the SCT list. So a
# new Fulcio arc cannot break the reader. Arc 23, the deployment environment, is not
# pinned because the release job names no GitHub environment: pin it in the commit that
# adds one.
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


# The required fields a workflow run on a branch instead of the version's tag changes: the
# ones that carry the ref, and how the run was triggered.
REF_FIELDS = frozenset({"san", "build_signer", "build_config", "ref", "trigger"})


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


def _field(doc, *keys):
    """doc[keys[0]][keys[1]]...; None when any step is absent or passes through something
    that is not an object. A statement is the publisher's JSON, so no level can be assumed."""
    for key in keys:
        if not isinstance(doc, dict):
            return None
        doc = doc.get(key)
    return doc


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
    if not isinstance(sig, dict):
        raise InfraError("toolchain", f"npm audit signatures did not print a report object (NOT a signature result): {sig!r:.200}")
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
    if "verified" not in sig:
        # npm prints `verified` whenever it honours --include-attestations, even when it
        # verified nothing. No list at all means an npm that ignored the flag (before 11.12):
        # a statement about npm, not about the release.
        raise InfraError(
            "toolchain",
            "npm audit signatures printed no `verified` list (NOT a signature result): npm lists "
            "verified attestations only when it honours --include-attestations, which needs npm 11.12 or later",
        )
    verified = sig["verified"]
    if not isinstance(verified, list) or not all(isinstance(item, dict) for item in verified):
        raise InfraError("toolchain", f"npm audit signatures printed a verified list that is not a list of objects (NOT a signature result): {verified!r:.200}")
    entries = [v for v in verified if v.get("name") == PACKAGE and v.get("version") == version]
    if len(entries) > 1:
        raise InfraError("toolchain", f"npm audit signatures lists {PACKAGE}@{version} as verified {len(entries)} times (NOT a signature result)")
    if not entries:
        raise _NotIndexedYet(f"{PACKAGE}@{version} carries no VERIFIED attestation in npm's report")
    attestations = entries[0].get("attestationBundles")
    if not isinstance(attestations, list) or not all(isinstance(item, dict) for item in attestations):
        raise InfraError("toolchain", f"npm audit signatures printed attestation bundles that are not a list of objects (NOT a signature result): {attestations!r:.200}")
    if not any(b.get("predicateType") == PUBLISH for b in attestations):
        # Absent from `missing` means something only if npm held the registry's keys, and
        # the registry's own publish attestation verifying is what shows it did.
        raise ReleaseCheckError(
            "signature",
            f"{PACKAGE}@{version} has no verified registry publish attestation, so nothing shows "
            "that npm checked the registry's signature",
        )
    bundles = [b for b in attestations if b.get("predicateType") == SLSA]
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
    payload = _field(bundles[0], "bundle", "dsseEnvelope", "payload")
    try:
        if not isinstance(payload, str):
            raise ValueError("the envelope has no payload")
        statement = parse_json(base64.b64decode(payload, validate=True).decode("utf-8"))
        if not isinstance(statement, dict):
            raise ValueError("the statement is not a JSON object")
    except (ValueError, RecursionError) as exc:
        raise ReleaseCheckError("provenance", f"the SLSA bundle's statement is unreadable: {exc}") from exc
    subjects = statement.get("subject")
    attested = {
        _field(subject, "digest", "sha512") for subject in (subjects if isinstance(subjects, list) else [])
    }
    dist_hex = base64.b64decode(integrity.split("-", 1)[1]).hex()
    wrong = {name: value for name, value in required_signer(version).items() if signer[name] != value}
    workflow = ("predicate", "buildDefinition", "externalParameters", "workflow")
    claimed = {"repository": signer["repository"], "path": pipeline["workflow"], "ref": signer["ref"]}
    disagree = [
        f"{k}: statement {_field(statement, *workflow, k)!r} != certificate {v!r}"
        for k, v in claimed.items()
        if _field(statement, *workflow, k) != v
    ]
    builder = _field(statement, "predicate", "runDetails", "builder", "id")
    if builder != GITHUB_HOSTED_BUILDER:
        disagree.append(f"builder {builder!r} != {GITHUB_HOSTED_BUILDER!r}, the github-hosted runner")
    if wrong:
        # The fields that carry the ref are the only ones a workflow dispatched on a branch
        # changes, so only a difference confined to them, in a certificate that is otherwise
        # consistent and that the statement agrees with, is said to be an off-tag publish.
        branch = signer["ref"]
        at_branch = f"{PROV_REPO}/{pipeline['workflow']}@{branch}"
        if (
            set(wrong) <= REF_FIELDS
            and branch.startswith("refs/heads/")
            and all(signer[name] == at_branch for name in ("san", "build_signer", "build_config"))
            and not disagree
        ):
            raise ReleaseCheckError(
                "provenance",
                f"{PACKAGE}@{version} was signed by {PROV_REPO} :: {pipeline['workflow']} at the branch "
                f"{branch!r}, not at its tag {required_signer(version)['ref']!r}. ai-tc's release "
                "workflow publishes only from a tag push, so an older copy of it was dispatched on a "
                "branch. An attestation is immutable, so this version can never be imported. This is "
                "not a stolen npm credential: the signing certificate names ai-tc's own workflow. "
                "Tell ai-tc's maintainers.",
            )
        raise ReleaseCheckError(
            "provenance",
            "the signing certificate does not bind this tarball to ai-tc's release workflow: "
            + "; ".join(
                f"{_field_label(name)}: attested {signer[name]!r} != required {value!r}"
                for name, value in wrong.items()
            )
            + ". A cryptographically valid attestation is NOT sufficient: anyone can publish "
            "with provenance from their own repository.",
        )
    if dist_hex not in attested:
        raise ReleaseCheckError(
            "provenance",
            f"the attestation covers a different tarball than the dist read ({integrity}); "
            "the two registry reads disagree about the bytes",
        )
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
    dependencies = _field(statement.body, "predicate", "buildDefinition", "resolvedDependencies")
    commits = [
        _field(dependency, "digest", "gitCommit")
        for dependency in (dependencies if isinstance(dependencies, list) else [])
        if isinstance(dependency, dict) and dependency.get("uri") == uri
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
    claimed = _field(statement.body, "predicate", "runDetails", "metadata", "invocationId")
    if claimed != url:
        raise ReleaseCheckError(
            "run-url", f"the statement names the run {claimed!r} but the signing certificate names {url!r}"
        )
    return url


def ai_tc_main_head(*, fetch: Fetch = http_fetch) -> str:
    """The commit ai-tc's main branch points at, read by the fully qualified ref. The short
    name `main` is ambiguous where a tag of that name exists, and ai-tc forbids no such tag,
    so nothing here compares against the name. A failed or malformed read is no verdict."""
    url = f"{AI_TC_API}/git/ref/heads/main"
    status, body = fetch(url, {})
    if status != 200:
        raise InfraError("commit-on-main", f"GET {url} answered {status}")
    try:
        ref = json.loads(body)
    except ValueError as exc:
        raise InfraError("commit-on-main", f"GET {url} answered non-JSON: {exc}") from exc
    obj = ref.get("object") if isinstance(ref, dict) else None
    sha = obj.get("sha") if isinstance(obj, dict) else None
    if (
        not isinstance(ref, dict)
        or ref.get("ref") != "refs/heads/main"
        or not isinstance(sha, str)
        or not SHA40.fullmatch(sha)
    ):
        raise InfraError("commit-on-main", f"GET {url} answered a body that names no commit for refs/heads/main")
    return sha


def commit_on_ai_tc_main(git_commit: str, *, fetch: Fetch = http_fetch) -> str:
    """Returns 'ahead' or 'identical' when the attested commit is on ai-tc main, compared
    against main's head as resolved from its full ref. Refuses behind (built on main's tip,
    never merged), diverged, 404 and every error."""
    head = ai_tc_main_head(fetch=fetch)
    url = f"{AI_TC_API}/compare/{git_commit}...{head}?per_page=1"
    status, body = fetch(url, {})
    if status in (404, 422):
        raise ReleaseCheckError("commit-on-main", f"GitHub cannot compare {git_commit} with ai-tc main ({status})")
    if status != 200:
        raise InfraError("commit-on-main", f"GET {url} answered {status}")
    result = json.loads(body).get("status")
    if result not in ("ahead", "identical"):
        raise ReleaseCheckError(
            "commit-on-main",
            f"compare {git_commit}...{head} is {result!r}: the attested commit is not on ai-tc main",
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


@dataclasses.dataclass
class Classification:
    classification: str
    migrations: list
    kinds: dict = dataclasses.field(default_factory=dict, compare=False)
    note: str = dataclasses.field(default="", compare=False)


# ai-tc runs a migration as the chunks left by splitting its text on this pattern, wherever
# it stands: after a statement on the same line, inside a comment, across a line break (see
# splitStatements in its migrations module). The split is on the raw text, before any quote
# or comment is read, so it is made first here too. JavaScript's \s is not Python's: it
# counts U+FEFF and leaves out a few control characters, so its set is spelled out.
_JS_WHITESPACE = "".join(
    map(
        chr,
        (0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680, *range(0x2000, 0x200B))
        + (0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF),
    )
)
STATEMENT_BREAKPOINT = re.compile("-->[" + re.escape(_JS_WHITESPACE) + "]*statement-breakpoint")


class _Unterminated(ValueError):
    """A quoted string or name, or a block comment, that never closes."""


def _closing_quote(text: str, start: int) -> int:
    """The index of the quote that closes the one at `start`. A doubled quote inside reads
    as a close and a re-open, which comes to the same thing, so it needs no case of its own."""
    stop = text.find(text[start], start + 1)
    if stop < 0:
        raise _Unterminated(f"a {text[start]} at {start} is never closed")
    return stop


def _chunk_statements(chunk: str) -> list:
    """The statements of one chunk, read left to right the way SQLite reads them.

    A single-quoted string becomes '' (what it says decides nothing, and a ';' or '--' in it
    ends nothing). A quoted name ("..." `...` [...]) is kept whole, so a __new_ table is
    still seen. A -- comment runs to the end of the line and a /* */ comment to its close;
    both are dropped. A ';' outside all of those ends a statement."""
    statements: list = []
    parts: list = []

    def end() -> None:
        statement = " ".join("".join(parts).split())
        if statement:
            statements.append(statement)
        parts.clear()

    i, size = 0, len(chunk)
    while i < size:
        char = chunk[i]
        if char == "'":
            i = _closing_quote(chunk, i) + 1
            parts.append("''")
        elif char in '"`':
            stop = _closing_quote(chunk, i) + 1
            parts.append(chunk[i:stop])
            i = stop
        elif char == "[":
            stop = chunk.find("]", i + 1) + 1
            if stop == 0:
                raise _Unterminated(f"a [ at {i} is never closed")
            parts.append(chunk[i:stop])
            i = stop
        elif chunk.startswith("--", i):
            stop = chunk.find("\n", i)
            i = size if stop < 0 else stop
            parts.append(" ")
        elif chunk.startswith("/*", i):
            stop = chunk.find("*/", i + 2)
            if stop < 0:
                raise _Unterminated(f"a /* at {i} is never closed")
            i = stop + 2
            parts.append(" ")
        elif char == ";":
            end()
            i += 1
        else:
            parts.append(char)
            i += 1
    end()
    return statements


def _statements(sql: str) -> list:
    """Every statement ai-tc would run for one migration file. Raises _Unterminated."""
    return [statement for chunk in STATEMENT_BREAKPOINT.split(sql) for statement in _chunk_statements(chunk)]


def _non_additive_reason(statement: str) -> str | None:
    upper = statement.upper()
    if upper.startswith("PRAGMA "):
        # The two drizzle writes around a table rebuild, and nothing else: any other
        # pragma changes how the store behaves (journal mode, schema writes, user_version).
        if re.fullmatch(r"PRAGMA FOREIGN_KEYS\s*=\s*(?:ON|OFF)", upper):
            return None
        return "a PRAGMA other than foreign_keys=ON/OFF"
    if "__NEW_" in upper:
        return "a table rebuild (drizzle's __new_ copy)"
    if re.match(r"CREATE TABLE ", upper) or re.match(r"CREATE INDEX ", upper):
        return None
    if re.match(r"CREATE UNIQUE INDEX ", upper):
        return "a UNIQUE index, a new constraint an older build's writes can violate"
    added = re.match(r"ALTER TABLE \S+ ADD (?:COLUMN )?(?:`[^`]*`|\"[^\"]*\"|\[[^\]]*\]|\S+)(.*)", upper)
    if added:
        # Only the words after the column's name count, and only as words: the name itself
        # (`is_default`, `x default`) and any quoted name further on are not keywords.
        definition = re.sub(r"`[^`]*`|\"[^\"]*\"|\[[^\]]*\]", " ", added.group(1))
        if re.search(r"\bNOT NULL\b", definition) and not re.search(r"\b(?:DEFAULT|GENERATED)\b", definition):
            return "a NOT NULL column without a default"
        return None
    if re.match(r"ALTER TABLE \S+ RENAME", upper):
        return "a rename"
    if re.match(r"ALTER TABLE \S+ DROP", upper):
        return "a dropped column"
    if upper.startswith("DROP "):
        return "a drop (" + " ".join(upper.split()[:2]).lower() + ")"
    if re.match(r"CREATE (?:TEMP |TEMPORARY )?VIEW ", upper):
        return "a view, which may stand in for a former table"
    if re.match(r"CREATE (?:TEMP |TEMPORARY )?TRIGGER ", upper):
        return "a trigger, which changes what an older build's writes do"
    return "an unrecognised statement"


def migration_kind(sql: str) -> str:
    """'additive', or 'non-additive: <first reason>', for one migration file."""
    try:
        statements = _statements(sql)
    except _Unterminated:
        return "non-additive: an unterminated quoted string or comment"
    if not statements:
        return "non-additive: no statements"
    for statement in statements:
        reason = _non_additive_reason(statement)
        if reason:
            return f"non-additive: {reason}"
    return "additive"


def _ai_tc_file(path: str, commit: str, fetch: Fetch) -> str | None:
    url = f"{AI_TC_API}/contents/{path}?ref={commit}"
    status, body = fetch(url, {"Accept": "application/vnd.github.raw+json"})
    if status == 404:
        return None
    if status != 200:
        raise InfraError("classify", f"GET {url} answered {status}")
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as exc:
        # The file at an attested commit never changes, so this is a verdict, not an outage.
        raise ReleaseCheckError("classify", f"{path} at {commit} is not UTF-8: {exc}") from exc


def _journal_tags(commit: str, fetch: Fetch):
    raw = _ai_tc_file(f"{MIGRATIONS_DIR}/meta/_journal.json", commit, fetch)
    if raw is None:
        return None
    try:
        document = parse_json(raw)
    except (ValueError, RecursionError) as exc:
        raise ReleaseCheckError("classify", f"the migration journal at {commit} does not parse: {exc}") from exc
    entries = document.get("entries") if isinstance(document, dict) else None
    tags = [e.get("tag") if isinstance(e, dict) else None for e in entries] if isinstance(entries, list) else None
    if tags is None or not all(isinstance(t, str) and MIGRATION_TAG.fullmatch(t) for t in tags):
        raise ReleaseCheckError("classify", f"the migration journal at {commit} has an unexpected shape")
    return tags


# The Contents API lists at most this many entries of a directory, and does not say it stopped.
CONTENTS_LISTING_CAP = 1000
EDITED_IN_PLACE = "non-additive: modified in place since the earlier release"
UNREADABLE_FILE = "non-additive: the migration file cannot be read"


def _migration_blobs(commit: str, fetch: Fetch) -> dict | None:
    """{tag: git blob sha} for every <tag>.sql in ai-tc's migrations directory at commit,
    or None when that directory is not there. One request however many files it holds.
    The raw media type the file reads use returns bytes with no sha, so this asks for the
    JSON listing instead."""
    url = f"{AI_TC_API}/contents/{MIGRATIONS_DIR}?ref={commit}"
    status, body = fetch(url, {"Accept": "application/vnd.github+json"})
    if status == 404:
        return None
    if status != 200:
        raise InfraError("classify", f"GET {url} answered {status}")
    try:
        listing = parse_json(body.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        raise InfraError("classify", f"GET {url} answered non-JSON: {exc}") from exc
    if not isinstance(listing, list) or not all(isinstance(entry, dict) for entry in listing):
        raise InfraError("classify", f"GET {url} did not answer a directory listing")
    if len(listing) >= CONTENTS_LISTING_CAP:
        raise InfraError(
            "classify", f"GET {url} lists {len(listing)} entries, the API's cap, so the listing may be incomplete"
        )
    return {
        entry["name"][: -len(".sql")]: entry.get("sha")
        for entry in listing
        if entry.get("type") == "file" and isinstance(entry.get("name"), str) and entry["name"].endswith(".sql")
    }


def _edited_in_place(tags: list, from_commit: str, to_commit: str, fetch: Fetch) -> dict:
    """{tag: kind} for each migration that both journals name and whose file is not the same
    blob at the two commits, or cannot be compared. ai-tc's store migrator records an
    applied migration by its tag and never re-runs it, so an edit changes what a fresh store
    gets but not what an existing one has: the two diverge, and no rollback across the
    release is safe. A file that cannot be found counts the same way, as it does for an added
    migration. A listing that fails or is malformed is no verdict."""
    if not tags:
        return {}
    listings = [_migration_blobs(commit, fetch) for commit in (from_commit, to_commit)]
    kinds = {}
    for tag in tags:
        shas = []
        for blobs in listings:
            if blobs is None or tag not in blobs:
                shas.append(None)
                continue
            sha = blobs[tag]
            if not isinstance(sha, str) or not SHA40.fullmatch(sha):
                raise InfraError("classify", f"ai-tc's listing gave {sha!r} as the blob sha of {tag}.sql")
            shas.append(sha)
        if None in shas:
            kinds[tag] = UNREADABLE_FILE
        elif shas[0] != shas[1]:
            kinds[tag] = EDITED_IN_PLACE
    return kinds


def classify_migrations(from_commit: str, to_commit: str, *, fetch: Fetch = http_fetch) -> Classification:
    """Classify the local-store migrations ai-tc added, removed from the journal or edited
    in place between two attested commits."""
    for commit in (from_commit, to_commit):
        if not isinstance(commit, str) or not SHA40.fullmatch(commit):
            raise ReleaseCheckError("classify", f"{commit!r} is not a 40-hex commit id")
    before = _journal_tags(from_commit, fetch)
    after = _journal_tags(to_commit, fetch)
    if before is None or after is None:
        unreadable = from_commit if before is None else to_commit
        return Classification(
            "not-rollback-safe",
            [],
            note=f"the migration journal at {unreadable} cannot be read, so the version counts as not rollback-safe",
        )
    added = [t for t in after if t not in before]
    removed = [t for t in before if t not in after]
    kinds = {}
    for tag in added:
        sql = _ai_tc_file(f"{MIGRATIONS_DIR}/{tag}.sql", to_commit, fetch)
        kinds[tag] = UNREADABLE_FILE if sql is None else migration_kind(sql)
    for tag in removed:
        kinds[tag] = "non-additive: removed from the journal (history rewritten)"
    edited = _edited_in_place([t for t in after if t in before], from_commit, to_commit, fetch)
    kinds.update(edited)
    migrations = added + removed + list(edited)
    if not migrations:
        return Classification("additive", [], kinds)
    if EVERY_MIGRATION_COUNTS:
        return Classification(
            "not-rollback-safe",
            migrations,
            kinds,
            note="every migration counts as not rollback-safe until an older build is measured on a store the newer one migrated",
        )
    flagged = any(kind != "additive" for kind in kinds.values())
    return Classification("not-rollback-safe" if flagged else "additive", migrations, kinds)


SAFETY_KEYS = ["classification", "from", "to", "migrations"]


def _entry_problems(version, entry) -> list:
    """What is wrong with one rollback-safety.json entry (empty = well formed)."""
    where = f"{SAFETY_FILE} {version!r}"
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        return [f"{where}: not an exact x.y.z"]
    if not isinstance(entry, dict) or list(entry) != SAFETY_KEYS:
        return [f"{where}: keys must be exactly {SAFETY_KEYS}, in that order"]
    problems = []
    if entry["classification"] not in ("additive", "not-rollback-safe"):
        problems.append(f"{where}: classification must be additive or not-rollback-safe")
    for key in ("from", "to"):
        if not isinstance(entry[key], str) or not SHA40.fullmatch(entry[key]):
            problems.append(f"{where}: {key} must be a 40-hex commit id")
    migrations = entry["migrations"]
    if not isinstance(migrations, list) or not all(isinstance(m, str) and MIGRATION_TAG.fullmatch(m) for m in migrations):
        problems.append(f"{where}: migrations must be a list of migration tags")
    return problems


def safety_problems(doc) -> list:
    """What is wrong with a rollback-safety.json document (empty = well formed)."""
    if not isinstance(doc, dict) or list(doc) != ["versions"] or not isinstance(doc["versions"], dict):
        return [f'{SAFETY_FILE} must be exactly {{"versions": {{...}}}}']
    return [problem for version, entry in doc["versions"].items() for problem in _entry_problems(version, entry)]


def safety_entry(version: str, pinned: set, *, verify=verify_release, classify=classify_migrations) -> dict:
    """The rollback-safety.json entry for version: its migrations since the highest pinned
    version below it, classified, with the two attested commits."""
    below = [p for p in pinned if vkey(p) < vkey(version)]
    if not below:
        raise ReleaseCheckError("safety", f"no pinned version is below {version} to compute its migrations from")
    start = verify(max(below, key=vkey)).git_commit
    end = verify(version).git_commit
    result = classify(start, end)
    return {"classification": result.classification, "from": start, "to": end, "migrations": list(result.migrations)}


def rollback_floor(safety: dict, target: str, highest_pinned: str, *, pinned=()) -> str | None:
    """The lowest version V flagged not rollback-safe with target < V <= highest_pinned,
    or None. Anything but an explicit, well-formed "additive" entry counts as flagged, and
    so does a version in `pinned` with no entry at all: a pin that reached main without a
    computed entry (a break-glass merge, a restore, a hand-run import) is no evidence of
    safety. An entry is judged on its own: one malformed entry flags its own version and
    does not stop the others being read, because refusing the file would block every
    rollback."""
    versions = safety.get("versions") if isinstance(safety, dict) else None
    if not isinstance(versions, dict):
        raise ReleaseCheckError("safety", f'{SAFETY_FILE} must be {{"versions": {{...}}}}')
    low, high = vkey(target), vkey(highest_pinned)
    candidates = set(versions) | {v for v in pinned if isinstance(v, str)}
    flagged = [
        version
        for version in candidates
        if isinstance(version, str)
        and SEMVER.fullmatch(version)
        and low < vkey(version) <= high
        and not (
            version in versions
            and not _entry_problems(version, versions[version])
            and versions[version]["classification"] == "additive"
        )
    ]
    return min(flagged, key=vkey) if flagged else None


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _rest_of(manifest: dict) -> tuple:
    """Everything a pin change must leave alone: the top-level keys, and every other entry
    in any order."""
    top = {k: v for k, v in manifest.items() if k != "plugins"}
    others = sorted(_canonical(p) for p in _plugins(manifest) if not _is_ai_tc(p))
    return _canonical(top), others


def _integrity_only(metadata) -> bool:
    return (
        isinstance(metadata, dict)
        and set(metadata) == {"integrity"}
        and isinstance(metadata["integrity"], str)
        and INTEGRITY.fullmatch(metadata["integrity"]) is not None
    )


def _restore_shape(entry: dict) -> bool:
    """{name: ai-tc, source: {npm, PACKAGE, x.y.z, REGISTRY}, description, metadata: {integrity}}."""
    source = entry.get("source")
    return (
        set(entry) == {"name", "source", "description", "metadata"}
        and entry["name"] == ENTRY_NAME
        and isinstance(entry["description"], str)
        and entry["description"].strip() != ""
        and isinstance(source, dict)
        and set(source) == {"source", "package", "version", "registry"}
        and source["source"] == "npm"
        and source["package"] == PACKAGE
        and source["registry"] == REGISTRY
        and entry_version(entry) is not None
        and _integrity_only(entry["metadata"])
    )


def _without_pin(entry: dict) -> dict:
    stripped = {k: v for k, v in entry.items() if k != "metadata"}
    if isinstance(stripped.get("source"), dict):
        stripped["source"] = {k: v for k, v in stripped["source"].items() if k != "version"}
    return stripped


def diff_mode(base_manifest: dict, head_manifest: dict) -> str:
    """Which importer mode a manifest change is EXACTLY. 'none' means the ai-tc entry is
    unchanged; 'human' means any other change to it."""
    base, head = find_ai_tc_entry(base_manifest), find_ai_tc_entry(head_manifest)
    if base == head:
        return "none"
    if _rest_of(base_manifest) != _rest_of(head_manifest):
        return "human"
    if head is None:
        return "remove"
    if base is None:
        return "restore" if _restore_shape(head) else "human"
    old, new = entry_version(base), entry_version(head)
    if old is None or new is None or old == new:
        return "human"
    if _without_pin(base) != _without_pin(head) or not _integrity_only(head.get("metadata")):
        return "human"
    if "metadata" in base and not _integrity_only(base["metadata"]):
        return "human"
    return "advance" if vkey(new) > vkey(old) else "rollback"


# The rulesets this repository must carry: name -> (target, rule types). Bypass lists are
# visible only to admins, so they are proven by probe when the rulesets are created.
EXPECTED_RULESETS = {
    "main": ("branch", {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}),
    "tags-locked": ("tag", {"creation", "update", "deletion"}),
    "fleet-tags-create": ("tag", {"creation"}),
    "fleet-tags-immutable": ("tag", {"update", "deletion", "non_fast_forward"}),
    "bot-branches": ("branch", {"creation", "update", "deletion"}),
    "x4-branches": ("branch", {"creation", "update", "deletion"}),
    "x4-tags": ("tag", {"creation", "update", "deletion"}),
}

# name -> (the accepted conditions.ref_name include lists, the exclude list). A ruleset
# retargeted away from its refs keeps rules that still read correctly while it protects
# nothing, so the patterns are audited too. main is named, never ~DEFAULT_BRANCH: a
# default-branch switch must not move it. Rulesets match with FNM_PATHNAME (`*` stops at
# `/`), so bot-branches and tags-locked each list both depths. tags-locked never uses ~ALL:
# GitHub documents it as every branch, and on a tag ruleset it could lock no tag.
EXPECTED_REF_PATTERNS = {
    "main": ([["refs/heads/main"]], []),
    "tags-locked": ([["refs/tags/*", "refs/tags/**/*"]], ["refs/tags/fleet-v*"]),
    "fleet-tags-create": ([["refs/tags/fleet-v*"]], []),
    "fleet-tags-immutable": ([["refs/tags/fleet-v*"]], []),
    "bot-branches": ([["refs/heads/bot/*", "refs/heads/bot/**/*"]], []),
    "x4-branches": ([["refs/heads/x4/*"]], []),
    "x4-tags": ([["refs/tags/x4/*"]], []),
}


def snapshot_tags(repo_dir: str) -> list:
    """[{tag, object, commit}] for every fleet-v tag: the frozen list's shape."""
    return [
        {
            "tag": tag,
            "object": _git(repo_dir, "rev-parse", f"refs/tags/{tag}").strip(),
            "commit": _git(repo_dir, "rev-parse", f"refs/tags/{tag}^{{commit}}").strip(),
        }
        for tag in fleet_tags(repo_dir)
    ]


def parse_tag_message(text: str) -> dict:
    """A fleet-v tag message: the subject line, then `key: value` lines (the first one wins)."""
    lines = text.splitlines()
    fields = {"subject": lines[0].strip() if lines else ""}
    for line in lines[1:]:
        match = re.fullmatch(r"([a-z][a-z-]*): (.+)", line.strip())
        if match and match.group(1) not in fields:
            fields[match.group(1)] = match.group(2).strip()
    return fields


def _tag_rows(path: str, label: str, problems: list):
    try:
        with open(path, encoding="utf-8") as handle:
            rows = parse_json(handle.read())
    except (OSError, ValueError) as exc:
        problems.append(f"the {label} {path} is unreadable: {exc}")
        return None
    well_formed = isinstance(rows, list) and all(
        isinstance(r, dict)
        and set(r) == {"tag", "object", "commit"}
        and isinstance(r["tag"], str)
        and FLEET_TAG.fullmatch(r["tag"])
        and isinstance(r["object"], str)
        and SHA40.fullmatch(r["object"])
        and isinstance(r["commit"], str)
        and SHA40.fullmatch(r["commit"])
        for r in rows
    )
    if not well_formed:
        problems.append(f"the {label} {path} must be a list of {{tag, object, commit}} rows")
        return None
    return rows


def _audit_new_tag(repo_dir, name, row, here, previous, fetch) -> list:
    """The checks for a tag cut after the frozen list, i.e. by tag-release."""
    problems = []
    commit = row["commit"]
    if here is None:
        problems.append(f"{name}'s commit {commit} is not on main's first-parent history")
    elif previous[0] is not None and here <= previous[0]:
        problems.append(f"{name}'s commit is not later on main than {previous[1]}'s")
    message = parse_tag_message(_git(repo_dir, "for-each-ref", "--format=%(contents)", f"refs/tags/{name}"))
    recorded = message.get("version", "")
    if message["subject"] != f"{name}: ai-tc {recorded}":
        problems.append(f"{name}'s subject {message['subject']!r} is not '{name}: ai-tc <version>'")
    try:
        entry = find_ai_tc_entry(_read_manifest(repo_dir, commit))
        expected = "entry removed" if entry is None else entry_version(entry)
    except (ReleaseCheckError, ValueError) as exc:
        expected = f"an unreadable manifest ({exc})"
    if recorded != expected:
        problems.append(f"{name} records version {recorded!r}, but the manifest at its commit pins {expected!r}")
    number = re.fullmatch(r"#?([1-9][0-9]*)", message.get("pr", ""))
    if number is None:
        problems.append(f"{name} names no PR (a 'pr: <number>' line)")
        return problems
    status, body = fetch(f"{MARKETPLACE_API}/pulls/{number.group(1)}", {})
    if status != 200:
        problems.append(f"{name}: GET pull {number.group(1)} answered {status}")
        return problems
    pull = json.loads(body)
    author = (pull.get("user") or {}).get("login")
    if BOT_LOGIN is None:
        problems.append(f"{name}: no bot identity is configured (release_checks.BOT_LOGIN), so no tag after the frozen list can be confirmed")
    elif author != BOT_LOGIN:
        problems.append(
            f"{name}: PR #{number.group(1)} was opened by {author}, not the bot App ({BOT_LOGIN}); "
            f"a break-glass PR's tag stays red until a reviewed PR adds it to {FROZEN_TAGS_FILE}"
        )
    if not pull.get("merged_at") or pull.get("merge_commit_sha") != commit:
        problems.append(f"{name}: PR #{number.group(1)} is not merged with {commit} as its merge commit")
    return problems


def _main_ruleset_problems(rules: dict) -> list:
    problems = []
    review = rules.get("pull_request") or {}
    count = review.get("required_approving_review_count")
    if not isinstance(count, int) or count < 1:
        problems.append(f"ruleset 'main': required_approving_review_count is {count!r}, not at least 1")
    for key in ("require_code_owner_review", "dismiss_stale_reviews_on_push", "require_last_push_approval"):
        if review.get(key) is not True:
            problems.append(f"ruleset 'main': {key} is {review.get(key)!r}, not True")
    if review.get("allowed_merge_methods") != ["squash"]:
        problems.append(f"ruleset 'main': allowed_merge_methods is {review.get('allowed_merge_methods')!r}, not ['squash']")
    checks = (rules.get("required_status_checks") or {}).get("required_status_checks") or []
    if not any(
        isinstance(c, dict) and c.get("context") == "validate" and c.get("integration_id") == GITHUB_ACTIONS_APP_ID
        for c in checks
    ):
        problems.append("ruleset 'main' does not require the validate check from the GitHub Actions app")
    return problems


def audit_rulesets(*, fetch: Fetch = http_fetch) -> list:
    """Every expected ruleset exists, is active, targets the right refs and has its rules."""
    status, body = fetch(f"{MARKETPLACE_API}/rulesets?targets=branch,tag&per_page=100", {})
    if status != 200:
        return [f"could not list the repository's rulesets (HTTP {status})"]
    listed = {r.get("name"): r for r in json.loads(body) if isinstance(r, dict)}
    problems = []
    for name, (target, rule_types) in EXPECTED_RULESETS.items():
        summary = listed.get(name)
        if summary is None:
            problems.append(f"ruleset {name!r} does not exist")
            continue
        status, body = fetch(f"{MARKETPLACE_API}/rulesets/{summary.get('id')}", {})
        if status != 200:
            problems.append(f"ruleset {name!r}: GET answered {status}")
            continue
        ruleset = json.loads(body)
        if ruleset.get("enforcement") != "active":
            problems.append(f"ruleset {name!r} is {ruleset.get('enforcement')!r}, not active")
        if ruleset.get("target") != target:
            problems.append(f"ruleset {name!r} targets {ruleset.get('target')!r}, not {target!r}")
        includes, exclude = EXPECTED_REF_PATTERNS[name]
        ref_name = (ruleset.get("conditions") or {}).get("ref_name") or {}
        got_include, got_exclude = sorted(ref_name.get("include") or []), sorted(ref_name.get("exclude") or [])
        if got_include not in [sorted(option) for option in includes] or got_exclude != sorted(exclude):
            wanted = " or ".join(str(sorted(option)) for option in includes)
            problems.append(
                f"ruleset {name!r} covers include {got_include} exclude {got_exclude}, "
                f"not include {wanted} exclude {sorted(exclude)}"
            )
        rules = {r.get("type"): r.get("parameters") or {} for r in ruleset.get("rules") or [] if isinstance(r, dict)}
        missing = sorted(rule_types - set(rules))
        if missing:
            problems.append(f"ruleset {name!r} lacks rules: {', '.join(missing)}")
        if name == "main":
            problems.extend(_main_ruleset_problems(rules))
    return problems


def audit_tags(repo_dir: str, frozen_path: str, *, previous_path=None, fetch: Fetch = http_fetch, check_rulesets=True) -> list:
    """Every problem with the fleet-v ledger (and the rulesets); empty means pass. This is
    detection, not prevention: the rulesets prevent, and this notices when one was edited."""
    problems = []
    current = {row["tag"]: row for row in snapshot_tags(repo_dir)}
    for name in _git(repo_dir, "for-each-ref", "--format=%(refname:strip=2)", "refs/tags").split():
        if not FLEET_TAG.fullmatch(name):
            problems.append(f"tag {name!r} exists: no tag other than fleet-v<N> may exist")
    frozen = _tag_rows(frozen_path, "frozen tag list", problems)
    if frozen is None:
        return problems
    compared = [("frozen list", frozen)]
    if previous_path is not None and os.path.exists(previous_path):
        compared.append(("previous run", _tag_rows(previous_path, "previous run's tag list", problems) or []))
    for label, rows in compared:
        for row in rows:
            now = current.get(row["tag"])
            if now is None:
                problems.append(f"{row['tag']} is in the {label} but no longer exists")
            elif now != row:
                problems.append(
                    f"{row['tag']} changed since the {label}: {row['object']} -> {row['commit']} "
                    f"is now {now['object']} -> {now['commit']}"
                )
    for name, row in current.items():
        if _git(repo_dir, "cat-file", "-t", row["object"]).strip() != "tag":
            problems.append(f"{name} is a lightweight tag; every fleet-v tag is annotated")
    numbers = sorted(int(name[len("fleet-v"):]) for name in current)
    if numbers != list(range(1, len(numbers) + 1)):
        problems.append(f"fleet-v numbering is not contiguous from 1: {numbers}")
    frozen_names = {row["tag"] for row in frozen}
    order = _git(repo_dir, "rev-list", "--first-parent", "--reverse", main_ref(repo_dir)).split()
    position = {commit: index for index, commit in enumerate(order)}
    previous = (None, None)
    for name in fleet_tags(repo_dir):
        row = current[name]
        here = position.get(row["commit"])
        if name not in frozen_names:
            problems.extend(_audit_new_tag(repo_dir, name, row, here, previous, fetch))
        previous = (here, name)
    if check_rulesets:
        problems.extend(audit_rulesets(fetch=fetch))
    return problems


def _emit(document, code: int) -> int:
    print(json.dumps(document, indent=2, ensure_ascii=False))
    return code


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="release_checks.py", description="Release checks for the ai-tc pin.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("verify-version", help="verify one npm release end to end").add_argument("version")
    candidates = sub.add_parser("candidates", help="exact npm versions above everything pinned")
    candidates.add_argument("--repo", default=".")
    classify = sub.add_parser("classify", help="classify ai-tc's store migrations between two commits")
    classify.add_argument("from_commit")
    classify.add_argument("to_commit")
    entry = sub.add_parser("safety-entry", help="the rollback-safety.json entry for a version")
    entry.add_argument("version")
    entry.add_argument("--repo", default=".")
    floor = sub.add_parser("floor", help="the rollback floor a target would cross")
    floor.add_argument("target")
    floor.add_argument("--repo", default=".")
    floor.add_argument("--safety", default=SAFETY_FILE)
    audit = sub.add_parser("audit-tags", help="audit the fleet-v tags and the rulesets")
    audit.add_argument("--repo", default=".")
    audit.add_argument("--frozen", default=FROZEN_TAGS_FILE)
    audit.add_argument("--previous", default=None)
    audit.add_argument("--no-rulesets", action="store_true")
    sub.add_parser("snapshot-tags", help="the fleet-v tags in the frozen list's shape").add_argument("--repo", default=".")
    mode = sub.add_parser("diff-mode", help="classify a manifest change")
    mode.add_argument("base")
    mode.add_argument("head")
    return parser


def _load(path: str):
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    try:
        return parse_json(text)
    except ValueError as exc:
        raise ReleaseCheckError("parse", f"{path} does not parse: {exc}") from exc


def _command(args) -> int:
    if args.command == "verify-version":
        release = verify_release(args.version)
        print(f"OK: {PACKAGE}@{release.version} built from {release.git_commit} on ai-tc main", file=sys.stderr)
        return _emit(dataclasses.asdict(release), 0)
    if args.command == "candidates":
        pinned = pinned_versions(args.repo)
        return _emit({"pinned": sorted(pinned, key=vkey), "candidates": npm_candidates(pinned)}, 0)
    if args.command == "classify":
        result = classify_migrations(args.from_commit, args.to_commit)
        for tag, kind in result.kinds.items():
            print(f"{tag}: {kind}", file=sys.stderr)
        if result.note:
            print(result.note, file=sys.stderr)
        return _emit(
            {"classification": result.classification, "from": args.from_commit, "to": args.to_commit, "migrations": result.migrations},
            0,
        )
    if args.command == "safety-entry":
        return _emit({"version": args.version, "entry": safety_entry(args.version, pinned_versions(args.repo))}, 0)
    if args.command == "floor":
        safety = _load(args.safety)
        pinned = pinned_versions(args.repo)
        if not pinned:
            raise ReleaseCheckError("floor", "nothing is pinned, so there is no rollback to judge")
        highest = max(pinned, key=vkey)
        floor = rollback_floor(safety, args.target, highest, pinned=pinned)
        result = {"target": args.target, "highest_pinned": highest, "floor": floor}
        if floor is None:
            return _emit(result, 0)
        detail = f"{args.target} is below {floor}, which is flagged not rollback-safe"
        print(f"::error::floor: {detail}", file=sys.stderr)
        result["error"] = {"check": "floor", "detail": detail}
        return _emit(result, 1)
    if args.command == "audit-tags":
        problems = audit_tags(args.repo, args.frozen, previous_path=args.previous, check_rulesets=not args.no_rulesets)
        for problem in problems:
            print(f"::error::{problem}", file=sys.stderr)
        return _emit({"problems": problems}, 1 if problems else 0)
    if args.command == "snapshot-tags":
        return _emit(snapshot_tags(args.repo), 0)
    return _emit({"mode": diff_mode(_load(args.base), _load(args.head))}, 0)


def main(argv=None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    try:
        return _command(args)
    except InfraError as exc:
        print(f"::error::{exc.check}: {exc.detail}", file=sys.stderr)
        return _emit({"error": {"check": exc.check, "detail": exc.detail}}, 2)
    except ReleaseCheckError as exc:
        print(f"::error::{exc.check}: {exc.detail}", file=sys.stderr)
        return _emit({"error": {"check": exc.check, "detail": exc.detail}}, 1)
    except (OSError, ValueError) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return _emit({"error": {"check": "usage", "detail": str(exc)}}, 2)
    except Exception as exc:
        # Neither a verdict nor a known failure: a defect in this tool, or a document shaped in
        # a way it did not expect. It reached no verdict, so it must not exit 1 (a verdict).
        # KeyboardInterrupt and SystemExit are not Exceptions and pass through.
        detail = f"{type(exc).__name__}: {exc}"
        print(f"::error::internal: {detail}", file=sys.stderr)
        return _emit({"error": {"check": "internal", "detail": detail}}, 2)


if __name__ == "__main__":
    sys.exit(main())
