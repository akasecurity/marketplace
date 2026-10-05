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
import http.client
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

# This version has no command line yet, and the docstring above says exit 0 is a pass. Run as
# a program, the file therefore says so and exits 2 (no verdict), never the silent 0 that
# `release_checks.py verify X && proceed` would read as a pass. The command line replaces
# this guard. Importing the module is unaffected.
if __name__ == "__main__":
    print("release_checks.py: this version has no command line; nothing was checked", file=sys.stderr)
    sys.exit(2)

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
    """json.loads that refuses duplicate keys and NaN/Infinity, which jq and json.loads accept.

    Every refusal is a ValueError, including text nested deeper than the parser reads:
    json.loads raises RecursionError for that, which is not a ValueError, so a caller that
    treats an unreadable document as a ValueError would crash on it. A fleet tag is permanent
    and each tag's manifest is read on every run, so one such tag would otherwise stop every
    later run."""
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
    except RecursionError as exc:
        raise ValueError("the document is too deeply nested to read") from exc


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
    """Only api.github.com ever sees the job's token, and never across a redirect (http_fetch
    follows none); the registry is read anonymously."""
    return urllib.parse.urlsplit(url).hostname == "api.github.com"


def _headers_for(url: str, extra: dict) -> dict:
    headers = {"User-Agent": "akasecurity-marketplace-release-checks", **extra}
    if _sends_token_to(url):
        headers.setdefault("Accept", "application/vnd.github+json")
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        if os.environ.get("GITHUB_TOKEN"):
            headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    return headers


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Follows no redirect, so a 30x comes back as its own status. urllib's default handler
    copies the request's headers onto the follow-up request, Authorization included, even
    when it goes to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def http_fetch(url: str, headers: dict) -> tuple:
    """GET url. An HTTP error status is returned, not raised, and a redirect is not followed
    (its status is returned like any other); no answer at all is InfraError, and so is an
    answer that stops partway: http.client raises its own errors from the status line and
    the body, which urllib does not wrap, and reading an error status's body can fail the
    same way."""
    request = urllib.request.Request(url, headers=_headers_for(url, headers))
    try:
        try:
            with _OPENER.open(request, timeout=60) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
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
    except (ValueError, RecursionError) as exc:
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
    caller judges what the attestation binds. Needs an npm that honours
    --include-attestations (11.12 or later). An older one prints no `verified` list at all,
    which provenance_verdict reports as a toolchain failure, not as a missing attestation."""
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
    """(integrity, shasum) npmjs serves for PACKAGE@version, from ONE registry document.

    Any answer but a 200 is read again, ATTEMPTS times in all, because a new publish lags on
    the read replicas. A 404 that outlasts them is a verdict (the registry does not serve
    this version). Any other last answer (a 429, a 403, a 5xx) says nothing about the
    release, so it is no verdict. A 200 is not read again: a body that is not a JSON object
    is no verdict at once, while a JSON document that holds no dist for this version, or a
    malformed integrity or shasum, is a verdict."""
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

# How a run on a branch is told to the people who must act on it, by the trigger the
# certificate records. Only these two are known to be what they say. Any other trigger
# (a schedule, a call from another workflow) gets the plain refusal, with no account of
# what happened and no assurance that nothing was stolen.
BRANCH_RUNS = {
    "workflow_dispatch": "an older copy of it was dispatched on a branch",
    "push": "a copy of it that publishes from a branch was pushed on that branch",
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
    # Only text can be the digest of the tarball. A list or an object in a later subject (npm
    # checks only the first) is unhashable, and putting it in this set would raise TypeError
    # here, before the certificate's identity is checked below, and lose that refusal.
    attested = {
        digest
        for digest in (
            _field(subject, "digest", "sha512") for subject in (subjects if isinstance(subjects, list) else [])
        )
        if isinstance(digest, str)
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
        # The fields that carry the ref are the only ones a workflow run on a branch changes
        # (a dispatch changes the trigger too), so only a difference confined to them, in a
        # certificate that is otherwise consistent, that the statement agrees with, and whose
        # trigger BRANCH_RUNS can tell, is said to be an off-tag publish.
        branch = signer["ref"]
        at_branch = f"{PROV_REPO}/{pipeline['workflow']}@{branch}"
        happened = BRANCH_RUNS.get(signer["trigger"])
        if (
            happened is not None
            and set(wrong) <= REF_FIELDS
            and branch.startswith("refs/heads/")
            and all(signer[name] == at_branch for name in ("san", "build_signer", "build_config"))
            and not disagree
        ):
            raise ReleaseCheckError(
                "provenance",
                f"{PACKAGE}@{version} was signed by {PROV_REPO} :: {pipeline['workflow']} at the branch "
                f"{branch!r}, not at its tag {required_signer(version)['ref']!r}. ai-tc's release "
                f"workflow publishes only from a tag push, so {happened}. An attestation is "
                "immutable, so this version can never be imported. This is not a stolen npm "
                "credential: the signing certificate names ai-tc's own workflow. Tell ai-tc's "
                "maintainers.",
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


# One SQLite name: quoted with backticks, double quotes or brackets (a doubled quote inside stands
# for one quote), or a run with no quote, space or dot in it. A table and a column are read the
# same way, so a quoted name that holds the words ADD or DROP stays one name instead of
# starting a clause; the table may carry a schema in front of it. The dot is left out of the
# bare run so the schema's dot has one reading and the match stays linear on a long token.
_SQL_NAME = r"(?:`(?:[^`]|``)*`|\"(?:[^\"]|\"\")*\"|\[[^\]]*\]|[^\s`\"\[\].]+)"
_SQL_TABLE = rf"(?:{_SQL_NAME}\.)?{_SQL_NAME}"


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
    added = re.match(rf"ALTER TABLE {_SQL_TABLE} ADD (?:COLUMN )?{_SQL_NAME}(.*)", upper)
    if added:
        # Only the words after the column's name count, and only as words: the name itself
        # (`is_default`, `x default`) and any quoted name further on are not keywords.
        definition = re.sub(r"`[^`]*`|\"[^\"]*\"|\[[^\]]*\]", " ", added.group(1))
        if re.search(r"\bNOT NULL\b", definition) and not re.search(r"\b(?:DEFAULT|GENERATED)\b", definition):
            return "a NOT NULL column without a default"
        if re.search(r"\bCHECK\b", definition):
            return "a CHECK constraint an older build's writes can fail"
        if re.search(r"\bREFERENCES\b", definition):
            return "a foreign key an older build's deletes can fail"
        return None
    if re.match(rf"ALTER TABLE {_SQL_TABLE} RENAME", upper):
        return "a rename"
    if re.match(rf"ALTER TABLE {_SQL_TABLE} DROP", upper):
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

# ai-tc also changes the store in code, not only through its migration journal: every time it
# opens a store it runs steps in migrations.ts after the journal loop (add a column, create a
# trigger, rebuild an index, run a one-time UPDATE), and the trigger's condition comes from
# sync-failure.ts. A release whose only store change is in these files has no new journal tag.
# They are compared as whole files (their git blob shas at the two attested commits) and
# never read: the statements are TypeScript with interpolated names and helper calls, and a
# shape a reader of that missed would read as additive, the direction this check exists to
# prevent. migrations.ts is the one file the store cannot be opened without.
STORE_CODE_DIR = "packages/persistence/src"
STORE_CODE_ENTRY = "migrations.ts"
STORE_CODE_FILES = (STORE_CODE_ENTRY, "sync-failure.ts")
STORE_CODE_CHANGED = "non-additive: the store code ai-tc runs when it opens a store changed outside the migration journal"
STORE_CODE_MISSING = "non-additive: the store code ai-tc runs at open cannot be found"


def _directory_listing(directory: str, commit: str, fetch: Fetch) -> list | None:
    """The entries of one ai-tc directory at commit, or None when that directory is not
    there. One request however many files it holds. The raw media type the file reads use
    returns bytes with no sha, so this asks for the JSON listing instead. A listing that
    fails, is malformed or may be cut short is no verdict."""
    url = f"{AI_TC_API}/contents/{directory}?ref={commit}"
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
    return listing


def _migration_blobs(commit: str, fetch: Fetch) -> dict | None:
    """{tag: git blob sha} for every <tag>.sql in ai-tc's migrations directory at commit,
    or None when that directory is not there."""
    listing = _directory_listing(MIGRATIONS_DIR, commit, fetch)
    if listing is None:
        return None
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


def _store_code_blobs(commit: str, fetch: Fetch) -> dict:
    """{file name: git blob sha} for each of STORE_CODE_FILES that is a plain file in ai-tc's
    persistence source at commit. A file that is not there, or a directory that is not there,
    is left out."""
    listing = _directory_listing(STORE_CODE_DIR, commit, fetch) or []
    blobs = {}
    for entry in listing:
        name = entry.get("name")
        if name not in STORE_CODE_FILES or entry.get("type") != "file":
            continue
        sha = entry.get("sha")
        if not isinstance(sha, str) or not SHA40.fullmatch(sha):
            raise InfraError("classify", f"ai-tc's listing gave {sha!r} as the blob sha of {name}")
        blobs[name] = sha
    return blobs


def _store_code_changes(from_commit: str, to_commit: str, fetch: Fetch) -> dict:
    """{path: kind} for each store-code file that is not the same blob at the two commits,
    appeared or vanished, and for the entry file when the later commit has none (ai-tc may
    have moved it, and then nothing here can say what the store does at open). Empty when
    the files are the same at both. A listing that fails or is malformed is no verdict."""
    before, after = (_store_code_blobs(commit, fetch) for commit in (from_commit, to_commit))
    kinds = {}
    for name in STORE_CODE_FILES:
        if name == STORE_CODE_ENTRY and name not in after:
            kinds[f"{STORE_CODE_DIR}/{name}"] = STORE_CODE_MISSING
        elif before.get(name) != after.get(name):
            kinds[f"{STORE_CODE_DIR}/{name}"] = STORE_CODE_CHANGED
    return kinds


def classify_migrations(from_commit: str, to_commit: str, *, fetch: Fetch = http_fetch) -> Classification:
    """Classify the local-store migrations ai-tc added, removed from the journal or edited
    in place between two attested commits, and any change to the store code it runs at open
    outside that journal (STORE_CODE_FILES).

    The store code is seen as a changed file, not by kind, so an edit to a comment alone
    flags a release. It is recorded in `kinds` under the file's path and never in
    `migrations`, which stays a list of journal tags. Some inputs to the store are out of
    view: the list of event types a one-time UPDATE counts (repositories/history-sync.ts),
    the adopt-or-replay logic under db/migrations, and the generated schema in
    packages/schema (ai-tc's own test holds it to the journal's .sql files)."""
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
    # Before the early returns: a release whose only store change is in code has no journal
    # tag, and counts whatever EVERY_MIGRATION_COUNTS says.
    store_code = _store_code_changes(from_commit, to_commit, fetch)
    kinds.update(store_code)
    notes = []
    if migrations and EVERY_MIGRATION_COUNTS:
        notes.append(
            "every migration counts as not rollback-safe until an older build is measured on a store the newer one migrated"
        )
    if store_code:
        notes.append("the store code ai-tc runs when it opens a store changed outside the migration journal")
    if notes:
        return Classification("not-rollback-safe", migrations, kinds, note="; ".join(notes))
    if not migrations:
        return Classification("additive", [], kinds)
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


def rollback_floor(safety: dict, target: str, highest_pinned: str, *, pinned) -> str | None:
    """The lowest version V flagged not rollback-safe with target < V <= highest_pinned,
    or None. Anything but an explicit, well-formed "additive" entry counts as flagged, and
    so does a version in `pinned` with no entry at all: a pin that reached main without a
    computed entry (a break-glass merge, a restore, a hand-run import) is no evidence of
    safety. `pinned` has no default: leaving it out would drop that rule without saying so.
    An entry is judged on its own: one malformed entry flags its own version and
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
    unchanged; 'human' means any other change to it. The entry is compared as JSON, as the rest
    of the manifest is, so true, 1 and 1.0 are three different values (Python's == says one)."""
    base, head = find_ai_tc_entry(base_manifest), find_ai_tc_entry(head_manifest)
    if _canonical(base) == _canonical(head):
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
    if _canonical(_without_pin(base)) != _canonical(_without_pin(head)) or not _integrity_only(head.get("metadata")):
        return "human"
    if "metadata" in base and not _integrity_only(base["metadata"]):
        return "human"
    return "advance" if vkey(new) > vkey(old) else "rollback"
