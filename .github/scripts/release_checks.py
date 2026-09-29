#!/usr/bin/env python3
"""The marketplace's one release-verification module (standard library only).

Every workflow that verifies an ai-tc release, or judges a change to the ai-tc pin, runs
THIS file from main's copy. validate.yml imports it through validate_pr.py; the
importer, tag-release, staleness and tag-audit run it as a CLI.

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
# attestation may nominate the workflow that is supposed to vouch for a release.
PACKAGE = "@akasecurity/ai-tc-claude-code"
ENTRY_NAME = "ai-tc"
REGISTRY = "https://registry.npmjs.org"
PROV_REPO = "https://github.com/akasecurity/ai-tc"
RELEASE_PIPELINE = {
    PACKAGE: {
        "workflow": ".github/workflows/release-plugin-claude.yml",
        "tag_prefix": "plugin-claude-v",
    },
}
AI_TC_API = "https://api.github.com/repos/akasecurity/ai-tc"
MARKETPLACE_API = "https://api.github.com/repos/akasecurity/marketplace"
MIGRATIONS_DIR = "packages/schema/drizzle/local-sqlite"

MANIFEST = ".claude-plugin/marketplace.json"
SAFETY_FILE = "rollback-safety.json"
FROZEN_TAGS_FILE = ".github/fleet-tags.frozen.json"

SLSA = "https://slsa.dev/provenance/v1"
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


class ReleaseCheckError(Exception):
    """A check reached a verdict, and the verdict is no (CLI exit 1)."""

    def __init__(self, check: str, detail: str) -> None:
        super().__init__(f"{check}: {detail}")
        self.check = check
        self.detail = detail


class InfraError(ReleaseCheckError):
    """No verdict: the network, npm, git or an API failed (CLI exit 2). Still a refusal."""


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
    """What a historical tag pins. Lenient: an unreadable or unpinned tag pins nothing."""
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
    versions = json.loads(body).get("versions")
    if isinstance(versions, dict):
        names = list(versions)
    elif isinstance(versions, list):
        names = versions
    elif isinstance(versions, str):
        names = [versions]
    else:
        raise InfraError("npm", f"{REGISTRY} returned no versions for {PACKAGE}")
    exact = {v for v in names if isinstance(v, str) and SEMVER.fullmatch(v)}
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
