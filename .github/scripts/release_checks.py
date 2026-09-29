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
    """(integrity, shasum) npmjs serves for PACKAGE@version, from ONE registry read."""
    url = f"{packument_url()}/{version}"
    for attempt in range(1, ATTEMPTS + 1):
        status, body = fetch(url, {"Accept": "application/json"})
        if status == 200:
            break
        if status != 404 and status < 500:
            raise ReleaseCheckError("dist", f"{REGISTRY} answered {status} for {PACKAGE}@{version}")
        if attempt == ATTEMPTS:
            if status == 404:
                raise ReleaseCheckError("dist", f"{REGISTRY} does not serve {PACKAGE}@{version}")
            raise InfraError("dist", f"{REGISTRY} answered {status} for {PACKAGE}@{version}")
        sleep(RETRY_SECONDS)
    doc = json.loads(body)
    dist = doc.get("dist") if isinstance(doc, dict) else None
    if not isinstance(dist, dict) or doc.get("version") != version:
        raise ReleaseCheckError("dist", f"{REGISTRY} returned no dist for {PACKAGE}@{version}")
    integrity, shasum = dist.get("integrity"), dist.get("shasum")
    if not isinstance(integrity, str) or not INTEGRITY.fullmatch(integrity):
        raise ReleaseCheckError("dist", f"integrity {integrity!r} is not one sha512 SRI")
    if not isinstance(shasum, str) or not SHASUM.fullmatch(shasum):
        raise ReleaseCheckError("dist", f"shasum {shasum!r} is not 40 hex")
    return integrity, shasum


def provenance_verdict(sig: dict, version: str, integrity: str) -> dict:
    """The SLSA statement for PACKAGE@version, once it binds the tarball the dist read saw
    to ai-tc's release workflow, at the version's own tag, on a GitHub-hosted runner.

    A cryptographically valid attestation alone proves only that SOMEONE published with
    provenance. The repository, workflow and ref binding carries the security."""
    pipeline = RELEASE_PIPELINE[PACKAGE]
    want = {
        "repository": PROV_REPO,
        "path": pipeline["workflow"],
        "ref": f"refs/tags/{pipeline['tag_prefix']}{version}",
    }
    if sig.get("invalid"):
        raise ReleaseCheckError("provenance", f"npm reports INVALID signatures or attestations: {sig['invalid']}")
    entry = next(
        (v for v in sig.get("verified") or [] if v.get("name") == PACKAGE and v.get("version") == version),
        None,
    )
    if entry is None:
        raise _NotIndexedYet(
            f"{PACKAGE}@{version} carries no VERIFIED attestation (npm's missing list, which "
            f"names packages with no registry signature: {sig.get('missing')})"
        )
    bundles = [b for b in entry.get("attestationBundles") or [] if b.get("predicateType") == SLSA]
    if not bundles:
        raise ReleaseCheckError("provenance", f"{PACKAGE}@{version} has no {SLSA} attestation")
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
    if dist_hex not in attested:
        raise ReleaseCheckError(
            "provenance",
            f"the attestation covers a different tarball than the dist read ({integrity}); "
            "the two registry reads disagree about the bytes",
        )
    bad = [f"{k}: attested {got.get(k)!r} != required {v!r}" for k, v in want.items() if got.get(k) != v]
    if "github-hosted" not in builder:
        bad.append(f"builder {builder!r} is not a github-hosted runner")
    if bad:
        if (
            got.get("repository") == want["repository"]
            and got.get("path") == want["path"]
            and str(got.get("ref", "")).startswith("refs/heads/")
        ):
            raise ReleaseCheckError(
                "provenance",
                f"{PACKAGE}@{version} was published by {want['repository']} :: {want['path']} from "
                f"{got.get('ref')!r}, not from its tag {want['ref']!r}: an off-tag publish from a "
                "branch dispatch. An attestation is immutable, so this version can never be "
                "imported. This is NOT a stolen-token signal.",
            )
        raise ReleaseCheckError(
            "provenance",
            "the attestation does not bind this tarball to ai-tc's release workflow: "
            + "; ".join(bad)
            + ". A cryptographically valid attestation is NOT sufficient: anyone can publish "
            "with provenance from their own repository.",
        )
    return statement


def attested_commit(statement: dict, version: str) -> str:
    """The git commit the provenance says the release was built from, for the tag's own URI."""
    tag_ref = f"refs/tags/{RELEASE_PIPELINE[PACKAGE]['tag_prefix']}{version}"
    uri = f"git+{PROV_REPO}@{tag_ref}"
    dependencies = ((statement.get("predicate") or {}).get("buildDefinition") or {}).get("resolvedDependencies") or []
    commits = [
        (d.get("digest") or {}).get("gitCommit")
        for d in dependencies
        if isinstance(d, dict) and d.get("uri") == uri
    ]
    if len(commits) != 1 or not isinstance(commits[0], str) or not SHA40.fullmatch(commits[0]):
        raise ReleaseCheckError("attested-commit", f"the provenance names no single commit for {uri} (found {commits!r})")
    return commits[0]


def release_run_url(statement: dict) -> str:
    """The ai-tc release run that built the tarball, for the PR body."""
    url = (((statement.get("predicate") or {}).get("runDetails") or {}).get("metadata") or {}).get("invocationId", "")
    if not isinstance(url, str) or not RUN_URL.fullmatch(url):
        raise ReleaseCheckError("run-url", f"the provenance names no ai-tc Actions run: {url!r}")
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
    GitHub. Nothing is taken on trust."""
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


def _statements(sql: str) -> list:
    text = sql.replace("--> statement-breakpoint", ";")
    lines = [line.split("--", 1)[0] for line in text.splitlines()]
    return [" ".join(part.split()) for part in " ".join(lines).split(";") if part.strip()]


def _non_additive_reason(statement: str) -> str | None:
    upper = statement.upper()
    if upper.startswith("PRAGMA "):
        return None
    if "__NEW_" in upper:
        return "a table rebuild (drizzle's __new_ copy)"
    if re.match(r"CREATE TABLE ", upper) or re.match(r"CREATE INDEX ", upper):
        return None
    if re.match(r"CREATE UNIQUE INDEX ", upper):
        return "a UNIQUE index, a new constraint an older build's writes can violate"
    added = re.match(r"ALTER TABLE \S+ ADD (?:COLUMN )?(.*)", upper)
    if added:
        column = added.group(1)
        if "NOT NULL" in column and "DEFAULT" not in column and "GENERATED" not in column:
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
    statements = _statements(sql)
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
    return body.decode("utf-8")


def _journal_tags(commit: str, fetch: Fetch):
    raw = _ai_tc_file(f"{MIGRATIONS_DIR}/meta/_journal.json", commit, fetch)
    if raw is None:
        return None
    entries = json.loads(raw).get("entries")
    tags = [e.get("tag") for e in entries] if isinstance(entries, list) else None
    if tags is None or not all(isinstance(t, str) and MIGRATION_TAG.fullmatch(t) for t in tags):
        raise ReleaseCheckError("classify", f"the migration journal at {commit} has an unexpected shape")
    return tags


def classify_migrations(from_commit: str, to_commit: str, *, fetch: Fetch = http_fetch) -> Classification:
    """Classify the local-store migrations ai-tc added between two attested commits."""
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
        kinds[tag] = "non-additive: the migration file cannot be read" if sql is None else migration_kind(sql)
    for tag in removed:
        kinds[tag] = "non-additive: removed from the journal (history rewritten)"
    migrations = added + removed
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


def safety_problems(doc) -> list:
    """What is wrong with a rollback-safety.json document (empty = well formed)."""
    if not isinstance(doc, dict) or list(doc) != ["versions"] or not isinstance(doc["versions"], dict):
        return [f'{SAFETY_FILE} must be exactly {{"versions": {{...}}}}']
    problems = []
    for version, entry in doc["versions"].items():
        where = f"{SAFETY_FILE} {version!r}"
        if not SEMVER.fullmatch(version):
            problems.append(f"{where}: not an exact x.y.z")
            continue
        if not isinstance(entry, dict) or list(entry) != SAFETY_KEYS:
            problems.append(f"{where}: keys must be exactly {SAFETY_KEYS}, in that order")
            continue
        if entry["classification"] not in ("additive", "not-rollback-safe"):
            problems.append(f"{where}: classification must be additive or not-rollback-safe")
        for key in ("from", "to"):
            if not isinstance(entry[key], str) or not SHA40.fullmatch(entry[key]):
                problems.append(f"{where}: {key} must be a 40-hex commit id")
        migrations = entry["migrations"]
        if not isinstance(migrations, list) or not all(isinstance(m, str) and MIGRATION_TAG.fullmatch(m) for m in migrations):
            problems.append(f"{where}: migrations must be a list of migration tags")
    return problems


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
    or None. Anything but an explicit "additive" entry counts as flagged, and so does a
    version in `pinned` with no entry at all: a pin that reached main without a computed
    entry (a break-glass merge, a restore, a hand-run import) is no evidence of safety."""
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
        and not (isinstance(versions.get(version), dict) and versions[version].get("classification") == "additive")
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
# `/`), so bot-branches lists both depths, and tags-locked is ~ALL or, where GitHub refuses
# ~ALL on a tag ruleset, the two tag globs that cover the same refs.
EXPECTED_REF_PATTERNS = {
    "main": ([["refs/heads/main"]], []),
    "tags-locked": ([["~ALL"], ["refs/tags/*", "refs/tags/**/*"]], ["refs/tags/fleet-v*"]),
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


if __name__ == "__main__":
    sys.exit(main())
