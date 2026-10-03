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

# Real values, read from npmjs and akasecurity/ai-tc on 2026-09-29.
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


def audit_output(version, stmt=None, *, invalid=None, verified=True):
    """What `npm audit signatures --json --include-attestations` prints for PACKAGE@version."""
    publish = {
        "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
        "bundle": {"dsseEnvelope": {"payload": base64.b64encode(b"{}").decode()}},
    }
    slsa = {
        "predicateType": rc.SLSA,
        "bundle": {
            "dsseEnvelope": {
                "payload": base64.b64encode(json.dumps(stmt or statement(version)).encode()).decode()
            }
        },
    }
    out = {"invalid": invalid or [], "missing": []}
    out["verified"] = (
        [{"name": rc.PACKAGE, "version": version, "attestationBundles": [publish, slsa]}]
        if verified
        else []
    )
    return out


def dist_url(version):
    return f"{rc.packument_url()}/{version}"


def compare_url(commit):
    return f"{rc.AI_TC_API}/compare/{commit}...main?per_page=1"


def contents_url(path, commit):
    return f"{rc.AI_TC_API}/contents/{path}?ref={commit}"


def release_routes(version, *, compare="ahead", commit=None, integrity=INTEGRITY):
    """The registry and GitHub answers for a release that passes every check."""
    commit = commit or ATTESTED.get(version, "c" * 40)
    return {
        dist_url(version): (200, {"version": version, "dist": {"integrity": integrity, "shasum": SHASUM}}),
        compare_url(commit): (200, {"status": compare, "ahead_by": 1, "behind_by": 0}),
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
