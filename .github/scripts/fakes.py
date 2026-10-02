"""Test doubles shared by the marketplace script tests. Not a test module: discovery skips it.

The manifests and the attested commits come from _testsupport, the fixtures
release_checks' own tests use, and every file is written by
release_checks.dump_json, the one writer."""
from __future__ import annotations

import base64
import re
from typing import Any, Callable

import _testsupport as ts
import release_checks
from ghapi import GitHubError

REPO = "akasecurity/marketplace"
BOT = "aka-marketplace-bot[bot]"
VERSIONS = ("0.9.12", "0.9.13", "0.9.14", "0.9.15", "0.9.16", "0.9.17")
INTEGRITY = {v: "sha512-" + base64.b64encode(bytes([int(v.split(".")[2])] * 64)).decode() for v in VERSIONS}
# The real attested commits through 0.9.14, then invented stand-ins for every later version.
# 0.9.15 is a real release too, but these tests use it as an invented next release.
ATTESTED = {**ts.ATTESTED, **{v: v.split(".")[2] * 20 for v in VERSIONS if v not in ts.ATTESTED}}
CODEOWNERS = "* @Vaishnav-OM @venuverse\n"


def manifest(version: str | None = "0.9.14", integrity: str | None = None, *, entry: bool = True) -> str:
    """_testsupport.manifest as the committed file's text. integrity None leaves the ai-tc entry without
    metadata, version None leaves it unpinned (fleet-v1's shape), and entry=False removes it."""
    doc = ts.manifest(version or "0.9.14", integrity=integrity)
    ai_tc = ts.ai_tc(doc)
    if version is None:
        del ai_tc["source"]["version"]
    if not entry:
        doc["plugins"] = [plugin for plugin in doc["plugins"] if plugin is not ai_tc]
    return release_checks.dump_json(doc)


def safety(entries: dict) -> str:
    return release_checks.dump_json({"versions": entries})


def safety_entry(version: str, previous: str, classification: str = "not-rollback-safe",
                 migrations: tuple = ("0035_example",)) -> dict:
    return {"classification": classification, "from": ATTESTED[previous], "to": ATTESTED[version],
            "migrations": list(migrations)}


class FakeGit:
    """gitrepo.Git's surface over in-memory commits. `chain` is main's first-parent history, oldest first."""

    def __init__(self, *, chain: list[str], files: dict | None = None, tags: list[dict] | None = None,
                 messages: dict | None = None, times: dict | None = None,
                 remote_refs: list[str] | None = None) -> None:
        self.repo_dir = "/fake/marketplace"
        self.chain = list(chain)
        self.files = dict(files or {})
        self.tags = list(tags or [])
        self.messages = dict(messages or {})
        self.times = dict(times or {})
        self.remote_refs = list(remote_refs or [])

    def rev_parse(self, rev: str) -> str:
        return self.chain[-1] if rev == "main" else rev

    def main(self) -> str:
        return "main"

    def show(self, rev: str, path: str) -> str | None:
        return self.files.get((self.rev_parse(rev), path))

    def fleet_tags(self) -> list[dict]:
        return sorted(self.tags, key=lambda tag: tag["n"])

    def tag_names(self) -> list[str]:
        return [tag["tag"] for tag in self.tags]

    def tag_message(self, tag: str) -> str:
        return self.messages.get(tag, "")

    def first_parent_after(self, base: str, tip: str) -> list[str]:
        return self.chain[self.chain.index(base) + 1: self.chain.index(self.rev_parse(tip)) + 1]

    def first_parent(self, sha: str) -> str | None:
        index = self.chain.index(sha)
        return self.chain[index - 1] if index else None

    def commits_between(self, before: str, after: str) -> list[str]:
        return self.first_parent_after(before, after)

    def commit_time(self, sha: str) -> int:
        return self.times[sha]

    def ls_remote(self, remote: str = "origin") -> list[str]:
        return list(self.remote_refs)


def fleet_tag(n: int, commit: str) -> dict:
    return {"tag": f"fleet-v{n}", "n": n, "object": f"{n:x}".rjust(40, "e"), "commit": commit}


class FakeGitHub:
    """ghapi.GitHub's surface. Routes map (METHOD, path) — ("GRAPHQL", field) for GraphQL — to an
    answer, a callable (body_or_variables, params) -> answer, or a GitHubError to raise. Every call
    is recorded; an unrouted call fails the test."""

    def __init__(self, routes: dict | None = None, repo: str = REPO) -> None:
        self.repo = repo
        self.routes = dict(routes or {})
        self.calls: list[tuple] = []

    def repo_path(self, suffix: str) -> str:
        return f"repos/{self.repo}/{suffix.lstrip('/')}"

    def _answer(self, method: str, path: str, body: Any = None, params: Any = None) -> Any:
        self.calls.append((method, path, body, params))
        if (method, path) not in self.routes:
            raise AssertionError(f"unexpected call: {method} {path}")
        answer = self.routes[(method, path)]
        if callable(answer):
            answer = answer(body, params)
        if isinstance(answer, GitHubError):
            raise answer
        return answer

    def get(self, path, params=None, ok=(200,)):
        return self._answer("GET", path, None, params)

    def post(self, path, body, ok=(200, 201)):
        return self._answer("POST", path, body)

    def patch(self, path, body):
        return self._answer("PATCH", path, body)

    def delete(self, path, ok=(204,)):
        return self._answer("DELETE", path)

    def paginate(self, path, params=None):
        return iter(self._answer("GET", path, None, params))

    def graphql(self, query, variables):
        return self._answer("GRAPHQL", re.search(r"\{\s*(\w+)", query).group(1), variables)

    def called(self, method: str, path: str) -> list[tuple]:
        return [call for call in self.calls if call[0] == method and call[1] == path]

    def writes(self) -> list[tuple]:
        return [call for call in self.calls if call[0] != "GET"]


def not_found(path: str = "") -> GitHubError:
    return GitHubError(404, "GET", path, '{"message": "Not Found"}')


def pull(number: int, head: str, *, state: str = "open", merged: bool = False,
         created_at: str = "2026-09-29T00:00:00Z", labels: tuple = (), repo: str = REPO, author: str = BOT) -> dict:
    """A pull request as the REST list endpoint returns it, opened by the release bot unless `author` says otherwise."""
    return {"number": number, "node_id": f"PR_{number}", "state": state, "created_at": created_at,
            "merged_at": "2026-09-29T01:00:00Z" if merged else None,
            "head": {"ref": head, "sha": f"{number:040x}", "repo": {"full_name": repo}},
            "labels": [{"name": name} for name in labels], "user": {"login": author}}


def pulls_route(pulls: list[dict]) -> Callable:
    """GET .../pulls answering by the `state` query parameter, from a list the test may keep changing."""
    return lambda body, params: [p for p in pulls if p["state"] == params["state"]]


def contents(text: str) -> dict:
    return {"content": base64.b64encode(text.encode("utf-8")).decode(), "encoding": "base64"}
