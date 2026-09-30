#!/usr/bin/env python3
"""validate.yml's rules for every PR into this repository.

This runs from the BASE branch's copy (pull_request_target). It reads the PR's files as
data: `git show <sha>:<path>` of the head commit, never a checkout, and it never imports
or executes anything the PR contains.

It is a correctness check on the automated path, not a security boundary: code-owner
review of every change is the control.

Exit 0 = every rule holds, 1 = a rule failed, 2 = no verdict (git, network or API).
"""

from __future__ import annotations

import dataclasses
import functools
import json
import os
import re
import subprocess
import sys

import release_checks as rc

MANIFESTS = (rc.MANIFEST, ".agents/plugins/marketplace.json", "plugins.json")
WATCHED = (*MANIFESTS, rc.SAFETY_FILE)
MODE_LABEL = {"advance": "ADVANCE", "rollback": "ROLLBACK", "remove": "REMOVE", "restore": "RESTORE"}
REPO_NAME = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+")


@dataclasses.dataclass(frozen=True)
class PullRequest:
    number: int
    author: str
    author_type: str
    head_repo: str
    base_repo: str
    head_ref: str
    commits: tuple  # ({"sha", "author", "committer", "verified"}, ...): GitHub logins or None, and GitHub's signature verdict


@dataclasses.dataclass
class Report:
    failures: list = dataclasses.field(default_factory=list)
    notes: list = dataclasses.field(default_factory=list)
    rows: list = dataclasses.field(default_factory=list)
    infra: str = ""

    def fail(self, message: str) -> None:
        self.failures.append(message)

    def note(self, message: str) -> None:
        self.notes.append(message)

    def row(self, key: str, value: str) -> None:
        self.rows.append((key, value))

    @property
    def exit_code(self) -> int:
        if self.infra:
            return 2
        return 1 if self.failures else 0


def _code(value) -> str:
    """Inline code for the summary: PR-controlled text cannot break out of it."""
    text = " ".join(str(value).replace("`", "'").split())
    return f"`{text[:200]}`"


def _frozen_top_level(manifest: dict) -> dict:
    """The manifest without plugins, and without the three keys a PR may change."""
    top = {k: v for k, v in manifest.items() if k not in ("plugins", "description")}
    if isinstance(top.get("metadata"), dict):
        top["metadata"] = {k: v for k, v in top["metadata"].items() if k not in ("description", "version")}
    return top


def _names_ai_tc(value) -> bool:
    if value == rc.ENTRY_NAME:
        return True
    if isinstance(value, dict):
        return any(_names_ai_tc(k) or _names_ai_tc(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_names_ai_tc(v) for v in value)
    return False


def parse_manifests(files: dict, report: Report, *, label: str) -> dict:
    """Parse every manifest, reporting each problem. Returns path -> document."""
    docs = {}
    for path in MANIFESTS:
        text = files.get(path)
        if text is None:
            report.fail(f"{path} is missing at {label}")
            continue
        try:
            doc = rc.parse_json(text)
        except ValueError as exc:
            report.fail(f"{path} does not parse at {label} (duplicate keys and NaN are refused): {exc}")
            continue
        plugins = doc.get("plugins") if isinstance(doc, dict) else None
        if not isinstance(plugins, list) or not all(isinstance(p, dict) and isinstance(p.get("name"), str) for p in plugins):
            report.fail(f"{path} at {label}: plugins must be a list of objects that each have a string name")
            continue
        names = [p["name"] for p in plugins]
        repeated = sorted({n for n in names if names.count(n) > 1})
        if repeated:
            report.fail(f"{path} at {label}: plugin names must be unique; repeated: {', '.join(repeated)}")
        docs[path] = doc
    return docs


def every_pr_rules(base_doc: dict, head_doc: dict, report: Report):
    """The rules for every PR. Returns (base_entry, head_entry, mode), or None when the
    ai-tc entry is ambiguous, since then nothing further can be judged."""
    if _names_ai_tc(head_doc.get("renames")):
        report.fail("a renames key or value names ai-tc: the plugin id every managed Mac enables is never renamed")
    base_top, head_top = _frozen_top_level(base_doc), _frozen_top_level(head_doc)
    if base_top != head_top:
        changed = sorted(k for k in set(base_top) | set(head_top) if base_top.get(k) != head_top.get(k))
        report.fail(
            "top-level keys are frozen (only description, metadata.description and metadata.version "
            "may change); changed: " + ", ".join(changed)
        )
    try:
        base_entry = rc.find_ai_tc_entry(base_doc)
        head_entry = rc.find_ai_tc_entry(head_doc)
        mode = rc.diff_mode(base_doc, head_doc)
    except rc.ReleaseCheckError as exc:
        report.fail(f"{exc.check}: {exc.detail}")
        return None
    return base_entry, head_entry, mode
