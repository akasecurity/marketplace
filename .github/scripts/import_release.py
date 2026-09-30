"""The ai-tc pin importer behind import-plugin-release.yml.

`plan` runs in the verify job, which holds no secret: it reads main and the
fleet-v tag ledger from the checkout, picks the version, verifies it with
release_checks, and prints one JSON plan. `open-pr` runs in the
marketplace-bot environment with the bot App's installation credential: it
re-reads main through the API, writes the bot commit through the Git Data API
(no local push and no persisted credential), creates the branch create-only
(an existing branch means another run got there), opens the PR and enables
auto-merge. AGENTS.md ("ai-tc is pinned", "The workflows") describes the flow.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Callable

import release_checks
from ghapi import GitHub, GitHubError
from gitrepo import Git
from release_checks import FLEET_TAG, INTEGRITY, MANIFEST, PACKAGE, SAFETY_FILE, SEMVER, SHA40, dump_json, vkey

# The paths, patterns, version order and JSON writer above are release_checks.py's, the
# module validate runs, so the importer and validate cannot disagree about them. These
# are the importer's own: its branch names and the labels it may set.
PIN_BRANCH = re.compile(rf"bot/pin-ai-tc-({SEMVER.pattern})")
ROLLBACK_BRANCH = re.compile(rf"bot/rollback-ai-tc-({SEMVER.pattern})-to-({SEMVER.pattern})")
LABELS = {"rollback", "emergency-stop"}


class Refused(Exception):
    """A reason to stop without acting; `red` decides whether the run fails."""

    def __init__(self, message: str, red: bool = True) -> None:
        super().__init__(message)
        self.red = red


def load_stable(raw: str, path: str) -> dict:
    """release_checks.load_round_trip (validate's strict parse, and the proof that rewriting the
    file changes only the edit), with its refusals as a Refused that names the file."""
    try:
        return release_checks.load_round_trip(raw)
    except ValueError as error:
        raise Refused(f"{path} does not parse as strict JSON: {error}") from error
    except release_checks.ReleaseCheckError as error:
        raise Refused(f"{path} does not round-trip through json.dumps(indent=2, ensure_ascii=False); "
                      "rewriting it would churn unrelated bytes, so fix its formatting in a reviewed PR first") from error


def describe(error: Exception) -> str:
    """A release_checks.ReleaseCheckError as '<check>: <detail>'."""
    return f"{getattr(error, 'check', 'check')}: {getattr(error, 'detail', error)}"


def entry_of(doc: dict) -> dict | None:
    """The manifest's ai-tc entry, or None when it has none.

    release_checks.find_ai_tc_entry is the one selector the importer, validate
    and staleness share: it refuses zero or two matches, or a name match that
    is not the package match, and gives None only when neither the name nor
    the package appears at all, i.e. the entry was removed.
    """
    try:
        return release_checks.find_ai_tc_entry(doc)
    except release_checks.ReleaseCheckError as error:
        raise Refused(f"the ai-tc entry is ambiguous or malformed: {error}") from error


def pinned_version(doc: dict) -> str | None:
    entry = entry_of(doc)
    if entry is None:
        return None
    version = release_checks.entry_version(entry)
    if version is None:
        raise Refused(f"the ai-tc pin {entry['source'].get('version')!r} is not an exact x.y.z")
    return version


def tag_pins(repo_dir: str) -> dict[str, str | None]:
    """Each fleet-v tag's ai-tc version; None where the tag pins no exact version (fleet-v1). This is
    release_checks.pins_by_ref, the ledger read validate and the floor CLI use, without main."""
    return {ref: version for ref, version in release_checks.pins_by_ref(repo_dir).items() if ref != "main"}


def list_pulls(gh: GitHub, state: str) -> list[dict]:
    """Same-repository PRs into main in `state`. A fork PR's head name proves nothing, so forks are skipped."""
    pulls = []
    for item in gh.paginate(gh.repo_path("pulls"), {"state": state, "base": "main"}):
        head = item.get("head") or {}
        if (head.get("repo") or {}).get("full_name") != gh.repo:
            continue
        pulls.append({"number": item["number"], "node_id": item.get("node_id", ""), "head": head.get("ref", ""),
                      "head_sha": head.get("sha", ""), "merged": item.get("merged_at") is not None,
                      "created_at": item.get("created_at", ""),
                      "labels": [label.get("name") for label in item.get("labels", [])]})
    return pulls


def pulls_by(pulls: list[dict], pattern: re.Pattern) -> list[dict]:
    return [p for p in pulls if pattern.fullmatch(p["head"])]


def edit_pin(raw: str, plan: dict) -> str:
    """Forward and rollback change exactly source.version and metadata.integrity of the ai-tc entry."""
    doc = load_stable(raw, MANIFEST)
    entry = entry_of(doc)
    if entry is None:
        raise Refused("main has no ai-tc entry to move; re-adding it is a restore-mode dispatch")
    old, new = entry["source"].get("version"), plan["version"]
    if not (isinstance(old, str) and SEMVER.fullmatch(old)):
        raise Refused(f"the ai-tc pin {old!r} is not an exact x.y.z")
    if plan["mode"] == "forward" and not vkey(new) > vkey(old):
        raise Refused(f"a forward pin must move up: {old} -> {new}")
    if plan["mode"] == "rollback" and not vkey(new) < vkey(old):
        raise Refused(f"a rollback must move down: {old} -> {new}")
    metadata = entry.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise Refused("the ai-tc entry's metadata is not an object")
    entry["source"]["version"] = new
    metadata["integrity"] = plan["integrity"]
    text = dump_json(doc)
    after = entry_of(json.loads(text))
    if after["source"]["version"] != new or after["metadata"]["integrity"] != plan["integrity"]:
        raise Refused("the rewritten manifest does not carry the new pin")
    return text


def add_safety_entry(raw: str, version: str, entry: dict) -> str | None:
    """rollback-safety.json with `version`'s entry appended; None when it already has one."""
    doc = load_stable(raw, SAFETY_FILE)
    versions = doc.setdefault("versions", {})
    if version in versions:
        return None
    versions[version] = entry
    return dump_json(doc)


MODE_RULES: dict[str, dict] = {
    "forward": {"branch": lambda plan: f"bot/pin-ai-tc-{plan['version']}",
                "required": ("version", "from_version", "integrity", "git_commit")},
    "rollback": {"branch": lambda plan: f"bot/rollback-ai-tc-{plan['from_version']}-to-{plan['version']}",
                 "required": ("version", "from_version", "integrity", "git_commit")},
}


def check_plan(plan: dict) -> None:
    """The verify job's output crosses a job boundary: re-check its shape before acting on it."""
    rules = MODE_RULES.get(plan.get("mode"))
    if rules is None:
        raise Refused(f"the plan names mode {plan.get('mode')!r}, which open-pr does not handle")
    for key in rules["required"]:
        if not plan.get(key):
            raise Refused(f"the plan has no {key}")
    for key, pattern in (("version", SEMVER), ("from_version", SEMVER), ("integrity", INTEGRITY), ("git_commit", SHA40)):
        value = plan.get(key)
        if value is not None and not (isinstance(value, str) and pattern.fullmatch(value)):
            raise Refused(f"the plan's {key} {value!r} is malformed")
    if plan.get("branch") != rules["branch"](plan):
        raise Refused(f"the plan's branch {plan.get('branch')!r} does not match its mode and versions")
    if not set(plan.get("labels", [])) <= LABELS:
        raise Refused(f"the plan's labels {plan.get('labels')!r} are not the importer's")


def pr_body(plan: dict, run_url: str) -> str:
    version, current, branch = plan["version"], plan["from_version"], plan["branch"]
    lines: list[str] = []
    if plan["mode"] == "forward":
        lines.append(f"Advances the `ai-tc` pin in `{MANIFEST}`: `{current}` → `{version}`.")
    else:
        pinned_by = f" (the version `{plan['target_tag']}` pins)" if plan.get("target_tag") else ""
        lines.append(f"**Rollback.** Moves the `ai-tc` pin in `{MANIFEST}` back: `{current}` → `{version}`{pinned_by}.")
    lines += [
        "",
        f"Opened by [import-plugin-release]({run_url}). Trust `validate`'s check summary over this body: "
        "anyone with write access can edit a PR body.",
        "",
        "**What the importer verified**, against https://registry.npmjs.org:",
        "",
        f"- package: `{PACKAGE}@{version}`",
        f"- integrity: `{plan['integrity']}` (also written to the entry's `metadata.integrity`)",
        f"- shasum: `{plan['shasum']}`",
        f"- provenance: SLSA, built by `.github/workflows/release-plugin-claude.yml` in akasecurity/ai-tc "
        f"at `refs/tags/plugin-claude-v{version}` on a GitHub-hosted runner",
        f"- attested commit: `{plan['git_commit']}`, on ai-tc main: yes",
        f"- ai-tc release run (its hook fail-open smoke tests run there): {plan['run_url']}",
        "",
    ]
    if plan["mode"] == "forward":
        migrations = ", ".join(f"`{name}`" for name in plan.get("migrations", [])) or "none"
        lines.append(f"**Store migrations** `{current}` → `{version}`: `{plan['classification']}` ({migrations}). "
                     "Informational: `validate` recomputes the value that counts.")
        lines.append(f"This PR also adds that entry to `{SAFETY_FILE}`." if plan.get("safety_entry")
                     else f"`{SAFETY_FILE}` already has an entry for `{version}`; this PR leaves it unchanged.")
        if plan.get("reimport"):
            lines += ["", f"**Re-import** (`reimport: true`): `{version}` is not above every version `main` or a "
                      "`fleet-v` tag has pinned, or a code owner closed an earlier PR for it. Approve only once "
                      "the reason it was rolled back or rejected is resolved."]
    else:
        floor = plan.get("floor")
        lines.append(f"**Rollback floor** (from `main`'s `{SAFETY_FILE}`): "
                     + (f"`{floor}` is flagged not-rollback-safe between `{version}` and `{plan['highest_pinned']}`."
                        if floor else f"no release between `{version}` and `{plan['highest_pinned']}` is flagged."))
        if plan.get("below_floor"):
            lines.append("**Dispatched with `below_floor: true`.** `validate` fails this PR; only an org owner's "
                         "break-glass merge can land it, and its tag will record the bypass.")
        if plan.get("crossed"):
            lines.append("Flagged not-rollback-safe releases this rollback moves back across: "
                         + ", ".join(f"`{v}`" for v in plan["crossed"])
                         + ". A Mac's store may already be ahead of the target build.")
        lines.append(f"Merging moves every Mac that follows `main` back to `{version}` at its next Claude Code "
                     "session. Auto-merge is off on any open forward pin PR until this resolves.")
    lines += [
        "",
        "**Approver checklist:**",
        "",
        "- [ ] Open the `validate` check run and confirm it is `validate.yml`'s run from `main` "
        "(event `pull_request_target`); read its summary.",
        "- [ ] Open the ai-tc release run above and confirm its hook fail-open smoke tests passed.",
        f"- [ ] Run `{version}` in one real session on a machine or VM without AKA's managed settings, with a "
        "throwaway home (a fresh `~/.aka`): "
        f"`claude plugin marketplace add akasecurity/marketplace#{branch}`, then "
        "`claude plugin install ai-tc@akasecurity`; send one clean prompt and one that must block; check "
        f"that hooks fire, the store records both, and `claude plugin list` shows `{version}`.",
        f"- [ ] Note `{version}` in your approval.",
        "- [ ] If this is a drill, add the `drill` label before approving.",
        "",
        "Approving is the only per-release act: auto-merge squash-merges this PR once `validate` is green, and "
        "tag-release then creates the next `fleet-v<N>` tag at the squash commit.",
    ]
    return "\n".join(lines) + "\n"
