"""The ai-tc pin importer behind import-plugin-release.yml.

`plan` runs in the verify job, which holds no secret: it reads main and the
fleet-v tag ledger from the checkout, picks the version, verifies it with
release_checks, and prints one JSON plan. `open-pr` runs in the
marketplace-bot environment with the bot App's installation credential: it
re-reads main through the API, writes the bot commit through the Git Data API
(no local push and no persisted credential), creates the branch with a create-only
ref, never a force-push (an existing branch with an open bot PR is skipped, and one with an
open PR of anyone else's is a red refusal, since deleting the branch would close that PR; one
the bot's closed PR used is skipped on a plain forward run, and deleted and created again only
by a reimport or rollback dispatch; one no PR ever used was left by a run that died before
opening it, and any run deletes it and creates it again), opens the PR and enables
auto-merge. A release the checks cannot reach a verdict on (a registry, network, npm or
GitHub API failure) stops the plan red, and the importer never falls back to a lower
version while a higher one has no verdict. Every decision about an open or closed PR looks at
the pull requests the release bot opened and no others (release_checks.BOT_LOGIN), so a person's
PR from a `bot/` branch name neither stops the schedule nor is closed, with one exception:
open-pr refuses, red, to delete a branch that a person's open PR is from, and stays red for
that version until the person closes the PR or renames its branch. While no bot login is
configured the importer refuses, red. AGENTS.md ("ai-tc is pinned", "The workflows") describes
the flow.
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
from release_checks import (FLEET_TAG, INTEGRITY, MANIFEST, MIGRATION_TAG, PACKAGE, RUN_URL, SAFETY_FILE, SEMVER,
                            SHA40, SHASUM, dump_json, vkey)

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
    """A release_checks.ReleaseCheckError or InfraError as '<check>: <detail>'."""
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
    """Same-repository PRs into main in `state`, with their authors. A fork PR's head name proves
    nothing, so forks are skipped. Nor does a same-repository head name prove who opened the PR, so a
    decision about the importer's own PRs reads through bot_pulls."""
    pulls = []
    for item in gh.paginate(gh.repo_path("pulls"), {"state": state, "base": "main"}):
        head = item.get("head") or {}
        if (head.get("repo") or {}).get("full_name") != gh.repo:
            continue
        pulls.append({"number": item["number"], "node_id": item.get("node_id", ""), "head": head.get("ref", ""),
                      "head_sha": head.get("sha", ""), "merged": item.get("merged_at") is not None,
                      "created_at": item.get("created_at", ""), "author": (item.get("user") or {}).get("login") or "",
                      "labels": [label.get("name") for label in item.get("labels", [])]})
    return pulls


def bot_login() -> str:
    """The release bot App's login, or a red refusal while none is configured: with no login the importer
    cannot tell its own pull requests from anyone else's, and acting on a branch name alone would let any
    writer's PR from a `bot/` branch stop the schedule, block a version or be closed by a later import."""
    login = release_checks.BOT_LOGIN
    if login is None:
        raise Refused("no bot identity is configured (release_checks.BOT_LOGIN), so the importer cannot tell its "
                      "own pull requests from anyone else's")
    return login


def bot_pulls(pulls: list[dict]) -> list[dict]:
    """The pull requests the release bot opened. Every importer decision about an open or closed PR reads
    through this, as validate does when it asks whose PR it is judging, except one refusal: open_pr lists
    every author's open PRs from its branch, and refuses red to delete the branch of a person's."""
    login = bot_login()
    return [p for p in pulls if p["author"] == login]


def pulls_by(pulls: list[dict], pattern: re.Pattern) -> list[dict]:
    return [p for p in pulls if pattern.fullmatch(p["head"])]


def merged_bot_versions(bot_closed: list[dict]) -> set[str]:
    """Versions the release bot's merged pull requests put on main or took it back from: the version
    of each merged bot/pin-ai-tc-<v> and the `from` of each merged bot/rollback-ai-tc-<from>-to-<to>.
    A fleet-v tag records a pin too, but tags are cut after the merge and only while tag-release is
    green, so a version can sit on main untagged; a version a rollback moved away from is exactly the
    one no tag may name. `bot_closed` is already the bot's own pull requests (bot_pulls)."""
    versions = set()
    for pr in bot_closed:
        if not pr["merged"]:
            continue
        match = PIN_BRANCH.fullmatch(pr["head"]) or ROLLBACK_BRANCH.fullmatch(pr["head"])
        if match:
            versions.add(match.group(1))
    return versions


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


# The title is built here, from the mode and the versions, by the planner and again by open-pr: a plan's own
# "title" field is never read back, so nothing in it can reach the commit message or the PR.
MODE_RULES: dict[str, dict] = {
    "forward": {"branch": lambda plan: f"bot/pin-ai-tc-{plan['version']}",
                "title": lambda plan: f"feat: advance the ai-tc pin to {plan['version']}",
                "required": ("version", "from_version", "integrity", "git_commit", "shasum", "run_url",
                             "highest_pinned")},
    "rollback": {"branch": lambda plan: f"bot/rollback-ai-tc-{plan['from_version']}-to-{plan['version']}",
                 "title": lambda plan: f"fix: roll the ai-tc pin back from {plan['from_version']} to {plan['version']}",
                 "required": ("version", "from_version", "integrity", "git_commit", "shasum", "run_url",
                              "highest_pinned")},
}
CLASSIFICATIONS = ("additive", "not-rollback-safe")


def check_plan(plan: dict) -> None:
    """The verify job's output crosses a job boundary: re-check it before acting on it. Every field that
    reaches the commit, the branch, the labels or the PR text is checked here or built by open-pr itself."""
    rules = MODE_RULES.get(plan.get("mode"))
    if rules is None:
        raise Refused(f"the plan names mode {plan.get('mode')!r}, which open-pr does not handle")
    for key in rules["required"]:
        if not plan.get(key):
            raise Refused(f"the plan has no {key}")
    # A value of None is allowed where the key is not required: floor and target_tag are None unless a
    # rollback names them.
    for key, pattern in (("version", SEMVER), ("from_version", SEMVER), ("integrity", INTEGRITY), ("git_commit", SHA40),
                         ("shasum", SHASUM), ("run_url", RUN_URL), ("highest_pinned", SEMVER), ("floor", SEMVER),
                         ("target_tag", FLEET_TAG)):
        value = plan.get(key)
        if value is not None and not (isinstance(value, str) and pattern.fullmatch(value)):
            raise Refused(f"the plan's {key} {value!r} is malformed")
    for key, pattern in (("migrations", MIGRATION_TAG), ("crossed", SEMVER)):
        value = plan.get(key)
        if not (isinstance(value, list) and all(isinstance(item, str) and pattern.fullmatch(item) for item in value)):
            raise Refused(f"the plan's {key} {value!r} is malformed")
    if plan.get("classification") not in CLASSIFICATIONS:
        raise Refused(f"the plan's classification {plan.get('classification')!r} is malformed")
    for key in ("reimport", "below_floor"):
        if not isinstance(plan.get(key), bool):
            raise Refused(f"the plan's {key} {plan.get(key)!r} is malformed")
    if plan.get("branch") != rules["branch"](plan):
        raise Refused(f"the plan's branch {plan.get('branch')!r} does not match its mode and versions")
    if not set(plan.get("labels", [])) <= LABELS:
        raise Refused(f"the plan's labels {plan.get('labels')!r} are not the importer's")
    check_plan_safety_entry(plan)


def check_plan_safety_entry(plan: dict) -> None:
    """The entry the plan asks open-pr to write into rollback-safety.json: none for a rollback, and for a
    forward import a well-formed entry for the plan's version that agrees with the plan's own
    classification, migrations and attested commit."""
    entry = plan.get("safety_entry")
    if entry is None:
        return
    if plan["mode"] != "forward":
        raise Refused(f"the plan's safety_entry {entry!r} is malformed: only a forward import writes one")
    if release_checks.safety_problems({"versions": {plan["version"]: entry}}):
        raise Refused(f"the plan's safety_entry {entry!r} is malformed")
    if (entry["classification"], entry["migrations"], entry["to"]) != (
            plan["classification"], plan["migrations"], plan["git_commit"]):
        raise Refused(f"the plan's safety_entry {entry!r} does not agree with the plan's classification, "
                      "migrations and commit")


def pr_body(plan: dict, run_url: str) -> str:
    version, current, branch = plan["version"], plan["from_version"], plan["branch"]
    # What the provenance check requires of a release, read from the one table it reads, so the body
    # cannot say a different workflow or tag than the check enforces.
    pipeline = release_checks.RELEASE_PIPELINE[PACKAGE]
    provenance_repo = release_checks.PROV_REPO.removeprefix("https://github.com/")
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
        f"- provenance: SLSA, built by `{pipeline['workflow']}` in {provenance_repo} "
        f"at `refs/tags/{pipeline['tag_prefix']}{version}` on a GitHub-hosted runner",
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
            lines += ["", f"**Re-import** (`reimport: true`): `{version}` is not above every version `main`, a "
                      "`fleet-v` tag or a merged release-bot pull request has pinned, or a code owner closed an "
                      "earlier PR for it. Approve only once the reason it was rolled back or rejected is resolved."]
    else:
        floor = plan.get("floor")
        lines.append(f"**Rollback floor** (from `main`'s `{SAFETY_FILE}`): "
                     + (f"`{floor}` is flagged not-rollback-safe between `{version}` and `{plan['highest_pinned']}`."
                        if floor else f"no release between `{version}` and `{plan['highest_pinned']}` is flagged."))
        if plan.get("below_floor"):
            lines.append("**Dispatched with `below_floor: true`.** `validate` fails this PR; only an org owner's "
                         "break-glass merge can land it. The merge is recorded twice: its `fleet-v<N>` tag notes "
                         "that `validate` had not passed on the PR's final head, and `main-audit` opens an issue "
                         "for the merge.")
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
        # validate read the rollback floor from main when it ran, so a reviewed edit to rollback-safety.json
        # that reached main since is not in its verdict.
        *(["- [ ] If `rollback-safety.json` changed on `main` after `validate` ran (compare the `Main read at` "
           "row of its summary with `main`'s head), re-run `validate` before approving."]
          if plan["mode"] == "rollback" else []),
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


@dataclass
class Context:
    """What a planner reads: the checkout, the API (read-only in the verify job), the dispatch inputs and
    the open pull requests the release bot opened."""

    git: Any
    gh: Any
    repo_dir: str
    event: str
    target: str
    reimport: bool
    below_floor: bool
    run_id: str
    doc: dict
    current: str | None
    safety: dict
    bot_open: list


def verify(version: str) -> Any:
    try:
        return release_checks.verify_release(version)
    except release_checks.InfraError as error:
        raise Refused(f"no verdict on {version}: {describe(error)} (a registry, network, npm or GitHub API "
                      "failure, not a verdict on the release; the next run or a re-dispatch retries)") from error
    except release_checks.ReleaseCheckError as error:
        raise Refused(f"{version} fails the release checks: {describe(error)}") from error


def facts(release: Any) -> dict:
    return {"version": release.version, "integrity": release.integrity, "shasum": release.shasum,
            "git_commit": release.git_commit, "run_url": release.run_url}


def check_recorded_entry(version: str, recorded: Any, computed: dict) -> None:
    """Refuse, red, a version whose entry on main validate would fail on the pin PR.

    validate recomputes a recorded entry the same way (validate_pr._recorded_entry_rules): the commit
    it runs up to must be the release's attested commit, and a class weaker than the computed one is
    wrong. A stronger class stands, and a different starting commit is only a note there (the highest
    pinned version below a release moves after a re-import of a lower one), so neither is checked."""
    problems = release_checks.safety_problems({"versions": {version: recorded}})
    if problems:
        raise Refused(f"main's {SAFETY_FILE} entry for {version} is malformed ({problems[0]}); validate would "
                      "fail the pin PR, so a code owner corrects the entry in a reviewed PR first")
    if recorded["to"] != computed["to"]:
        raise Refused(f"main's {SAFETY_FILE} records {version} up to commit {recorded['to']}, but its attested "
                      f"commit is {computed['to']}; validate would fail the pin PR, so a code owner corrects the "
                      "entry in a reviewed PR first")
    if recorded["classification"] == "additive" and computed["classification"] == "not-rollback-safe":
        raise Refused(f"main's {SAFETY_FILE} records {version} as additive, but the importer computes "
                      f"not-rollback-safe ({', '.join(computed['migrations']) or 'none'}); validate would fail "
                      "the pin PR, so a code owner corrects the entry in a reviewed PR first")


def plan_forward(ctx: Context) -> dict:
    scheduled = ctx.event == "schedule"
    if ctx.current is None:
        raise Refused("main has no ai-tc entry: nothing is imported until a restore merges", red=not scheduled)
    rollbacks = pulls_by(ctx.bot_open, ROLLBACK_BRANCH)
    if scheduled and rollbacks:
        raise Refused(f"rollback PR #{rollbacks[0]['number']} is open: the scheduled import opens nothing "
                      "until it merges or closes", red=False)
    pinned = set(release_checks.pinned_versions(ctx.repo_dir))
    # What "above every version ever pinned" means: main and the fleet-v tags (`pinned`, which is also what
    # validate computes a rollback-safety entry from), and the versions the bot's merged pull requests put
    # on main or took it back from, which no tag need name.
    bot_closed = bot_pulls(list_pulls(ctx.gh, "closed"))
    ever = pinned | merged_bot_versions(bot_closed)
    highest = max(ever, key=vkey)
    refused: list[dict] = []
    if ctx.target:
        if not SEMVER.fullmatch(ctx.target):
            raise Refused(f"target {ctx.target!r} is not an exact x.y.z")
        if not vkey(ctx.target) > vkey(ctx.current):
            raise Refused(f"{ctx.target} is not above main's pin {ctx.current}; moving the pin down is a "
                          "rollback-mode dispatch")
        if not ctx.reimport and not vkey(ctx.target) > vkey(highest):
            raise Refused(f"{ctx.target} is not above {highest}, the highest version main, a fleet-v tag or a "
                          "merged release-bot pull request has pinned; re-promoting a version a rollback moved "
                          "away from takes reimport: true")
        release = verify(ctx.target)
    else:
        if ctx.reimport:
            raise Refused("reimport: true needs an explicit target version")
        release = None
        # npm_candidates takes the floor from `ever`; the filter is the same rule stated again, so a
        # version at or below it is never walked, whatever the list holds.
        for candidate in reversed([v for v in release_checks.npm_candidates(ever) if vkey(v) > vkey(highest)]):
            try:
                release = release_checks.verify_release(candidate)
                break
            except release_checks.InfraError as error:
                # A version the checks could not reach a verdict on is not a version they refused. Falling
                # back to a lower one would pin an older release while a newer one might be the real
                # newest, and ending quietly would read as "nothing new". So stop, red, and let the next
                # run try again. A dispatch naming a lower target that is still above every pin imports
                # that release meanwhile, since that path reads no candidate list; the scheduled run stays
                # red until a higher release passes.
                raise Refused(f"no verdict on {candidate}: {describe(error)}. The importer takes the highest "
                              "release that passes and does not fall back to a lower one while a higher one "
                              "has no verdict; the next run retries.") from error
            except release_checks.ReleaseCheckError as error:
                refused.append({"version": candidate, "reason": describe(error)})
                print(f"::warning::npm has {candidate}, which the importer refuses: {describe(error)}")
        if release is None:
            if refused:
                raise Refused(f"no npm release above {highest} passes the release checks "
                              f"(refused: {', '.join(item['version'] for item in refused)})", red=False)
            raise Refused(f"npm has no exact release above {highest}", red=False)
    version = release.version
    branch = f"bot/pin-ai-tc-{version}"
    same = [p for p in ctx.bot_open if p["head"] == branch]
    if same:
        raise Refused(f"PR #{same[0]['number']} for {version} is already open", red=False)
    if not ctx.reimport:
        closed = [p for p in bot_closed if p["head"] == branch and not p["merged"]]
        if closed:
            raise Refused(f"a bot PR for {version} (#{closed[0]['number']}) was closed unmerged; that rejection "
                          "stands until a dispatch with reimport: true", red=not scheduled)
    known = ctx.safety.get("versions", {})
    # Computed whether or not main already records the version, by the computation validate repeats
    # (release_checks.safety_entry): the migrations since the highest version main or a fleet-v tag
    # has pinned below this one, which after a rollback is the release rolled back from, not main's
    # pin. The candidate is not re-verified. That older release is, on every run that gets this far,
    # because its attested commit is where the migration range starts. If it stops verifying (npm or
    # GitHub answers differently than when it was pinned) the importer goes red here, as no verdict for
    # an outage or "could not compute" for a refusal, and opens no pull request until it verifies again.
    # That is wanted: a range that starts at a commit nobody can attest would put an unchecked entry in
    # the safety file, and validate reads the same commit when it checks the pin PR. Pinned by
    # test_an_outage_verifying_the_version_below_is_no_verdict and
    # test_a_verdict_computing_the_safety_entry_still_says_could_not_compute.
    try:
        computed = release_checks.safety_entry(
            version, pinned,
            verify=lambda v: release if v == version else release_checks.verify_release(v),
            classify=release_checks.classify_migrations)
    except release_checks.InfraError as error:
        raise Refused(f"no verdict computing {version}'s {SAFETY_FILE} entry: {describe(error)}") from error
    except release_checks.ReleaseCheckError as error:
        raise Refused(f"could not compute {version}'s {SAFETY_FILE} entry: {describe(error)}") from error
    if version in known:
        # An entry already on main is shown and left alone, but not taken on trust: it may have been
        # typed in for a release nobody classified.
        check_recorded_entry(version, known[version], computed)
        classification, migrations, safety_entry = known[version]["classification"], list(known[version]["migrations"]), None
    else:
        safety_entry = computed
        classification, migrations = safety_entry["classification"], list(safety_entry["migrations"])
    return {**facts(release), "branch": branch, "title": MODE_RULES["forward"]["title"]({"version": version}),
            "labels": [], "classification": classification, "migrations": migrations,
            "safety_entry": safety_entry, "refused": refused, "highest_pinned": highest}


def plan_rollback(ctx: Context) -> dict:
    if ctx.current is None:
        raise Refused("main has no ai-tc entry to roll back; re-adding it is a restore-mode dispatch")
    if not ctx.target:
        raise Refused("a rollback needs a target: an exact x.y.z or fleet-v<N>")
    pins = tag_pins(ctx.repo_dir)
    target_tag = None
    if FLEET_TAG.fullmatch(ctx.target):
        if ctx.target not in pins:
            raise Refused(f"there is no tag {ctx.target}")
        target_tag, version = ctx.target, pins[ctx.target]
        if version is None:
            raise Refused(f"{ctx.target} pins no exact ai-tc version, so it cannot be a rollback target")
    elif SEMVER.fullmatch(ctx.target):
        version = ctx.target
    else:
        raise Refused(f"target {ctx.target!r} is neither an exact x.y.z nor fleet-v<N>")
    if version not in {pinned for pinned in pins.values() if pinned}:
        raise Refused(f"{version} is not a version any fleet-v tag has pinned; a rollback target must be one")
    if not vkey(version) < vkey(ctx.current):
        raise Refused(f"{version} is not below main's pin {ctx.current}, so this is not a rollback")
    pinned = release_checks.pinned_versions(ctx.repo_dir)
    highest = max(pinned, key=vkey)
    # pinned=: a pinned version with no rollback-safety entry counts as flagged, exactly as
    # validate (bot_rules) and the `floor` CLI compute it, so this refusal and validate's agree.
    floor = release_checks.rollback_floor(ctx.safety, version, highest, pinned=pinned)
    if floor is not None and not ctx.below_floor:
        raise Refused(f"{version} is below the rollback floor: {floor} is flagged not-rollback-safe in main's "
                      f"{SAFETY_FILE}, so a Mac's store may already be ahead of {version}'s build. below_floor: true "
                      "opens the PR anyway, but validate fails it and only an org owner's break-glass merge lands it")
    release = verify(version)
    branch = f"bot/rollback-ai-tc-{ctx.current}-to-{version}"
    same = [p for p in ctx.bot_open if p["head"] == branch]
    if same:
        raise Refused(f"rollback PR #{same[0]['number']} for {ctx.current} -> {version} is already open", red=False)
    known = ctx.safety.get("versions", {})
    crossed = sorted((v for v, entry in known.items()
                      if SEMVER.fullmatch(v) and vkey(version) < vkey(v) <= vkey(ctx.current)
                      and entry.get("classification") == "not-rollback-safe"), key=vkey)
    return {**facts(release), "branch": branch,
            "title": MODE_RULES["rollback"]["title"]({"version": version, "from_version": ctx.current}),
            "labels": ["rollback"],
            "classification": "not-rollback-safe" if crossed else "additive", "migrations": [],
            "highest_pinned": highest, "floor": floor, "crossed": crossed, "target_tag": target_tag}


PLANNERS: dict[str, Callable[[Context], dict]] = {"forward": plan_forward, "rollback": plan_rollback}


def make_plan(git: Any, gh: Any, *, repo_dir: str, mode: str, target: str, reimport: bool, below_floor: bool,
              event: str, run_id: str) -> dict:
    if mode not in ("forward", "rollback", "remove", "restore"):
        raise Refused(f"unknown mode {mode!r}")
    planner = PLANNERS.get(mode)
    if planner is None:
        raise Refused(f"{mode} mode is not available: remove and restore are built only once removal is "
                      "qualified as an emergency stop")
    bot_login()
    main_sha = git.rev_parse(git.main())
    raw = git.show(main_sha, MANIFEST)
    if raw is None:
        raise Refused(f"main has no {MANIFEST}")
    safety_raw = git.show(main_sha, SAFETY_FILE)
    if safety_raw is None:
        raise Refused(f"main has no {SAFETY_FILE}")
    doc = json.loads(raw)
    ctx = Context(git=git, gh=gh, repo_dir=repo_dir, event=event, target=target.strip(),
                  reimport=reimport and mode == "forward", below_floor=below_floor and mode != "forward",
                  run_id=run_id, doc=doc, current=pinned_version(doc), safety=json.loads(safety_raw),
                  bot_open=bot_pulls(list_pulls(gh, "open")))
    plan = {"mode": mode, "version": None, "from_version": ctx.current, "integrity": None, "shasum": None,
            "git_commit": None, "run_url": None, "branch": None, "title": None, "labels": [],
            "classification": None, "migrations": [], "safety_entry": None, "refused": [],
            "highest_pinned": None, "floor": None, "crossed": [], "target_tag": None}
    plan.update(planner(ctx))
    plan.update(reimport=ctx.reimport, below_floor=ctx.below_floor, base_sha=main_sha, base_entry=entry_of(doc))
    return plan


AUTO_MERGE_ON = ("mutation($id: ID!) { enablePullRequestAutoMerge(input: {pullRequestId: $id, mergeMethod: SQUASH}) "
                 "{ pullRequest { number } } }")
AUTO_MERGE_OFF = ("mutation($id: ID!) { disablePullRequestAutoMerge(input: {pullRequestId: $id}) "
                  "{ pullRequest { number } } }")
AUTO_MERGE_STATE = ("query($owner: String!, $name: String!, $number: Int!) { repository(owner: $owner, name: $name) "
                    "{ pullRequest(number: $number) { autoMergeRequest { enabledAt } } } }")
# The committer GitHub records, and signs as, on a commit it creates itself (login web-flow).
GITHUB_COMMITTER_EMAIL = "noreply@github.com"


def comment(gh: GitHub, number: int, text: str) -> None:
    gh.post(gh.repo_path(f"issues/{number}/comments"), {"body": text})


def read_file(gh: GitHub, path: str, ref: str) -> str | None:
    try:
        answer = gh.get(gh.repo_path(f"contents/{path}"), params={"ref": ref})
    except GitHubError as error:
        if error.status == 404:
            return None
        raise
    return base64.b64decode(answer["content"]).decode("utf-8")


def branch_exists(gh: GitHub, branch: str) -> bool:
    try:
        gh.get(gh.repo_path(f"git/ref/heads/{branch}"))
    except GitHubError as error:
        if error.status == 404:
            return False
        raise
    return True


def create_commit(gh: GitHub, base_sha: str, files: dict[str, str], message: str) -> str:
    """One commit on base_sha replacing `files`, through the Git Data API.

    No author or committer is sent, so GitHub records the App's bot account as the author and
    itself (GitHub <noreply@github.com>, login web-flow) as the committer, and signs the commit.
    That is the shape validate accepts on a bot PR: every commit authored by the bot App, and
    committed by it or by web-flow with a verified signature. A commit GitHub committed without
    signing would fail validate, so it gets no branch."""
    base_tree = gh.get(gh.repo_path(f"git/commits/{base_sha}"))["tree"]["sha"]
    tree = gh.post(gh.repo_path("git/trees"), {"base_tree": base_tree, "tree": [
        {"path": path, "mode": "100644", "type": "blob", "content": text} for path, text in sorted(files.items())]})["sha"]
    if tree == base_tree:
        raise Refused("the edit leaves main's tree unchanged; there is nothing to commit", red=False)
    created = gh.post(gh.repo_path("git/commits"), {"message": message, "tree": tree, "parents": [base_sha]})
    signed = (created.get("verification") or {}).get("verified") is True
    if (created.get("committer") or {}).get("email") == GITHUB_COMMITTER_EMAIL and not signed:
        raise Refused(f"GitHub committed {created['sha']} without a verified signature, which validate refuses on a "
                      "bot PR, so no branch was created; the App's request must carry no author or committer")
    return created["sha"]


def enable_auto_merge(gh: GitHub, pr: dict) -> None:
    try:
        gh.graphql(AUTO_MERGE_ON, {"id": pr["node_id"]})
    except GitHubError as error:
        raise Refused(f"PR #{pr['number']} is open, but auto-merge could not be enabled, so it stays open for a "
                      f"person to merge: {error}") from error


def supersede_lower(gh: GitHub, plan: dict, number: int) -> list[int]:
    """Close open forward pin PRs for lower versions. Never a rollback PR; a failure only warns."""
    closed = []
    for other in pulls_by(bot_pulls(list_pulls(gh, "open")), PIN_BRANCH):
        other_version = PIN_BRANCH.fullmatch(other["head"]).group(1)
        if other["number"] == number or not vkey(other_version) < vkey(plan["version"]):
            continue
        try:
            comment(gh, other["number"], f"Superseded by the ai-tc pin advance to `{plan['version']}` (#{number}). "
                    "This PR moves the same `source.version` line from the same base, so it can now only conflict. "
                    "The importer never re-imports a lower version on schedule; moving the pin down is a "
                    "rollback-mode dispatch of import-plugin-release to a version a `fleet-v` tag has pinned.")
            gh.patch(gh.repo_path(f"pulls/{other['number']}"), {"state": "closed"})
            closed.append(other["number"])
        except GitHubError as error:
            print(f"::warning::could not close superseded PR #{other['number']}: {error}")
    return closed


def disable_auto_merge(gh: GitHub, pr: dict) -> bool:
    """Turn auto-merge off on `pr`; True once it is off. The mutation answers an error when auto-merge was
    never on (another run's hold got there first), so after an error the PR's own autoMergeRequest decides."""
    try:
        gh.graphql(AUTO_MERGE_OFF, {"id": pr["node_id"]})
    except GitHubError:
        owner, name = gh.repo.split("/", 1)
        state = gh.graphql(AUTO_MERGE_STATE, {"owner": owner, "name": name, "number": pr["number"]})
        return state["repository"]["pullRequest"]["autoMergeRequest"] is None
    return True


def hold_forward(gh: GitHub, number: int, kind: str = "rollback") -> list[int]:
    """Turn auto-merge off on every open forward pin PR while a rollback (or remove) PR is open."""
    held = []
    for other in pulls_by(bot_pulls(list_pulls(gh, "open")), PIN_BRANCH):
        if not disable_auto_merge(gh, other):
            raise Refused(f"could not turn off auto-merge on forward pin PR #{other['number']} while {kind} "
                          f"PR #{number} is open; turn it off by hand")
        comment(gh, other["number"], f"Auto-merge is off: {kind} PR #{number} is open. If it merges, this PR "
                "conflicts: close it and dispatch import-plugin-release with this version as `target` and "
                "`reimport: true` to reopen it on the new `main` (it then needs a fresh approval).")
        held.append(other["number"])
    return held


def close_other_rollbacks(gh: GitHub, number: int, branch: str) -> list[int]:
    closed = []
    for other in pulls_by(bot_pulls(list_pulls(gh, "open")), ROLLBACK_BRANCH):
        if other["number"] == number or other["head"] == branch:
            continue
        comment(gh, other["number"], f"Superseded by rollback PR #{number}.")
        gh.patch(gh.repo_path(f"pulls/{other['number']}"), {"state": "closed"})
        closed.append(other["number"])
    return closed


def after_forward(gh: GitHub, plan: dict, pr: dict) -> str:
    closed = supersede_lower(gh, plan, pr["number"])
    rollbacks = pulls_by(bot_pulls(list_pulls(gh, "open")), ROLLBACK_BRANCH)
    if rollbacks:
        comment(gh, pr["number"], f"Auto-merge is not enabled: rollback PR #{rollbacks[0]['number']} is open. Once it "
                "resolves, enable auto-merge here, or close this PR and dispatch the import with `reimport: true`.")
        return (f"opened #{pr['number']} without auto-merge (rollback PR #{rollbacks[0]['number']} is open); "
                f"superseded {closed}")
    enable_auto_merge(gh, pr)
    # The check above and the enable are not one step, and a rollback run has its own concurrency group.
    # A rollback run opens its PR before it holds the forward PRs, so look again: if its hold ran before
    # the enable, its PR is listed now; if after, its hold turned this PR's auto-merge off itself.
    meanwhile = pulls_by(bot_pulls(list_pulls(gh, "open")), ROLLBACK_BRANCH)
    if meanwhile:
        late = meanwhile[0]["number"]
        if not disable_auto_merge(gh, pr):
            raise Refused(f"rollback PR #{late} opened while auto-merge was being enabled on #{pr['number']}, and "
                          "auto-merge could not be turned off again; turn it off by hand")
        comment(gh, pr["number"], f"Auto-merge is off: rollback PR #{late} opened while it was being enabled. Once it "
                "resolves, enable auto-merge here, or close this PR and dispatch the import with `reimport: true`.")
        return (f"opened #{pr['number']}; auto-merge turned off again: rollback PR #{late} opened meanwhile; "
                f"superseded {closed}")
    return f"opened #{pr['number']} with auto-merge (squash); superseded {closed}"


def after_rollback(gh: GitHub, plan: dict, pr: dict) -> str:
    # Hold the forward pin PRs first: if enabling auto-merge here then fails (red), no approved
    # forward PR can still auto-merge past the open rollback.
    held = hold_forward(gh, pr["number"])
    enable_auto_merge(gh, pr)
    closed = close_other_rollbacks(gh, pr["number"], plan["branch"])
    return f"opened rollback #{pr['number']} with auto-merge (squash); auto-merge off on {held}; closed {closed}"


ACTIONS: dict[str, dict] = {
    "forward": {"edit": edit_pin, "after": after_forward},
    "rollback": {"edit": edit_pin, "after": after_rollback},
}


def open_pr(gh: GitHub, plan: dict, run_url: str) -> str:
    check_plan(plan)
    bot_login()
    actions = ACTIONS[plan["mode"]]
    title = MODE_RULES[plan["mode"]]["title"](plan)
    main_sha = gh.get(gh.repo_path("git/ref/heads/main"))["object"]["sha"]
    raw = read_file(gh, MANIFEST, main_sha)
    if raw is None:
        raise Refused(f"main has no {MANIFEST}")
    if entry_of(json.loads(raw)) != plan["base_entry"]:
        raise Refused("main's ai-tc entry changed after the verify job read it; the next run re-evaluates", red=False)
    branch = plan["branch"]
    if branch_exists(gh, branch):
        open_here = [p for p in list_pulls(gh, "open") if p["head"] == branch]
        if bot_pulls(open_here):
            raise Refused(f"a PR for {branch} is already open", red=False)
        if open_here:
            # Deleting the branch would close that PR. Only the bot's own are the importer's to replace.
            raise Refused(f"{branch} is the head of PR #{open_here[0]['number']}, which {open_here[0]['author'] or 'someone'} "
                          "opened, not the release bot; the importer does not delete a branch another PR uses, so a "
                          "person closes that PR or renames its branch first")
        leftover = False
        if plan["mode"] == "forward" and not plan.get("reimport"):
            if [p for p in bot_pulls(list_pulls(gh, "closed")) if p["head"] == branch]:
                raise Refused(f"{branch} already exists, and the bot's PR for it was closed (tag-release has not yet "
                              "deleted its branch); that rejection stands, and a dispatch with reimport: true "
                              "replaces it", red=False)
            # No PR ever used it, so an earlier run died between creating the branch and opening the PR.
            # Scheduled runs and forward dispatches share one concurrency group (the workflow's header says
            # why they must), so no live run owns it. Delete and create, as a reimport does; the ref is still
            # never force-pushed.
            leftover = True
        gh.delete(gh.repo_path(f"git/refs/heads/{branch}"))
        # Said as what happens next, not as done: the commit and the ref are still to be made, and a failure
        # there ends the run red before anything has been created.
        print(f"::notice::deleted {branch}, left with no pull request by an earlier run; creating it again"
              if leftover else f"deleted {branch}, which had no open PR; creating it again")
    files = {MANIFEST: actions["edit"](raw, plan)}
    if plan.get("safety_entry"):
        safety_raw = read_file(gh, SAFETY_FILE, main_sha)
        if safety_raw is None:
            raise Refused(f"main has no {SAFETY_FILE}")
        added = add_safety_entry(safety_raw, plan["version"], plan["safety_entry"])
        if added is not None:
            files[SAFETY_FILE] = added
    commit = create_commit(gh, main_sha, files, title)
    try:
        gh.post(gh.repo_path("git/refs"), {"ref": f"refs/heads/{branch}", "sha": commit})
    except GitHubError as error:
        if error.status != 422:
            raise
        # A 422 is also what a ref rule answers, so only a branch that now exists proves a lost race.
        if branch_exists(gh, branch):
            raise Refused(f"{branch} was created by another run first", red=False) from error
        raise Refused(f"GitHub refused to create {branch}, and it does not exist: {error.body[:500]}") from error
    pr = gh.post(gh.repo_path("pulls"), {"title": title, "head": branch, "base": "main",
                                         "body": pr_body(plan, run_url)})
    if plan["labels"]:
        gh.post(gh.repo_path(f"issues/{pr['number']}/labels"), {"labels": plan["labels"]})
    return actions["after"](gh, plan, pr)


def write_output(key: str, value: str) -> None:
    if "\n" in value or "\r" in value:
        raise Refused(f"the {key} output is not one line")
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as out:
            print(f"{key}={value}", file=out)
    else:
        print(f"{key}={value}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="import-plugin-release: plan (no secrets) or open-pr (bot App)")
    parser.add_argument("command", choices=["plan", "open-pr"])
    parser.add_argument("--repo-dir", default=".")
    args = parser.parse_args(argv)
    env = os.environ
    gh = GitHub(env.get("GH_TOKEN", ""), env["GITHUB_REPOSITORY"])
    if args.command == "plan":
        # The verify job runs the release checks; open-pr runs none (its calls are GitHub's, each
        # with its own timeout), so it starts no budget. One budget for the whole plan, cleared
        # below however the run ends: every release-check request and npm call is cut to what
        # remains of it, so the run ends with a no-verdict of its own before GitHub cancels the
        # job. The plan's own GitHub reads are not budgeted; each has its own 60 s timeout.
        release_checks.start_budget(release_checks.BUDGET_JOB)
    try:
        if args.command == "plan":
            plan = make_plan(Git(args.repo_dir), gh, repo_dir=args.repo_dir, mode=env.get("MODE") or "forward",
                             target=env.get("TARGET", ""), reimport=env.get("REIMPORT") == "true",
                             below_floor=env.get("BELOW_FLOOR") == "true", event=env.get("EVENT_NAME", ""),
                             run_id=env.get("GITHUB_RUN_ID", ""))
            write_output("proceed", "true")
            write_output("plan", json.dumps(plan, separators=(",", ":")))
            print(f"plan: {plan['mode']} {plan['from_version']} -> {plan['version']} on {plan['branch']}")
        else:
            run_url = f"{env['GITHUB_SERVER_URL']}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}"
            print(open_pr(gh, json.loads(env["PLAN_JSON"]), run_url))
    except Refused as refusal:
        print(f"::{'error' if refusal.red else 'notice'}::{refusal}")
        if args.command == "plan":
            write_output("proceed", "false")
        return 1 if refusal.red else 0
    except (release_checks.InfraError, release_checks.ReleaseCheckError) as error:
        # A call into release_checks that no planner wraps (the npm version list, the pins, the tag
        # ledger, the rollback floor) ends here as one annotation and `proceed=false`, which skips
        # open-pr: red, as before, but one line in the run instead of a traceback.
        print(f"::error::{describe(error)}")
        if args.command == "plan":
            write_output("proceed", "false")
        return 1
    finally:
        release_checks.clear_budget()
    return 0


if __name__ == "__main__":
    sys.exit(main())
