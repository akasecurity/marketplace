"""tag-release: cut fleet-v<N> at every first-parent commit on main whose ai-tc version changed.

A sweep, not a per-push tag: each run walks main's first-parent history from
the last fleet-v tag's commit to the tip, oldest first, and tags every commit
whose ai-tc version (or the entry's absence) differs from its parent's and
that carries no fleet-v tag yet. GitHub keeps one pending run per concurrency
group and drops the rest, so a dropped run loses nothing: the next one tags
what it missed, in commit order. Each tag is annotated, and its message
records the version, integrity, PR, approver and store-migration class, plus
rollback-from, drill and approver-note when they apply. The approver-note also
says when the PR's final head had no passing `validate` run (none at all, or its
latest one failed or had not finished), whoever approved it, so a merge past a
failed check is in the permanent record. Only a run of validate.yml that the
`pull_request_target` event started, at or before the time the PR merged, counts:
a job of that name in another workflow passes nothing, and a run made after the
merge (an edit of the closed PR, a manual re-run) decides nothing. That read uses
the workflow's own token, which can read checks and workflow runs, not the App's.
A commit that GitHub links to no merged PR is left untagged, and so is everything
after it, until it is an hour old: a slow link must not become a permanent
`pr: none` tag. After that hour it is tagged as a push without a PR. A commit
dated more than five minutes ahead of the runner's clock is not young either
(only a direct push can carry one, and waiting for its date would hold every
later tag back): it is tagged at once, as an old one would be. The owners that decide
whether a PR was approved come from CODEOWNERS at the merged commit's parent,
read strictly: one `*` line of user owners. That file is fixed history, which
no later pull request can change, so a parent whose file is anything else (a
team, a path rule, bytes that are not text, no file, or an entry that is not a
file at all, such as a submodule) never stops the sweep, which would stop
tagging for good: a commit a pull request merged is tagged with
`approver: unknown` and an approver-note saying why, rather than a guess at who
counts. A commit no pull request merged records `approver: none`
whatever the file holds, as there is no approval to match.
Likewise a commit whose manifest cannot be read (not JSON, nested too deeply,
a repeated key, an ambiguous ai-tc entry) is never a pin change and never stops
the sweep: every run reports it as a warning and goes on, comparing each later
commit with the nearest earlier one that reads.
The run also deletes the bot's own branches that still point at the head a
closed PR closed on, since only the bot may delete bot/** branches.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from datetime import datetime
from typing import Callable

from ghapi import GitHub, GitHubError
from gitrepo import Git, GitError
from import_release import Refused, entry_of, list_pulls
from issue_router import CODEOWNERS_FILE
from release_checks import GITHUB_ACTIONS_APP_ID, MANIFEST, SAFETY_FILE, SEMVER, InfraError, parse_json, vkey

ABSENT = "entry removed"
# Not a version: what the manifest at a commit says when it cannot be read at all (see Unreadable).
UNREADABLE = "manifest unreadable"
# The modes git gives a regular file; any other mode at the CODEOWNERS path (120000 a symbolic link, 160000 a
# submodule, 040000 a directory) holds nothing a reader can take rules from.
FILE_MODES = ("100644", "100755")
ENTRY_KINDS = {"120000": "a symbolic link", "160000": "a submodule", "040000": "a directory"}
# The required check on main: the job validate.yml runs, which GitHub Actions reports under this name.
VALIDATE_CHECK = "validate"
# Only a check run of that workflow file, run for the event below, is the required check. A job of any other
# name-alike workflow (another file, a push or pull_request run of validate.yml itself) can report the same
# check name. validate.yml runs for pull_request_target, so GitHub takes the workflow from main and not from
# the pull request, which is what makes its answer one a pull request cannot write for itself.
VALIDATE_WORKFLOW = ".github/workflows/validate.yml"
VALIDATE_EVENT = "pull_request_target"
ASSOCIATION_ATTEMPTS = 3
ASSOCIATION_WAIT = 20.0
# How long a commit may stay unlinked from a merged PR before it is tagged as a push without one (the
# hour staleness waits before it reports an untagged pin change).
UNLINKED_GRACE = 3600
# The clock-skew allowance, in seconds. GitHub dates a commit it makes at the moment it makes it, so a
# commit it made is never more than seconds ahead of this runner's clock. One dated further ahead was
# made on a machine with the wrong time (only a direct push can carry one), and it is not young: waiting
# for its date would hold every later tag back until then. It is handled as an old unlinked commit.
CLOCK_SKEW = 300
# A user owner in CODEOWNERS: "@" and a login. A team ("@org/team") or an email address matches no reviewer's login.
USER_OWNER = re.compile(r"@[A-Za-z0-9][A-Za-z0-9_-]*")


class Unreadable(Refused):
    """The manifest at a commit cannot be read: it is not JSON, is nested too deeply to read, repeats a key, has
    no plugins list, or has an ai-tc entry that is ambiguous or malformed. Main's history is fixed, so a commit
    like that never gets better, and a sweep that stopped at one would stop for good: pin_changes treats it as no
    pin change and goes on. It is a Refused only so that, if one ever escapes, the run ends as one error line."""


def entry_at(git: Git, sha: str) -> dict | None:
    """The ai-tc entry of the manifest at `sha`, or None when the commit has no manifest or its manifest has no
    entry. The manifest is read the way validate reads it (parse_json, entry_of), so what is unreadable here is
    unreadable there: Unreadable says so. A checkout that cannot be read at all (a missing object) raises GitError."""
    try:
        raw = git.show(sha, MANIFEST)
        return None if raw is None else entry_of(parse_json(raw))
    except (ValueError, Refused) as error:
        raise Unreadable(f"{MANIFEST} at {sha[:12]} cannot be read: {' '.join(str(error).split())[:200]}") from error


def read_version(git: Git, sha: str | None) -> tuple[str, str]:
    """(the ai-tc version main pinned at `sha`, "") with ABSENT as the version when the entry (or the commit) is
    missing, or (UNREADABLE, why) when the manifest there cannot be read."""
    if sha is None:
        return ABSENT, ""
    try:
        entry = entry_at(git, sha)
    except Unreadable as problem:
        return UNREADABLE, str(problem)
    if entry is None:
        return ABSENT, ""
    version = entry["source"].get("version")
    return (version if isinstance(version, str) and version else "unpinned"), ""


def version_at(git: Git, sha: str | None) -> str:
    """The ai-tc version main pinned at `sha`: ABSENT when the entry (or the commit) is missing, UNREADABLE when
    the manifest there cannot be read."""
    return read_version(git, sha)[0]


def version_up_to(git: Git, sha: str | None) -> str:
    """The version main pinned at `sha`, or at the nearest first-parent ancestor whose manifest can be read:
    what a commit's parent stood for. ABSENT when the entry is missing there, or nothing back to the root reads."""
    while sha is not None:
        version = version_at(git, sha)
        if version != UNREADABLE:
            return version
        sha = git.first_parent(sha)
    return ABSENT


def last_pinned(git: Git, sha: str | None) -> str:
    """The version main last pinned at or before `sha`: its own, or the nearest first-parent ancestor's
    when the entry is removed there or its manifest cannot be read. ABSENT only when nothing back to the root
    pins one."""
    while sha is not None:
        version = version_at(git, sha)
        if version not in (ABSENT, UNREADABLE):
            return version
        sha = git.first_parent(sha)
    return ABSENT


def code_owners(git: Git, sha: str) -> list[str]:
    """The logins CODEOWNERS names at `sha`, read strictly. The file must hold exactly one rule, a `*` line
    naming user owners (comments and blank lines aside). A team, an email address, a path rule, a second rule,
    a file that is not UTF-8 text, an entry that is not a file (a submodule, a symbolic link, a directory) or no
    file at all is a Refused, not a guess: a reviewer's login can be matched only to a user, so any other shape
    would turn a real approval into a recorded bypass. What a caller does with the Refused is its own call: for
    a commit a pull request merged, the sweep tags with an unknown approver, because the file it reads is fixed
    history (a commit no pull request merged records `none`). Only a checkout that cannot be read at all
    (a missing object) raises GitError, as Git.show says."""
    where = f"{CODEOWNERS_FILE} at {sha[:12]}"
    mode = git.entry_mode(sha, CODEOWNERS_FILE)
    if mode is not None and mode not in FILE_MODES:
        # Git.show cannot read a submodule entry (there is no blob) and would raise GitError, which is not a
        # statement about the file; the entry's kind is.
        raise Refused(f"{where} is {ENTRY_KINDS.get(mode, f'a tree entry of mode {mode}')}, not a file; code owners "
                      "can only be read from a file of one `*` line naming users.")
    try:
        raw = git.show(sha, CODEOWNERS_FILE)
    except UnicodeDecodeError as error:
        # Git.show decodes what it reads as UTF-8; a file that is not text is no more readable than a team owner.
        raise Refused(f"{where} is not valid UTF-8 text (byte {error.start} is not); code owners can only be "
                      "read from a file of one `*` line naming users.") from error
    if raw is None:
        raise Refused(f"{where} is missing; code owners can only be read from a file of one `*` line naming users.")
    rules = [fields for fields in (line.split("#", 1)[0].split() for line in raw.splitlines()) if fields]
    if len(rules) != 1 or rules[0][0] != "*":
        raise Refused(f"{where} does not hold exactly one rule, a `*` line; code owners can only be read from a "
                      "file of one `*` line naming users, with no path rules.")
    owners = rules[0][1:]
    if not owners:
        raise Refused(f"{where} names no owner on its `*` line.")
    unusable = [owner for owner in owners if not USER_OWNER.fullmatch(owner)]
    if unusable:
        raise Refused(f"{where} names {', '.join(f'`{owner}`' for owner in unusable)}, which is not a user "
                      "(`@login`); a team or an email address cannot be matched to a reviewer.")
    return [owner[1:] for owner in owners]


def integrity_at(git: Git, sha: str) -> tuple[str, str]:
    """(the integrity the ai-tc entry at `sha` records, "") with "none" when it records none, or ("unknown", why) when
    metadata.integrity holds something that is not a string. The manifest only has to parse to reach here, so a push
    that skipped validate can leave a number or a null there; the tag message is text, and the sweep must not stop on
    a value that cannot be written into it (it would stop on every later run)."""
    entry = entry_at(git, sha)
    metadata = entry.get("metadata") if entry is not None else None
    if not isinstance(metadata, dict):
        return "none", ""
    integrity = metadata.get("integrity", "none")
    if isinstance(integrity, str):
        return integrity, ""
    return "unknown", "integrity unknown: metadata.integrity of the ai-tc entry is not a string"


def pin_changes(git: Git, base: str) -> tuple[list[str], dict[str, str]]:
    """The first-parent commits on main after `base` that changed the ai-tc version and carry no fleet-v tag,
    oldest first, and the commits whose manifest cannot be read, each with why.

    A commit whose manifest cannot be read is never a pin change, and is not compared with: a commit is compared
    with the version at the nearest earlier commit that reads (version_up_to), so a manifest that was broken for
    a commit and mended to the same version is no change either way, and a pin change behind a broken commit is
    found at the first commit that reads again. Main's history is fixed, so a run that stopped at a commit like
    that would stop on every later run; the caller reports it and carries on."""
    tagged = {tag["commit"] for tag in git.fleet_tags()}
    changes, unreadable = [], {}
    # git.main() is the full ref: a bare "main" would resolve to a tag of that name before the branch.
    for sha in git.first_parent_after(base, git.main()):
        if sha in tagged:
            continue
        version, why = read_version(git, sha)
        if version == UNREADABLE:
            unreadable[sha] = why
        elif version != version_up_to(git, git.first_parent(sha)):
            changes.append(sha)
    return changes, unreadable


def last_tag_commit(git: Git) -> str:
    tags = git.fleet_tags()
    if not tags:
        raise Refused("no fleet-v tag exists to sweep from")
    return tags[-1]["commit"]


def pending(git: Git) -> list[str]:
    return pin_changes(git, last_tag_commit(git))[0]


def store_migration(git: Git, sha: str, version: str, previous: str) -> tuple[str, str]:
    """(the store-migration class the tag records, why when that is a fallback the reader should be told about).
    `unknown` also when the safety table at `sha` cannot be read: a rollback would otherwise read an empty table and
    record `additive` across a release that was not safe. The same when an entry the answer rests on has the wrong
    type (an entry that is not an object, a classification that is not a string): the table parses, so only a push
    that skipped validate leaves one, and the sweep must neither stop on it nor call that release additive. On a
    rollback a crossed entry that says not-rollback-safe still decides, whatever else is wrong with the table."""
    if not SEMVER.fullmatch(version):
        return "none", ""
    raw = git.show(sha, SAFETY_FILE)
    try:
        table = parse_json(raw) if raw else {}
    except ValueError:
        return "unknown", ""
    known = table.get("versions", {}) if isinstance(table, dict) else None
    if not isinstance(known, dict):
        return "unknown", ""
    if SEMVER.fullmatch(previous) and vkey(version) < vkey(previous):
        crossed = [entry for v, entry in known.items()
                   if SEMVER.fullmatch(v) and vkey(version) < vkey(v) <= vkey(previous)]
        if any(isinstance(entry, dict) and entry.get("classification") == "not-rollback-safe" for entry in crossed):
            return "not-rollback-safe", ""
        if any(not isinstance(entry, dict) or not isinstance(entry.get("classification", ""), str)
               for entry in crossed):
            return "unknown", (f"store-migration unknown: {SAFETY_FILE} holds an entry between {version} and "
                               f"{previous} that is not an object with a string classification")
        return "additive", ""
    entry = known.get(version)
    if not isinstance(entry, dict):
        return "unknown", ""
    classification = entry.get("classification", "unknown")
    if isinstance(classification, str):
        return classification, ""
    return "unknown", f"store-migration unknown: the classification of {version} in {SAFETY_FILE} is not a string"


def noted(facts: dict, *reasons: str) -> dict:
    """`facts` with each non-empty reason added to the note, joined the way pr_facts joins its notes."""
    note = facts["note"]
    for reason in reasons:
        if reason:
            note = f"{note}; {reason}" if note else reason
    return {**facts, "note": note}


def merged_into_main(pull: dict) -> bool:
    """Whether the API lists `pull` as merged into main. A PR merged into another branch whose commits later
    reached main is not main's merge."""
    return bool(pull.get("merged_at")) and (pull.get("base") or {}).get("ref") == "main"


def pull_association(gh: GitHub, sha: str,
                     sleep: Callable[[float], None] = time.sleep) -> tuple[dict | None, list[dict]]:
    """The PR into main whose merge commit is `sha`, or None, and every PR GitHub linked to `sha` in the answer
    that decided it. The association can lag a merge by seconds, so an empty answer is asked again before it
    stands; the list is the last answer read, which a caller can use without asking again."""
    pulls: list[dict] = []
    for attempt in range(ASSOCIATION_ATTEMPTS):
        pulls = gh.get(gh.repo_path(f"commits/{sha}/pulls"))
        merged = [p for p in pulls if p.get("merge_commit_sha") == sha and merged_into_main(p)]
        if merged:
            return merged[0], pulls
        if attempt < ASSOCIATION_ATTEMPTS - 1:
            sleep(ASSOCIATION_WAIT)
    return None, pulls


def merged_pull(gh: GitHub, sha: str, sleep: Callable[[float], None] = time.sleep) -> dict | None:
    """The PR into main whose merge commit is `sha`, or None (see pull_association)."""
    return pull_association(gh, sha, sleep)[0]


def owner_approvals(reviews, head: str, owners: list[str], exclude=()) -> list[str]:
    """The code owners whose latest review that takes a position approves `head`, the one who approved
    last at the end. Each reviewer's latest APPROVED, CHANGES_REQUESTED or DISMISSED review decides (a comment
    or a pending review changes nothing, and `reviews` is in the API's chronological order), so an approval
    its owner later withdrew, or that was dismissed, does not count. `exclude` names reviewers whose
    approval is not allowed to count, such as the last pusher."""
    latest: dict[str, dict] = {}
    for review in reviews:
        login = (review.get("user") or {}).get("login")
        if login and review.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest.pop(login, None)
            latest[login] = review
    return [login for login, review in latest.items()
            if review["state"] == "APPROVED" and review.get("commit_id") == head
            and login in owners and login not in exclude]


def timestamp(text) -> datetime | None:
    """A GitHub timestamp ("2026-10-02T00:00:00Z") as a datetime, or None when it is missing or in any other form."""
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ") if isinstance(text, str) else None
    except ValueError:
        return None


def is_validate_workflow_run(reader: GitHub, run: dict, suites: dict[int, list]) -> bool:
    """Whether check run `run` was reported by a run of validate.yml that the `pull_request_target` event started.

    A check run names its check suite, and GitHub Actions makes one check suite for each workflow run, so the
    workflow runs listed for the suite say what the check run belongs to (`check_suite_id` is a documented
    filter of the repository's workflow-run list, and each run there states its `event` and the `path` of its
    workflow file). A check run with no suite, or one whose suite lists no workflow run or more than one, is not
    counted: nothing says what it belongs to. `suites` keeps the answers of one call, so a suite is asked once."""
    suite = (run.get("check_suite") or {}).get("id")
    if not isinstance(suite, int) or isinstance(suite, bool):
        return False
    if suite not in suites:
        answer = reader.get(reader.repo_path("actions/runs"), {"check_suite_id": suite})
        listed = answer.get("workflow_runs") if isinstance(answer, dict) else None
        suites[suite] = listed if isinstance(listed, list) else []
    if len(suites[suite]) != 1 or not isinstance(suites[suite][0], dict):
        return False
    workflow = suites[suite][0]
    # The path is the workflow file's; a trailing "@<ref>" is accepted, as GitHub's own examples show one.
    return (workflow.get("event") == VALIDATE_EVENT
            and isinstance(workflow.get("path"), str) and workflow["path"].split("@", 1)[0] == VALIDATE_WORKFLOW)


def validate_conclusion(reader: GitHub, head: str, merged_at: str | None) -> str | None:
    """How the latest `validate` run on `head` that counts ended, or None when none counts. A run that has not
    finished has no conclusion, so its status stands in for it (`queued`, `in_progress`); the two sets of words
    do not overlap, and only `success` is a pass.

    The required check is the job named `validate` that GitHub Actions reports, so the runs are asked for by
    name and app and checked again here. Of those, a run counts only if it
    (1) started at or before `merged_at`, the time its pull request merged: a run made afterwards (an edit of the
        closed pull request starts one, and so does a manual re-run) neither fails a head that was validated nor
        passes one that was not. A run queued before the merge and started after it started after it. A run with
        no start time, or a merge with no time, cannot be placed before the merge and does not count; and
    (2) belongs to a run of .github/workflows/validate.yml started by `pull_request_target`
        (is_validate_workflow_run), so a job of that name in any other workflow, or in a push or pull_request run,
        passes nothing and fails nothing.
    Of the runs that count the latest (the highest id) decides: a re-run that failed after an earlier pass leaves
    the head unvalidated. They are tried newest first, so the workflow run behind a check run is asked about only
    until one counts. `filter=all` asks for every run, not just the latest of each name.

    The reader needs `checks: read` and `actions: read`. A failed read raises, as any read of GitHub does."""
    merged = timestamp(merged_at)
    runs = [run for run in reader.paginate(reader.repo_path(f"commits/{head}/check-runs"),
                                           {"check_name": VALIDATE_CHECK, "app_id": GITHUB_ACTIONS_APP_ID,
                                            "filter": "all"})
            if run.get("name") == VALIDATE_CHECK and (run.get("app") or {}).get("id") == GITHUB_ACTIONS_APP_ID]
    suites: dict[int, list] = {}
    for run in sorted(runs, key=lambda run: run.get("id") or 0, reverse=True):
        started = timestamp(run.get("started_at"))
        if merged is not None and started is not None and started <= merged \
                and is_validate_workflow_run(reader, run, suites):
            if run.get("status") != "completed":
                return run.get("status") or "unfinished"
            return run.get("conclusion") or "without a result"
    return None


def pr_facts(gh: GitHub, sha: str, owners: list[str] | None, sleep: Callable[[float], None] = time.sleep,
             unreadable: str = "", reader: GitHub | None = None) -> dict:
    """What the tag records about the PR that merged `sha`. `owners` is None when CODEOWNERS could not be read
    at the commit's parent, and `unreadable` says why: the PR is still named, but nobody can be matched to an
    approval, so the approver is unknown and no bypass is claimed. With no PR there is no approval to match,
    so the owners do not matter.

    Whoever approved it, a PR whose final head has no passing `validate` run gets that said in the note, joined
    to any other note: a below-floor rollback or any other merge past a red or missing check is then in the
    record. `reader` is the client for that read (the workflow's token, which can read checks; the App's cannot
    and does not need to); it defaults to `gh`."""
    pull = merged_pull(gh, sha, sleep)
    if pull is None:
        return {"pr": "none", "approver": "none", "note": "no pull request merged this commit", "drill": False}
    number = pull["number"]
    full = gh.get(gh.repo_path(f"pulls/{number}"))
    head = full["head"]["sha"]
    drill = any(label.get("name") == "drill" for label in full.get("labels", []))
    merger = (full.get("merged_by") or {}).get("login") or "unknown"
    bypass = False
    if owners is None:
        approver = "unknown"
        note = f"code owners could not be read: {unreadable or 'CODEOWNERS is not one line of users'}"
    else:
        approvers = owner_approvals(gh.paginate(gh.repo_path(f"pulls/{number}/reviews")), head, owners)
        approver, note = (approvers[-1], None) if approvers else ("none", f"ruleset bypass by {merger}")
        bypass = not approvers
    conclusion = validate_conclusion(gh if reader is None else reader, head, pull["merged_at"])
    if conclusion != "success":
        unvalidated = ("validate had not passed on the PR's final head "
                       f"({'no run' if conclusion is None else f'latest run: {conclusion}'})")
        # The merger is already named by a bypass note; otherwise the note names who merged past the check.
        unvalidated += "" if bypass else f"; merged by {merger}"
        note = f"{note}; {unvalidated}" if note else unvalidated
    return {"pr": str(number), "approver": approver, "note": note, "drill": drill}


def one_line(text: str) -> str:
    """`text` as part of one line of a tag message: every character that is not printable (a line break of any
    kind, any other control or separator character) is written as an escape. The manifest and the safety table
    are free text, and a tag message is read line by line, so an unescaped value could add a line of its own
    (a second `pr:`, a `drill:`) to a permanent record. Printable text, the ordinary case, is unchanged."""
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text)


def message(n: int, version: str, previous: str, integrity: str, facts: dict, migration: str) -> str:
    """The tag message. Every value that comes from a file or from GitHub goes in as one line (`one_line`); a
    version that is not x.y.z is recorded as it stands, because that record is what lets the audit flag it."""
    shown = one_line(version)
    lines = [f"fleet-v{n}: ai-tc {shown}", "", f"version: {shown}", f"integrity: {one_line(integrity)}",
             f"pr: {one_line(facts['pr'])}", f"approver: {one_line(facts['approver'])}",
             f"store-migration: {one_line(migration)}"]
    if SEMVER.fullmatch(version) and SEMVER.fullmatch(previous) and vkey(version) < vkey(previous):
        lines.append(f"rollback-from: {previous}")
    if facts["drill"]:
        lines.append("drill: true")
    if facts["note"]:
        lines.append(f"approver-note: {one_line(facts['note'])}")
    return "\n".join(lines) + "\n"


def refused_by_github(what: str, error: GitHubError, cause: str, done: list[str]) -> Refused:
    """A write GitHub refused, as the one-line refusal the workflow annotates: what was refused, GitHub's answer,
    the likely cause, and what this run had already done (it is not undone)."""
    answer = " ".join(error.body.split())[:300]
    already = f" Already done in this run: {', '.join(done)}." if done else ""
    return Refused(f"GitHub refused {what} (HTTP {error.status}: {answer}). {cause}{already}")


def tag_exists(gh: GitHub, name: str) -> bool:
    try:
        gh.get(gh.repo_path(f"git/ref/tags/{name}"))
    except GitHubError as error:
        if error.status == 404:
            return False
        raise
    return True


def sweep(git: Git, gh: GitHub, sleep: Callable[[float], None] = time.sleep,
          now: Callable[[], float] = time.time, reader: GitHub | None = None) -> list[str]:
    """Tag every untagged pin change on main, oldest first. `gh` writes (the App's token); `reader` reads the
    checks of a merged PR's head (the workflow token) and defaults to `gh`."""
    todo, unreadable = pin_changes(git, last_tag_commit(git))
    for why in unreadable.values():
        # One line each, and the sweep goes on: no later pull request can mend a commit already on main.
        print(f"::warning::{why}. It is not counted as a pin change, and the sweep goes on with the commits after it.")
    number = git.fleet_tags()[-1]["n"]
    created = []
    for sha in todo:
        number += 1
        name = f"fleet-v{number}"
        if tag_exists(gh, name):
            raise Refused(f"{name} already exists on GitHub but not in this checkout; re-run the sweep")
        parent = git.first_parent(sha)
        version, previous = version_at(git, sha), version_up_to(git, parent)
        if previous == ABSENT:
            # A restore after a removal moves the Macs from the last version pinned before the removal.
            previous = last_pinned(git, parent)
        # The parent's file is fixed history: refusing here would keep every later commit untagged for good, as no
        # pull request can change it. An unreadable file means an unknown approver, recorded on the tag of a commit
        # a pull request merged.
        try:
            owners, unreadable = (code_owners(git, parent) if parent else []), ""
        except Refused as refusal:
            owners, unreadable = None, " ".join(str(refusal).split())
        facts = pr_facts(gh, sha, owners, sleep, unreadable, reader)
        if facts["pr"] == "none" and -CLOCK_SKEW <= now() - git.commit_time(sha) < UNLINKED_GRACE:
            raise Refused(f"{sha[:12]} changed the ai-tc version, but GitHub links no merged pull request into main "
                          "to it yet, so nothing from it on was tagged. A commit under an hour old is left untagged "
                          "so that a slow link never becomes a permanent `pr: none` tag: the next push to main or a "
                          "dispatch of tag-release asks again, and from an hour after the commit an unlinked commit "
                          "is tagged as a push without a pull request.")
        integrity, integrity_why = integrity_at(git, sha)
        migration, migration_why = store_migration(git, sha, version, previous)
        text = message(number, version, previous, integrity, noted(facts, integrity_why, migration_why), migration)
        try:
            tag_object = gh.post(gh.repo_path("git/tags"),
                                 {"tag": name, "message": text, "object": sha, "type": "commit"})["sha"]
            gh.post(gh.repo_path("git/refs"), {"ref": f"refs/tags/{name}", "sha": tag_object})
        except GitHubError as error:
            raise refused_by_github(
                f"to create {name} at {sha[:12]}", error,
                "The release bot App must be a bypass actor of the fleet-tags-create ruleset, the only way a "
                "fleet-v tag can be created, and have contents: write.", created) from error
        created.append(f"{name} -> {sha} (ai-tc {one_line(version)})")
        print(f"created {created[-1]}")
    return created


def cleanup_branches(gh: GitHub) -> list[str]:
    """Delete a bot/** branch only while it still points at the head a closed PR of that name closed on, and
    no open PR uses the name. Keep a branch with an open PR, one with no PR at all, and one re-created after its
    PR closed: a reimport or a repeated rollback reuses a branch name, and a re-created branch is a new commit,
    so its tip matches no closed PR's head. The REST API has no delete that compares the tip, so a branch
    re-created between reading the refs and deleting this one would still go; the tip check closes the wider
    gap between reading the pull requests and the refs."""
    open_heads = {p["head"] for p in list_pulls(gh, "open")}
    closed_tips: dict[str, set[str]] = {}
    for closed in list_pulls(gh, "closed"):
        closed_tips.setdefault(closed["head"], set()).add(closed["head_sha"])
    deleted = []
    for ref in gh.get(gh.repo_path("git/matching-refs/heads/bot/")):
        branch = ref["ref"][len("refs/heads/"):]
        tip = (ref.get("object") or {}).get("sha")
        if branch in open_heads or not tip or tip not in closed_tips.get(branch, set()):
            continue
        try:
            gh.delete(gh.repo_path(f"git/refs/heads/{branch}"))
        except GitHubError as error:
            raise refused_by_github(
                f"to delete {branch}", error,
                "The release bot App must be a bypass actor of the bot-branches ruleset, which restricts "
                "deleting bot/** branches, and have contents: write.", deleted) from error
        deleted.append(branch)
    return deleted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="tag-release: tag main's untagged pin changes; clean up bot branches")
    parser.add_argument("command", choices=["sweep", "cleanup-branches"])
    parser.add_argument("--repo-dir", default=".")
    args = parser.parse_args(argv)
    gh = GitHub(os.environ.get("GH_TOKEN", ""), os.environ["GITHUB_REPOSITORY"])
    try:
        if args.command == "sweep":
            # The App's token writes the tags; the workflow's own token (GITHUB_TOKEN, `checks: read`) reads checks.
            reader = GitHub(os.environ.get("GITHUB_TOKEN", ""), os.environ["GITHUB_REPOSITORY"])
            created = sweep(Git(args.repo_dir), gh, reader=reader)
            print(f"tagged {len(created)} commit(s)" if created
                  else "nothing to tag: every pin change on main has its fleet-v tag")
        else:
            deleted = cleanup_branches(gh)
            print("deleted " + (", ".join(deleted) if deleted else "no branch"))
    except Refused as refusal:
        print(f"::error::{refusal}")
        return 1
    except (GitHubError, GitError, InfraError) as error:
        # A failed read or write, or a checkout without main: one annotation, not a traceback.
        print(f"::error::{' '.join(str(error).split())}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
