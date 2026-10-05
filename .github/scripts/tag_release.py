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
failed check is in the permanent record. That read uses the workflow's own
token, which can read checks, not the App's. A commit that GitHub links to no
merged PR is left untagged, and so is everything after it, until it is an hour
old: a slow link must not become a permanent `pr: none` tag. After that hour
it is tagged as a push without a PR. A commit dated more than
five minutes ahead of the runner's clock is not young either (only a direct
push can carry one, and waiting for its date would hold every later tag back):
it is tagged at once, as an old one would be. The owners that decide
whether a PR was approved come from CODEOWNERS at the merged commit's parent,
read strictly: one `*` line of user owners. That file is fixed history, which
no later pull request can change, so a parent whose file is anything else (a
team, a path rule, bytes that are not text, no file, or an entry that is not a
file at all, such as a submodule) never stops the sweep, which would stop
tagging for good: a commit a pull request merged is tagged with
`approver: unknown` and an approver-note saying why, rather than a guess at who
counts. A commit no pull request merged records `approver: none`
whatever the file holds, as there is no approval to match.
The run also deletes the bot's own branches that still point at the head a
closed PR closed on, since only the bot may delete bot/** branches.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from typing import Callable

from ghapi import GitHub, GitHubError
from gitrepo import Git, GitError
from import_release import Refused, entry_of, list_pulls
from issue_router import CODEOWNERS_FILE
from release_checks import GITHUB_ACTIONS_APP_ID, MANIFEST, SAFETY_FILE, SEMVER, InfraError, vkey

ABSENT = "entry removed"
# The modes git gives a regular file; any other mode at the CODEOWNERS path (120000 a symbolic link, 160000 a
# submodule, 040000 a directory) holds nothing a reader can take rules from.
FILE_MODES = ("100644", "100755")
ENTRY_KINDS = {"120000": "a symbolic link", "160000": "a submodule", "040000": "a directory"}
# The required check on main: the job validate.yml runs, which GitHub Actions reports under this name.
VALIDATE_CHECK = "validate"
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


def version_at(git: Git, sha: str | None) -> str:
    """The ai-tc version main pinned at `sha`, or ABSENT when the entry (or the commit) is missing."""
    if sha is None:
        return ABSENT
    raw = git.show(sha, MANIFEST)
    if raw is None:
        return ABSENT
    entry = entry_of(json.loads(raw))
    if entry is None:
        return ABSENT
    version = entry["source"].get("version")
    return version if isinstance(version, str) and version else "unpinned"


def last_pinned(git: Git, sha: str | None) -> str:
    """The version main last pinned at or before `sha`: its own, or the nearest first-parent ancestor's
    when the entry is removed there. ABSENT only when nothing back to the root pins one."""
    while sha is not None:
        version = version_at(git, sha)
        if version != ABSENT:
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


def integrity_at(git: Git, sha: str) -> str:
    raw = git.show(sha, MANIFEST)
    entry = entry_of(json.loads(raw)) if raw else None
    metadata = entry.get("metadata") if entry is not None else None
    return metadata.get("integrity", "none") if isinstance(metadata, dict) else "none"


def pending(git: Git) -> list[str]:
    tags = git.fleet_tags()
    if not tags:
        raise Refused("no fleet-v tag exists to sweep from")
    tagged = {tag["commit"] for tag in tags}
    # git.main() is the full ref: a bare "main" would resolve to a tag of that name before the branch.
    return [sha for sha in git.first_parent_after(tags[-1]["commit"], git.main())
            if sha not in tagged and version_at(git, sha) != version_at(git, git.first_parent(sha))]


def store_migration(git: Git, sha: str, version: str, previous: str) -> str:
    if not SEMVER.fullmatch(version):
        return "none"
    raw = git.show(sha, SAFETY_FILE)
    known = json.loads(raw).get("versions", {}) if raw else {}
    if SEMVER.fullmatch(previous) and vkey(version) < vkey(previous):
        crossed = [entry for v, entry in known.items()
                   if SEMVER.fullmatch(v) and vkey(version) < vkey(v) <= vkey(previous)]
        return ("not-rollback-safe" if any(entry.get("classification") == "not-rollback-safe" for entry in crossed)
                else "additive")
    entry = known.get(version)
    return entry.get("classification", "unknown") if isinstance(entry, dict) else "unknown"


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


def validate_conclusion(reader: GitHub, head: str) -> str | None:
    """How the latest `validate` run from GitHub Actions on `head` ended, or None when none ran. A run that has
    not finished has no conclusion, so its status stands in for it (`queued`, `in_progress`); the two sets of
    words do not overlap, and only `success` is a pass.

    The required check is the job named `validate` that GitHub Actions reports, so the runs are asked for by
    name and app and checked again here, and the latest of them (the highest id) decides: a re-run that failed
    after an earlier pass leaves the head unvalidated. `filter=all` asks for every run, not just the latest of
    each name."""
    runs = [run for run in reader.paginate(reader.repo_path(f"commits/{head}/check-runs"),
                                           {"check_name": VALIDATE_CHECK, "app_id": GITHUB_ACTIONS_APP_ID,
                                            "filter": "all"})
            if run.get("name") == VALIDATE_CHECK and (run.get("app") or {}).get("id") == GITHUB_ACTIONS_APP_ID]
    if not runs:
        return None
    latest = max(runs, key=lambda run: run.get("id") or 0)
    if latest.get("status") != "completed":
        return latest.get("status") or "unfinished"
    return latest.get("conclusion") or "without a result"


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
    conclusion = validate_conclusion(gh if reader is None else reader, head)
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
    todo = pending(git)
    number = git.fleet_tags()[-1]["n"]
    created = []
    for sha in todo:
        number += 1
        name = f"fleet-v{number}"
        if tag_exists(gh, name):
            raise Refused(f"{name} already exists on GitHub but not in this checkout; re-run the sweep")
        parent = git.first_parent(sha)
        version, previous = version_at(git, sha), version_at(git, parent)
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
        text = message(number, version, previous, integrity_at(git, sha), facts,
                       store_migration(git, sha, version, previous))
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
