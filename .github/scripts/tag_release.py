"""tag-release: cut fleet-v<N> at every first-parent commit on main whose ai-tc version changed.

A sweep, not a per-push tag: each run walks main's first-parent history from
the last fleet-v tag's commit to the tip, oldest first, and tags every commit
whose ai-tc version (or the entry's absence) differs from its parent's and
that carries no fleet-v tag yet. GitHub keeps one pending run per concurrency
group and drops the rest, so a dropped run loses nothing: the next one tags
what it missed, in commit order. Each tag is annotated, and its message
records the version, integrity, PR, approver and store-migration class, plus
rollback-from, drill and approver-note when they apply. A commit that GitHub
links to no merged PR is left untagged, and so is everything after it, until
it is an hour old: a slow link must not become a permanent `pr: none` tag.
After that hour it is tagged as a push without a PR. A commit dated more than
five minutes ahead of the runner's clock is not young either (only a direct
push can carry one, and waiting for its date would hold every later tag back):
it is tagged at once, as an old one would be. The owners that decide
whether a PR was approved come from CODEOWNERS at the merged commit's parent,
read strictly: one `*` line of user owners. That file is fixed history, which
no later pull request can change, so a parent whose file is anything else never
stops the sweep (it would stop tagging for good): the commit is tagged with
`approver: unknown` and an approver-note saying why, rather than a guess at who
counts.
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
from release_checks import MANIFEST, SAFETY_FILE, SEMVER, InfraError, vkey

ABSENT = "entry removed"
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
    naming user owners (comments and blank lines aside). A team, an email address, a path rule, a second rule
    or no file at all is a Refused, not a guess: a reviewer's login can be matched only to a user, so any other
    shape would turn a real approval into a recorded bypass. What a caller does with the Refused is its own
    call: the sweep tags with an unknown approver, because the file it reads is fixed history."""
    raw = git.show(sha, CODEOWNERS_FILE)
    where = f"{CODEOWNERS_FILE} at {sha[:12]}"
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


def merged_pull(gh: GitHub, sha: str, sleep: Callable[[float], None] = time.sleep) -> dict | None:
    """The PR into main whose merge commit is `sha`, or None. A PR merged into another branch whose merge
    commit later reached main is not main's merge. The association can lag a merge by seconds, so an
    empty answer is asked again before it stands."""
    for attempt in range(ASSOCIATION_ATTEMPTS):
        pulls = gh.get(gh.repo_path(f"commits/{sha}/pulls"))
        merged = [p for p in pulls if p.get("merge_commit_sha") == sha and p.get("merged_at")
                  and (p.get("base") or {}).get("ref") == "main"]
        if merged:
            return merged[0]
        if attempt < ASSOCIATION_ATTEMPTS - 1:
            sleep(ASSOCIATION_WAIT)
    return None


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


def pr_facts(gh: GitHub, sha: str, owners: list[str] | None, sleep: Callable[[float], None] = time.sleep,
             unreadable: str = "") -> dict:
    """What the tag records about the PR that merged `sha`. `owners` is None when CODEOWNERS could not be read
    at the commit's parent, and `unreadable` says why: the PR is still named, but nobody can be matched to an
    approval, so the approver is unknown and no bypass is claimed. With no PR there is no approval to match,
    so the owners do not matter."""
    pull = merged_pull(gh, sha, sleep)
    if pull is None:
        return {"pr": "none", "approver": "none", "note": "no pull request merged this commit", "drill": False}
    number = pull["number"]
    full = gh.get(gh.repo_path(f"pulls/{number}"))
    head = full["head"]["sha"]
    drill = any(label.get("name") == "drill" for label in full.get("labels", []))
    if owners is None:
        return {"pr": str(number), "approver": "unknown", "drill": drill,
                "note": f"code owners could not be read: {unreadable or 'CODEOWNERS is not one line of users'}"}
    approvers = owner_approvals(gh.paginate(gh.repo_path(f"pulls/{number}/reviews")), head, owners)
    if approvers:
        return {"pr": str(number), "approver": approvers[-1], "note": None, "drill": drill}
    merger = (full.get("merged_by") or {}).get("login") or "unknown"
    return {"pr": str(number), "approver": "none", "note": f"ruleset bypass by {merger}", "drill": drill}


def message(n: int, version: str, previous: str, integrity: str, facts: dict, migration: str) -> str:
    lines = [f"fleet-v{n}: ai-tc {version}", "", f"version: {version}", f"integrity: {integrity}",
             f"pr: {facts['pr']}", f"approver: {facts['approver']}", f"store-migration: {migration}"]
    if SEMVER.fullmatch(version) and SEMVER.fullmatch(previous) and vkey(version) < vkey(previous):
        lines.append(f"rollback-from: {previous}")
    if facts["drill"]:
        lines.append("drill: true")
    if facts["note"]:
        lines.append(f"approver-note: {facts['note']}")
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
          now: Callable[[], float] = time.time) -> list[str]:
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
        # pull request can change it. An unreadable file means an unknown approver, recorded on the tag.
        try:
            owners, unreadable = (code_owners(git, parent) if parent else []), ""
        except Refused as refusal:
            owners, unreadable = None, " ".join(str(refusal).split())
        facts = pr_facts(gh, sha, owners, sleep, unreadable)
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
        created.append(f"{name} -> {sha} (ai-tc {version})")
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
            created = sweep(Git(args.repo_dir), gh)
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
