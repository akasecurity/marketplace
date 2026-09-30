"""main-audit: every commit a push adds to main must be the merge of a code-owner-approved PR.

Red unless each commit is the merge commit of a PR with an approving review,
on the PR's final head, from a code owner (CODEOWNERS at the commit's parent)
who is not its last pusher. REST names no pusher, so the head commit's author
and committer stand in for the last pusher (web-flow, GitHub's committer for
web edits, is skipped); the main ruleset's "most recent push approved by
someone else" is what enforces the rule, and this records when it was
bypassed. Detective only: it runs from the pushed commit's own file, so a
bypass push can change it in the same push. Every red result is keyed to its
push and closed only by a person; a push the audit could not finish, or one
that moved main without extending it, gets its own such result.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from typing import Callable

from ghapi import GitHub
from gitrepo import Git
from import_release import write_output
from issue_router import CODEOWNERS_FILE, Result, parse_codeowners, results_to_json
from tag_release import merged_pull

LABEL = "main-audit"
SUMMARY_RULE = "main-audit"
REWRITE_RULE = "main-audit-rewrite-"
UNAUDITED_RULE = "main-audit-unaudited-"
ZERO = re.compile(r"0{40}")
NOT_A_PUSHER = {"web-flow"}


def added_commits(git: Git, before: str, after: str) -> list[str]:
    if not before or ZERO.fullmatch(before):
        return [after]
    return git.commits_between(before, after)


def audit_commit(gh: GitHub, git: Git, sha: str, sleep: Callable[[float], None]) -> str | None:
    pull = merged_pull(gh, sha, sleep)
    if pull is None:
        return f"`{sha}` is not the merge commit of any pull request: it was pushed to main directly."
    number = pull["number"]
    head = gh.get(gh.repo_path(f"pulls/{number}"))["head"]["sha"]
    parent = git.first_parent(sha)
    owners = parse_codeowners(git.show(parent, CODEOWNERS_FILE) or "") if parent else []
    head_commit = gh.get(gh.repo_path(f"commits/{head}"))
    pushers = {login for login in ((head_commit.get("author") or {}).get("login"),
                                   (head_commit.get("committer") or {}).get("login"))
               if login and login not in NOT_A_PUSHER}
    approvals = [review for review in gh.paginate(gh.repo_path(f"pulls/{number}/reviews"))
                 if review.get("state") == "APPROVED" and review.get("commit_id") == head
                 and (review.get("user") or {}).get("login") in owners
                 and review["user"]["login"] not in pushers]
    if approvals:
        return None
    return (f"`{sha}` merged PR #{number} without an approving review from a code owner "
            f"({', '.join(owners) or 'none listed'}) on its final head `{head}` by someone other than its last "
            f"pusher ({', '.join(sorted(pushers)) or 'unknown'}).")


def rewrite_problem(git: Git, before: str, after: str) -> str | None:
    """Why this push moved main other than by adding commits on top of the old tip, or None when it did not.

    An old tip that only main held is not fetched once main has moved off it, so an unknown `before` is the
    ordinary shape of a reset or force-push and reads as one."""
    if not before or ZERO.fullmatch(before):
        return None
    ancestor = git.is_ancestor(before, after)
    if ancestor is True:
        return None
    if ancestor is None:
        return (f"main moved from `{before}` to `{after}` and the old tip is not in the checkout, so it is no "
                "longer reachable from any branch or tag: history was rewritten or reset.")
    return f"main moved from `{before}` to `{after}` and the old tip is not an ancestor of the new one: history was rewritten or reset."


def audit(git: Git, gh: GitHub, before: str, after: str, sleep: Callable[[float], None] = time.sleep) -> list[Result]:
    """One red result per offending commit, rewrite of main or unfinished audit, then one green summary of the push.

    The summary is always the last result, so the list is never empty. It is green and auto_close is off, so
    the router files nothing and closes nothing for it; it records the number of commits it set out to audit and the
    number of red results. Every red result is keyed to this push and never closes by itself (auto_close is
    off), so a push the audit could not finish is recorded too: an error part-way through keeps what was
    found so far and adds an unaudited result, rather than failing the job into the shared workflow issue.
    A moved-not-extended main audits the new tip only.
    """
    results: list[Result] = []
    commits: list[str] = []
    try:
        moved = rewrite_problem(git, before, after)
        if moved:
            commits = [after]
            results.append(Result(
                rule=f"{REWRITE_RULE}{after[:12]}", label=LABEL, red=True, auto_close=False,
                title=f"main-audit: main moved from {before[:12]} to {after[:12]} without extending it",
                detail=moved + "\n\nRecord who did it and why here; a person closes this issue once it is explained."))
        else:
            commits = added_commits(git, before, after)
        for sha in commits:
            # Only a push's tip can be a merge that push has only just made, so only it waits for the
            # pull request association; every other commit is read once.
            problem = audit_commit(gh, git, sha, sleep if sha == after else (lambda seconds: None))
            if problem:
                results.append(Result(
                    rule=f"main-audit-{sha[:12]}", label=LABEL,
                    title=f"main-audit: {sha[:12]} reached main without a code-owner-approved PR", red=True,
                    auto_close=False,
                    detail=problem + "\n\nIf this was a break-glass merge, record the incident and who merged it "
                                     "here; a person closes this issue once it is explained."))
    except Exception as error:  # noqa: BLE001 - whatever stopped the audit must not end as an unrecorded push
        reason = " ".join(f"{type(error).__name__}: {error}".split())[:300]
        results.append(Result(
            rule=f"{UNAUDITED_RULE}{after[:12]}", label=LABEL, red=True, auto_close=False,
            title=f"main-audit: the push to {after[:12]} could not be audited",
            detail=f"The audit of the push from `{before or 'nothing'}` to `{after}` stopped before it finished "
                   f"({reason}), so some or all of its commits were not checked.\n\nCheck them by hand and "
                   "record the result here; a person closes this issue once they are checked."))
    flagged = sum(1 for item in results if item.red)
    results.append(Result(
        rule=SUMMARY_RULE, label=LABEL, title="main-audit: the commits a push added to main", red=False,
        auto_close=False,
        detail=f"{len(commits)} commit(s) audited in this push, {flagged} flagged."))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="main-audit: the commits a push added to main")
    parser.add_argument("--repo-dir", default=".")
    args = parser.parse_args(argv)
    env = os.environ
    results = audit(Git(args.repo_dir), GitHub(env.get("GH_TOKEN", ""), env["GITHUB_REPOSITORY"]),
                    env.get("BEFORE", ""), env["AFTER"])
    flagged = [item for item in results if item.red]
    for item in flagged:
        print(f"::error::{item.detail.splitlines()[0]}")
    commits = [item for item in flagged if not item.rule.startswith((REWRITE_RULE, UNAUDITED_RULE))]
    print(f"{len(commits)} commit(s) in this push reached main without a code-owner-approved PR")
    print(f"{len(flagged) - len(commits)} other problem(s) with this push: main rewritten, or the audit unfinished")
    write_output("results", results_to_json(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
