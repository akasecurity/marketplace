"""main-audit: every commit a push adds to main must be the merge of a code-owner-approved PR.

Red unless each commit is the merge commit of a PR with an approving review,
on the PR's final head, from a code owner (CODEOWNERS at the commit's parent)
who is not its last pusher. REST names no pusher, so the head commit's author
and committer stand in for the last pusher (web-flow, GitHub's committer for
web edits, is skipped); the main ruleset's "most recent push approved by
someone else" is what enforces the rule, and this records when it was
bypassed. Detective only: it runs from the pushed commit's own file, so a
bypass push can change it in the same push.
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


def audit(git: Git, gh: GitHub, before: str, after: str, sleep: Callable[[float], None] = time.sleep) -> list[Result]:
    """One red result per offending commit or rewrite of main, then one green summary of the push.

    The summary is always the last result, so the list is never empty. It is green and auto_close is off, so
    the router files nothing and closes nothing for it (the red ones wait for a person); it records the number
    of commits the push added and the number of red results.
    """
    commits = added_commits(git, before, after)
    results = []
    for sha in commits:
        problem = audit_commit(gh, git, sha, sleep)
        if problem:
            results.append(Result(
                rule=f"main-audit-{sha[:12]}", label=LABEL,
                title=f"main-audit: {sha[:12]} reached main without a code-owner-approved PR", red=True,
                auto_close=False,
                detail=problem + "\n\nIf this was a break-glass merge, record the incident and who merged it "
                                 "here; a person closes this issue once it is explained."))
    if not commits and before and not ZERO.fullmatch(before) and before != after:
        results.append(Result(
            rule=f"main-audit-rewrite-{after[:12]}", label=LABEL,
            title=f"main-audit: main moved from {before[:12]} to {after[:12]} without adding a commit", red=True,
            auto_close=False,
            detail=f"main moved from `{before}` to `{after}` and the push added no commit, so history was "
                   "rewritten or reset.\n\nRecord who did it and why here; a person closes this issue once it "
                   "is explained."))
    flagged = sum(1 for item in results if item.red)
    results.append(Result(
        rule=SUMMARY_RULE, label=LABEL, title="main-audit: the commits a push added to main", red=False,
        auto_close=False,
        detail=f"{len(commits)} commit(s) added by this push, {flagged} flagged."))
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
    print(f"{len(flagged)} commit(s) in this push reached main without a code-owner-approved PR")
    write_output("results", results_to_json(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
