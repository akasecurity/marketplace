"""staleness: hourly checks that the release chain has not stalled.

Each rule is its own result, filed as its own issue by issue_router.py:
  (i)   npm has an exact x.y.z above every version main or a fleet-v tag has
        pinned that passes the release checks and was published more than 24
        hours ago; a version the importer refuses is its own result once it has
        been on npm for an hour, and so is a version the checks could not finish
        on (the registry, the network, npm or GitHub failed: no verdict, which is
        neither a refusal nor a release that is gone). While a version that has
        been on npm for over an hour, or whose publish time is unknown, has no
        verdict, (i) and the refused-version rule can still go red from the
        versions that did finish, but neither is cleared. A younger version is
        left out: neither rule can name it yet. So an outage never closes the
        issue of a version either rule could name;
  (ii)  a bot PR has been open for more than 24 hours;
  (iii) a first-parent commit on main after the last frozen tag's commit, more
        than an hour old, changed the ai-tc version and carries no fleet-v tag
        (a commit whose manifest cannot be read is no pin change: the run logs
        a warning for it and goes on, as tag-release does);
  (iv)  a tag other than fleet-v<N> (N a positive integer without a leading
        zero) exists, or a ref other than refs/heads/main answers to the name
        main.
Also: the ai-tc entry missing from main, or main's manifest unreadable (red
until a PR that restores or mends it merges), the "rolled back, awaiting
fix-forward" notice while the latest fleet-v tag is a rollback (rule (i) stays
live then, so a fix-forward the importer fails to pin still goes red), and a
drill result a manual run raises to test the path.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from typing import Callable

import release_checks
from ghapi import GitHub
from gitrepo import Git
from import_release import describe, list_pulls, write_output
from issue_router import Result, results_to_json
from release_checks import MANIFEST, vkey
from tag_release import Unreadable, entry_at, pin_changes, version_at

LABEL = "staleness"
HOUR = dt.timedelta(hours=1)
DAY = dt.timedelta(hours=24)
REGISTRY_URL = release_checks.packument_url()
SHADOWS = ("refs/main", "refs/tags/main", "refs/remotes/main", "refs/remotes/main/HEAD")
TITLES = {
    # One rule, one issue, for both ways main can have no usable ai-tc entry (the detail says which): the entry is
    # missing, or the manifest cannot be read at all. The router titles an issue once, when it opens it.
    "staleness-entry": "staleness: the ai-tc entry is missing from main, or main's manifest cannot be read",
    "staleness-i": "staleness: npm has had a passing ai-tc release above every pin for over 24 hours",
    "staleness-i-refused": "staleness: npm has an ai-tc version the importer refuses",
    "staleness-i-no-verdict": "staleness: the release checks reached no verdict on an ai-tc version",
    "staleness-ii": "staleness: a bot PR has been open for more than 24 hours",
    "staleness-iii": "staleness: a pin change on main has had no fleet-v tag for over an hour",
    "staleness-iv": "staleness: a stray tag, or a second ref named main",
    "staleness-rollback-hold": "rolled back, awaiting fix-forward",
    "staleness-drill": "staleness drill: the issue path works",
}


def fetch_json(url: str, fetch: release_checks.Fetch | None = None) -> dict:
    """GET url through release_checks.http_fetch, the one HTTP door the release checks use, or through
    `fetch`, a reader shaped like it."""
    status, body = (fetch or release_checks.http_fetch)(url, {"Accept": "application/json"})
    if status != 200:
        raise release_checks.InfraError("npm", f"GET {url} answered {status}")
    return json.loads(body)


def read_packument() -> release_checks.Fetch:
    """Read the registry's package document once, and return a reader that answers every later read of
    it with that same answer. The publish times and the list of versions must come from one document:
    the registry serves it from a CDN cache, so two reads a moment apart can disagree for a few minutes
    after a publish, and a version in the second but not the first would read as published at an unknown
    time, which counts as older than a day."""
    answer = release_checks.http_fetch(REGISTRY_URL, {"Accept": "application/json"})

    def same_answer(url: str, headers: dict) -> tuple:
        if url != REGISTRY_URL:
            raise ValueError(f"only {REGISTRY_URL} was read, not {url}")
        return answer

    return same_answer


def publish_times(fetch: Callable[[str], dict] = fetch_json) -> dict[str, str]:
    """npm's publish time for every version, from the registry's full package document."""
    return fetch(REGISTRY_URL).get("time", {})


def age(now: dt.datetime, iso: str | None) -> dt.timedelta | None:
    return None if not iso else now - dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))


def result(rule: str, red: bool | None, detail: str = "", **extra) -> Result:
    return Result(rule=rule, label=LABEL, title=TITLES[rule], red=red, detail=detail, **extra)


def entry_and_rule_i(git: Git, repo_dir: str, now: dt.datetime, times: dict[str, str],
                     packument: release_checks.Fetch) -> list[Result]:
    # git.main() is the full ref: a bare "main" would resolve to a tag of that name before the branch.
    # A manifest on main that cannot be read (it does not parse, is nested too deeply, or names ai-tc twice) is
    # reported as this rule too, not left to crash the run: nothing can be imported from it either.
    try:
        present, unreadable = entry_at(git, git.rev_parse(git.main())) is not None, ""
    except Unreadable as problem:
        present, unreadable = False, str(problem)
    entry = result("staleness-entry", not present,
                   f"{unreadable}. Nothing is imported, and the expected version reads unknown, until a PR that "
                   "mends it merges." if unreadable else
                   "main's `.claude-plugin/marketplace.json` has no ai-tc entry. Nothing is imported, and the "
                   "expected version reads unknown, until a restore PR merges.")
    if not present:
        return [entry, result("staleness-i", None), result("staleness-i-refused", None),
                result("staleness-i-no-verdict", None)]
    pinned = set(release_checks.pinned_versions(repo_dir))
    highest = max(pinned, key=vkey)
    stale, refused, unverified = [], [], []
    # `packument` answers with the one document `times` came from (read_packument).
    for version in release_checks.npm_candidates(pinned, fetch=packument):
        on_npm = age(now, times.get(version))
        published = times.get(version, "at an unknown time")
        try:
            release_checks.verify_release(version)
        except release_checks.InfraError as error:
            # No verdict: the failure is not the release's. The full error goes to the run log; the issue names
            # only the check, because npm's own error output carries a log path with a timestamp, which would
            # make every hourly run a changed detail and so a new comment.
            print(f"::warning::no verdict on {version}: {describe(error)}")
            if on_npm is None or on_npm > HOUR:
                unverified.append(f"- `{version}` (published {published}): the `{error.check}` check did not finish")
            continue
        except release_checks.ReleaseCheckError as error:
            # Same rule as above: the full reason goes to the run log and the issue names only the check. A
            # reason can carry a value that moves without the release changing (a commit-on-main refusal names
            # ai-tc's current main head), and the router comments on the issue whenever its text changes.
            print(f"::warning::refused {version}: {describe(error)}")
            if on_npm is None or on_npm > HOUR:
                refused.append(f"- `{version}` (published {published}): the `{error.check}` check refused it")
            continue
        if on_npm is None or on_npm > DAY:
            stale.append(f"- `{version}`, published {published}")
    # A version with no verdict that has been on npm for over an hour, or whose publish time is unknown, might be
    # the very one these two rules name, or the one that clears them, so while one exists they can go red from
    # the versions that did finish, but they cannot be cleared. A younger one is not in `unverified`: neither
    # rule can name it yet (they need more than an hour and more than a day).
    undecided = bool(unverified)
    return [entry,
            result("staleness-i", True if stale else (None if undecided else False),
                   f"npm has releases above `{highest}`, the highest version `main` or any `fleet-v` tag pins, that "
                   "pass the importer's checks, for more than 24 hours:\n" + "\n".join(stale)
                   + "\n\nThe importer runs every 15 minutes: look for an open or closed pin PR, or a failing "
                   "import-plugin-release run."),
            result("staleness-i-refused", True if refused else (None if undecided else False),
                   f"npm has versions above `{highest}` that the importer refuses:\n" + "\n".join(refused)
                   + "\n\nThis workflow's run log holds the full reason for each. A version published from a "
                   "branch can never pass (its signing certificate names a branch, not the version's tag). If npm "
                   "`latest` names one, the runbook's dist-tag step moves it back."),
            result("staleness-i-no-verdict", bool(unverified),
                   f"The release checks could not finish on npm versions above `{highest}`: a registry, network, "
                   "npm or GitHub API failure, which is no verdict on the release:\n" + "\n".join(unverified)
                   + "\n\nThe unpinned-release and refused-version rules can still open an issue from the "
                   "versions that did finish, but they cannot close one until every version that has been on npm "
                   "for over an hour, or whose publish time is unknown, has a verdict. A younger version is not "
                   "listed: neither rule can name it yet. The check is repeated every hour, and this workflow's "
                   "run log holds the full error.")]


def rule_ii(gh: GitHub, now: dt.datetime) -> Result:
    old = [p for p in list_pulls(gh, "open")
           if p["head"].startswith("bot/") and (age(now, p["created_at"]) or dt.timedelta(0)) > DAY]
    return result("staleness-ii", bool(old),
                  "Open for more than 24 hours:\n"
                  + "\n".join(f"- #{p['number']} `{p['head']}`, opened {p['created_at']}" for p in old)
                  + "\n\nOne code-owner approval merges a bot PR; a rollback PR waiting this long is an incident.")


def rule_iii(git: Git, frozen: list[dict], now: dt.datetime) -> Result:
    last = max(frozen, key=lambda tag: int(tag["tag"][len("fleet-v"):]))
    changed, unreadable = pin_changes(git, last["commit"])
    for why in unreadable.values():
        # A commit already on main whose manifest cannot be read is no pin change, and this rule goes on past it:
        # stopping would fail every run for good. The full reason goes to the run log only.
        print(f"::warning::{why}. It is not counted as a pin change.")
    missing = []
    for sha in changed:
        committed = dt.datetime.fromtimestamp(git.commit_time(sha), dt.timezone.utc)
        if now - committed > HOUR:
            missing.append(f"- `{sha}` (ai-tc {version_at(git, sha)}, committed {committed:%Y-%m-%dT%H:%M:%SZ})")
    return result("staleness-iii", bool(missing),
                  f"Pin changes on main after {last['tag']} with no fleet-v tag for more than an hour:\n"
                  + "\n".join(missing) + "\n\ntag-release tags them on its next run (it runs hourly too): dispatch it for "
                  "an immediate run, and read why its last run failed.")


def rule_iv(refs: list[str]) -> Result:
    names = [ref for ref in refs if not ref.endswith("^{}")]
    stray = [ref for ref in names if ref.startswith("refs/tags/") and not release_checks.FLEET_TAG.fullmatch(ref[len("refs/tags/"):])]
    found = sorted(set(stray + [ref for ref in names if ref in SHADOWS]))
    return result("staleness-iv", bool(found),
                  "Refs that must not exist:\n" + "\n".join(f"- `{ref}`" for ref in found)
                  + "\n\nSome Claude Code versions follow a tag named `main` instead of the branch. Deleting a "
                  "tag takes an org owner (a tag ruleset forbids it to everyone else): follow the runbook's "
                  "stray-tag step.")


def rollback_hold(git: Git) -> Result:
    tags = git.fleet_tags()
    latest = tags[-1]["tag"] if tags else None
    found = re.search(r"(?m)^rollback-from: (\S+)$", git.tag_message(latest)) if latest else None
    return result("staleness-rollback-hold", found is not None,
                  f"The latest tag, {latest}, is a rollback from {found.group(1) if found else '-'}. npm `latest` "
                  "may still name that version until the runbook's dist-tag step moves it. This notice stays "
                  "until a forward pin merges; rule (i) stays live for any newer version meanwhile.",
                  kind="notice", extra_labels=["rollback-hold"])


def evaluate(*, git: Git, gh: GitHub, repo_dir: str, frozen: list[dict], now: dt.datetime,
             times: dict[str, str], packument: release_checks.Fetch, remote_refs: list[str], drill: bool,
             actor: str) -> list[Result]:
    results = entry_and_rule_i(git, repo_dir, now, times, packument)
    results += [rule_ii(gh, now), rule_iii(git, frozen, now), rule_iv(remote_refs), rollback_hold(git),
                result("staleness-drill", drill,
                       f"A manual run with drill: true, by {actor}, to prove red reaches an issue. The next run "
                       "without drill closes this issue.")]
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="staleness: is the release chain stalled?")
    parser.add_argument("--repo-dir", default=".")
    parser.add_argument("--frozen", required=True)
    args = parser.parse_args(argv)
    env = os.environ
    # One budget for the whole run, cleared below however it ends. Every release-check request and npm call is
    # cut to what remains of it, so a run that cannot finish says "no verdict" itself before GitHub cancels the
    # job. The GitHub API reads each have their own 60 s timeout (ghapi) and are not cut to it.
    release_checks.start_budget(release_checks.BUDGET_STALENESS)
    try:
        git = Git(args.repo_dir)
        with open(args.frozen, encoding="utf-8") as handle:
            frozen = json.load(handle)
        packument = read_packument()
        results = evaluate(git=git, gh=GitHub(env.get("GH_TOKEN", ""), env["GITHUB_REPOSITORY"]),
                           repo_dir=args.repo_dir, frozen=frozen, now=dt.datetime.now(dt.timezone.utc),
                           times=publish_times(lambda url: fetch_json(url, packument)), packument=packument,
                           remote_refs=git.ls_remote("origin"), drill=env.get("DRILL") == "true",
                           actor=env.get("ACTOR", "unknown"))
    finally:
        release_checks.clear_budget()
    for item in results:
        print(f"{item.rule}: " + ("not evaluated" if item.red is None else "red" if item.red else "clear"))
    write_output("results", results_to_json(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
