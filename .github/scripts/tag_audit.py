"""tag-audit's checks. tag-release runs tag-audit's ledger and ruleset checks before it creates anything (not its
comparison with the last green run's snapshot of the tag objects); only tag-audit's own run makes that comparison.

Detection, not prevention: the rulesets prevent, and this notices an edit to
one of them, a moved or deleted fleet-v tag, or a tag that should not exist.
release_checks.audit_tags holds the tag-ledger rules: the frozen list, the
fleet-v<N> name rule, and, for every tag after the frozen list, contiguous
numbering, its place on main's first-parent history, its message's version
and the merged bot PR it names. This script adds what audit_tags's inputs
cannot carry: the tag objects the last green run saw, and the rulesets'
presence, enforcement, targets, rules and conditions. Bypass lists are
visible only to admins; the probe and an admin's read-back cover those.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import release_checks
from ghapi import GitHub
from gitrepo import Git
from import_release import write_output
from issue_router import Result, results_to_json

# Each ruleset's target, rule types and accepted ref_name include and exclude lists, taken from
# release_checks' tables (the ones release_checks.audit_rulesets checks), never restated here.
RULESETS: dict[str, dict] = {
    name: {"target": target, "rules": rules, "include": release_checks.EXPECTED_REF_PATTERNS[name][0],
           "exclude": [release_checks.EXPECTED_REF_PATTERNS[name][1]]}
    for name, (target, rules) in release_checks.EXPECTED_RULESETS.items()
}
MAIN_REVIEW = {"required_approving_review_count": 1, "require_code_owner_review": True,
               "dismiss_stale_reviews_on_push": True, "require_last_push_approval": True,
               "allowed_merge_methods": ["squash"]}


def ruleset_problems(name: str, want: dict, ruleset: dict) -> list[str]:
    problems = []
    if ruleset.get("enforcement") != "active":
        problems.append(f"ruleset {name!r} is {ruleset.get('enforcement')!r}, not active")
    if ruleset.get("target") != want["target"]:
        problems.append(f"ruleset {name!r} targets {ruleset.get('target')!r}, not {want['target']!r}")
    rules = ruleset.get("rules") or []
    missing = want["rules"] - {rule.get("type") for rule in rules}
    if missing:
        problems.append(f"ruleset {name!r} lacks the rules {sorted(missing)}")
    for rule in rules:
        if rule.get("type") == "update" and (rule.get("parameters") or {}).get("update_allows_fetch_and_merge") is not False:
            problems.append(f"ruleset {name!r}: its update rule allows fetch-and-merge")
    ref_name = (ruleset.get("conditions") or {}).get("ref_name")
    if not isinstance(ref_name, dict):
        problems.append(f"ruleset {name!r}: its ref conditions are not readable")
    else:
        for key in ("include", "exclude"):
            got = sorted(ref_name.get(key) or [])
            if got not in [sorted(option) for option in want[key]]:
                problems.append(f"ruleset {name!r}: {key} is {got}, expected one of {want[key]}")
    if name == "main":
        problems += main_problems(rules)
    return problems


def main_problems(rules: list[dict]) -> list[str]:
    problems = []
    review = next(((rule.get("parameters") or {}) for rule in rules if rule.get("type") == "pull_request"), {})
    for key, want in MAIN_REVIEW.items():
        got = review.get(key)
        if key == "allowed_merge_methods":
            got = sorted(got or [])
        if got != want:
            problems.append(f"ruleset 'main': pull_request {key} is {got!r}, expected {want!r}")
    checks = next(((rule.get("parameters") or {}).get("required_status_checks", [])
                   for rule in rules if rule.get("type") == "required_status_checks"), [])
    if not any(check.get("context") == "validate" and check.get("integration_id") == release_checks.GITHUB_ACTIONS_APP_ID
               for check in checks):
        problems.append("ruleset 'main': the required check `validate` pinned to the GitHub Actions app is missing")
    return problems


def check_rulesets(gh: GitHub) -> list[str]:
    listed = gh.get(gh.repo_path("rulesets"), params={"includes_parents": "false", "per_page": 100})
    problems = []
    for name, want in RULESETS.items():
        found = [summary for summary in listed if summary.get("name") == name]
        if len(found) != 1:
            problems.append(f"ruleset {name!r}: expected exactly one, found {len(found)}")
            continue
        problems += ruleset_problems(name, want, gh.get(gh.repo_path(f"rulesets/{found[0]['id']}")))
    return problems


def snapshot(git: Git) -> list[dict]:
    return [{"tag": tag["tag"], "object": tag["object"], "commit": tag["commit"]} for tag in git.fleet_tags()]


def freeze_text(git: Git) -> str:
    """The frozen list: every fleet-v tag that exists when tag-audit is activated."""
    lightweight = [tag["tag"] for tag in git.fleet_tags() if tag["object"] == tag["commit"]]
    if lightweight:
        raise SystemExit(f"refusing to freeze lightweight fleet tags: {', '.join(lightweight)}")
    return release_checks.dump_json(snapshot(git))


def compare_previous(previous: list[dict], current: list[dict]) -> list[str]:
    now = {tag["tag"]: tag for tag in current}
    problems = []
    for tag in previous:
        seen = now.get(tag["tag"])
        if seen is None:
            problems.append(f"{tag['tag']} (tag object {tag['object']}) existed at the last green run and is gone")
        elif (seen["object"], seen["commit"]) != (tag["object"], tag["commit"]):
            problems.append(f"{tag['tag']} moved since the last green run: tag object {tag['object']} -> "
                            f"{seen['object']}, commit {tag['commit']} -> {seen['commit']}")
    return problems


def run_check(git: Git, gh: GitHub, frozen: str, previous: list[dict] | None) -> list[str]:
    # The rulesets are checked once, by check_rulesets below (it adds exactly-one-per-name and
    # the fetch-and-merge rule); release_checks.audit_tags would otherwise check them a second
    # time and file every ruleset problem twice. test_the_configured_rulesets_pass pins RULESETS
    # to release_checks.EXPECTED_RULESETS, which an external vendored copy of the audit also runs.
    problems = [f"tag ledger: {problem}"
                for problem in release_checks.audit_tags(git.repo_dir, frozen, check_rulesets=False)]
    problems += check_rulesets(gh)
    if previous is not None:
        problems += compare_previous(previous, snapshot(git))
    return problems


def as_result(problems: list[str]) -> Result:
    return Result(rule="tag-audit", label="tag-audit",
                  title="tag-audit: the fleet-v tag ledger or the marketplace rulesets changed", red=bool(problems),
                  detail="\n".join(f"- {problem}" for problem in problems) if problems else "Every tag-audit check passes.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="tag-audit's checks, and the frozen tag list")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("--repo-dir", default=".")
    check.add_argument("--frozen", required=True)
    check.add_argument("--previous")
    check.add_argument("--snapshot")
    check.add_argument("--results", action="store_true", help="write the outputs results and red, and exit 0")
    freeze = sub.add_parser("freeze")
    freeze.add_argument("--repo-dir", default=".")
    freeze.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    git = Git(args.repo_dir)
    if args.command == "freeze":
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(freeze_text(git))
        print(f"froze {len(git.fleet_tags())} fleet-v tags into {args.out}")
        return 0
    previous = None
    if args.previous and os.path.exists(args.previous):
        with open(args.previous, encoding="utf-8") as handle:
            previous = json.load(handle)
    elif args.previous:
        print("::notice::no snapshot from an earlier green tag-audit run; the frozen list and the ledger rules still apply")
    gh = GitHub(os.environ.get("GH_TOKEN", ""), os.environ["GITHUB_REPOSITORY"])
    problems = run_check(git, gh, args.frozen, previous)
    if args.snapshot:
        os.makedirs(os.path.dirname(args.snapshot) or ".", exist_ok=True)
        with open(args.snapshot, "w", encoding="utf-8") as handle:
            handle.write(release_checks.dump_json(snapshot(git)))
    for problem in problems:
        print(f"::error::{problem}")
    if args.results:
        write_output("results", results_to_json([as_result(problems)]))
        write_output("red", "true" if problems else "false")
        return 0
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
