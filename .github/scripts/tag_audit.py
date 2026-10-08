"""tag-audit's checks. tag-release runs tag-audit's ledger, ruleset and environment checks before it creates
anything (not its comparison with the last green run's snapshot of the tag objects); only tag-audit's own run
makes that comparison.

Detection, not prevention: the rulesets prevent, and this notices an edit to
one of them, a change to the deployment branches of the `marketplace-bot`
environment, a moved or deleted fleet-v tag, or a tag that should not exist.
release_checks.audit_tags holds the tag-ledger rules: the frozen list, the
fleet-v<N> name rule, and, for every tag after the frozen list, contiguous
numbering, its place on main's first-parent history, its message's version
and the merged bot PR it names. This script adds what audit_tags's inputs
cannot carry: the tag objects the last green run saw, the rulesets'
presence, enforcement, targets, rules and conditions, and that environment's
existence and deployment branches (the one place the release bot's key is
released, and only to a job running from main). Bypass lists, and where the
bot's secrets are stored, are visible only to admins; the probe and an
admin's read-back cover those.

A change to a tag since the last green run stays red until a reviewed pull
request re-freezes the tag list (`freeze`), which is how a person records
that it is explained. A tag in the list is exempt from the checks a new tag
gets, so `freeze` does not rewrite a row quietly: it prints every row it adds,
changes or drops, and it changes or drops a row already in the list only when
`--accept fleet-vN` names that tag (once for each). When the run is told there is no snapshot to compare
with (`--no-baseline`: none was ever kept, it expired or it was deleted), the
comparison is replaced by a stricter rule: the frozen list must record every
fleet-v tag that exists, so the baseline is re-set in a reviewed pull request
rather than by the passage of time. That rule sees only tags that exist. A tag
cut after the frozen list and deleted since the lost snapshot is not seen by
this audit: staleness reports its pin change as untagged once it has stood for
an hour, and tag-release cuts the tag again on its next run, but neither says
that a tag was deleted. A `--previous` file that is not there is red, and a
run given neither flag (tag-release's) applies neither rule.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import NamedTuple

import release_checks
from ghapi import GitHub, GitHubError
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
# The environment the release bot's key is stored in; import-plugin-release.yml's open-pr job enters it by
# this name (a test reads the workflow). It must admit deployments from main alone: a custom list of
# branch rules, none for protected branches, holding the branch main and nothing else, no tag rule.
ENVIRONMENT = "marketplace-bot"
ENVIRONMENT_POLICY = {"protected_branches": False, "custom_branch_policies": True}
ENVIRONMENT_RULES = [{"name": "main", "type": "branch"}]
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
        # GitHub omits the parameters when the flag is false (its default); only a flag that is not false is a problem.
        if rule.get("type") == "update" and (rule.get("parameters") or {}).get("update_allows_fetch_and_merge", False) is not False:
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


def check_environment(gh: GitHub) -> list[str]:
    """What is wrong with the `marketplace-bot` environment's deployment branches, from GitHub's own answer.
    An environment that does not exist (404) is a problem; any other failure to read it is an error, never
    a problem, so a token that cannot read it fails the run instead of reporting drift that did not happen.
    The rule list is read only when the environment says it has custom rules: GitHub answers 404 for the
    list of an environment that has none. Not checked here: where the secrets are stored."""
    path = gh.repo_path(f"environments/{ENVIRONMENT}")
    try:
        environment = gh.get(path)
    except GitHubError as error:
        if error.status == 404:
            return [f"the {ENVIRONMENT} environment does not exist"]
        raise
    policy = environment.get("deployment_branch_policy")
    if policy != ENVIRONMENT_POLICY:
        return [f"the {ENVIRONMENT} environment's deployment_branch_policy is {policy!r}, "
                f"not {ENVIRONMENT_POLICY!r}"]
    listed = gh.get(f"{path}/deployment-branch-policies", params={"per_page": 100})
    rules = sorted(({"name": rule.get("name"), "type": rule.get("type")} for rule in listed.get("branch_policies") or []),
                   key=lambda rule: (str(rule["name"]), str(rule["type"])))
    if rules != ENVIRONMENT_RULES or listed.get("total_count") != len(ENVIRONMENT_RULES):
        return [f"the {ENVIRONMENT} environment's deployment branch rules are {rules!r} "
                f"(total_count {listed.get('total_count')!r}), not {ENVIRONMENT_RULES!r}"]
    return []


def snapshot(git: Git) -> list[dict]:
    return [{"tag": tag["tag"], "object": tag["object"], "commit": tag["commit"]} for tag in git.fleet_tags()]


def freeze_text(git: Git) -> str:
    """The frozen list: every fleet-v tag as it stands now, which is what a freeze writes. The committed
    list records the tags as of the last reviewed freeze; a reviewed re-freeze is how a changed tag is
    accepted and the baseline is reset."""
    lightweight = [tag["tag"] for tag in git.fleet_tags() if tag["object"] == tag["commit"]]
    if lightweight:
        raise SystemExit(f"refusing to freeze lightweight fleet tags: {', '.join(lightweight)}")
    return release_checks.dump_json(snapshot(git))


def _tag_number(name: str) -> int:
    return int(name[len("fleet-v"):])


def fleet_tag_name(value: str) -> str:
    """An --accept value: the name of a fleet-v tag."""
    if not release_checks.FLEET_TAG.fullmatch(value):
        raise argparse.ArgumentTypeError(f"{value!r} is not a fleet-v<N> tag name")
    return value


def read_frozen_rows(path: str) -> list[dict]:
    """The rows the file holds now, or none when there is no such file (the first freeze). A file that is
    there but cannot be read, or that names a tag twice, is refused: what a freeze would change in it could
    not be told."""
    if not os.path.exists(path):
        return []
    problems: list[str] = []
    rows = release_checks._tag_rows(path, "frozen tag list", problems)
    if rows is None:
        raise SystemExit(f"refusing to freeze over {path}: {problems[0]}. Fix the file by hand, or delete it to "
                         "start the list again (every tag then shows as added).")
    names = [row["tag"] for row in rows]
    repeated = sorted({name for name in names if names.count(name) > 1}, key=_tag_number)
    if repeated:
        raise SystemExit(f"refusing to freeze over {path}: it names {', '.join(repeated)} more than once, so what "
                         "a freeze would change in it could not be told. Fix the file by hand.")
    return rows


class RowChange(NamedTuple):
    tag: str
    kind: str  # "added", "changed" or "removed"
    text: str


def row_changes(existing: list[dict], current: list[dict]) -> list[RowChange]:
    """Every row a freeze would add, change or drop, in tag order. A row that stays as it is is left out."""
    before = {row["tag"]: row for row in existing}
    after = {row["tag"]: row for row in current}
    changes = []
    for name in sorted({*before, *after}, key=_tag_number):
        old, new = before.get(name), after.get(name)
        if old == new:
            continue
        if old is None:
            changes.append(RowChange(name, "added", f"{name} added: tag object {new['object']}, commit {new['commit']}"))
        elif new is None:
            changes.append(RowChange(name, "removed", f"{name} removed: the list holds it (tag object {old['object']}, "
                                                      f"commit {old['commit']}) and the tag no longer exists"))
        else:
            changes.append(RowChange(name, "changed", f"{name} changed: tag object {old['object']} -> {new['object']}, "
                                                      f"commit {old['commit']} -> {new['commit']}"))
    return changes


def refreeze(git: Git, path: str, accept: list[str]) -> tuple[str, list[str]]:
    """The new frozen list for `path`, and the lines that say what it changes. A tag in the list is exempt
    from the checks a new tag gets, so a row already there is not rewritten unless `accept` names its tag: a
    re-freeze that also carries a tag that moved would otherwise bless the move unread. `accept` may name only
    a tag whose row changes, so an accept left over from an earlier freeze approves nothing. Adding a row for
    a tag the list does not hold needs no accept; it is printed all the same. A refusal raises SystemExit
    carrying the lines and the reason, and the caller writes nothing."""
    text = freeze_text(git)
    changes = row_changes(read_frozen_rows(path), json.loads(text))
    lines = [change.text for change in changes] or ["no row changes"]
    touched = [change.tag for change in changes if change.kind != "added"]
    unnamed = [name for name in touched if name not in accept]
    unused = [name for name in dict.fromkeys(accept) if name not in touched]
    reasons = []
    if unnamed:
        flags = " ".join(f"--accept {name}" for name in unnamed)
        reasons.append(f"it would change or drop the row of {', '.join(unnamed)}; once each is explained, name it "
                       f"({flags})")
    if unused:
        reasons.append(f"--accept names {', '.join(unused)}, whose row does not change")
    if reasons:
        raise SystemExit("\n".join([*lines, f"refusing to freeze: {'; '.join(reasons)}. Nothing was written."]))
    return text, lines


REFREEZE ="if this change is explained, re-freeze it in a reviewed pull request (`tag_audit.py freeze`)"


def compare_previous(previous: list[dict], current: list[dict], frozen: list[dict] | None = None) -> list[str]:
    """What changed since the last green run's snapshot. A change a reviewed pull request re-froze is
    accepted: the committed list is where a person records that a tag's new state is explained. Only an
    exact match counts, so a tag that moved again after the re-freeze is still named, and a deleted tag
    is never accepted (the list has no row that says "gone"): it has to be put back and then re-frozen.
    `frozen` is None when the list could not be read, which accepts nothing."""
    now = {tag["tag"]: tag for tag in current}
    recorded = {(row["tag"], row["object"], row["commit"]) for row in frozen or []}
    problems = []
    for tag in previous:
        seen = now.get(tag["tag"])
        if seen is None:
            problems.append(f"{tag['tag']} (tag object {tag['object']}) existed at the last green run and is gone; "
                            f"re-create it at commit {tag['commit']}, then {REFREEZE}")
        elif (seen["object"], seen["commit"]) != (tag["object"], tag["commit"]):
            if (tag["tag"], seen["object"], seen["commit"]) in recorded:
                continue
            problems.append(f"{tag['tag']} moved since the last green run: tag object {tag['object']} -> "
                            f"{seen['object']}, commit {tag['commit']} -> {seen['commit']}; {REFREEZE}")
    return problems


def uncovered(current: list[dict], frozen: list[dict] | None) -> list[str]:
    """The stand-in for the comparison when there is no snapshot to compare with: every fleet-v tag must
    have a row in the frozen list. `frozen` None means the list could not be read; the ledger check already
    reports that, so nothing is added here."""
    if frozen is None:
        return []
    recorded = {row["tag"] for row in frozen}
    missing = [tag["tag"] for tag in current if tag["tag"] not in recorded]
    if not missing:
        return []
    return [f"no snapshot from an earlier green run to compare against, and the frozen list does not record "
            f"{', '.join(missing)}; re-freeze every fleet-v tag in a reviewed pull request to set a new baseline"]


def run_check(git: Git, gh: GitHub, frozen: str, previous: list[dict] | None, *,
              no_baseline: bool = False) -> list[str]:
    """Every problem: the ledger's, the rulesets', the bot environment's, and then the snapshot comparison's.
    `previous` is the snapshot an earlier green run kept. `no_baseline` says the caller has none to give
    (the workflow found none was kept, it expired or it was deleted): the frozen list then has to cover every
    tag. A caller that gives neither, as tag-release does not, gets neither the comparison nor the coverage
    rule, and still gets the rest: it runs in the same environment, so it refuses on drift in it too."""
    # The rulesets are checked once, by check_rulesets below (it adds exactly-one-per-name and
    # the fetch-and-merge rule); release_checks.audit_tags would otherwise check them a second
    # time and file every ruleset problem twice. test_the_configured_rulesets_pass pins RULESETS
    # to release_checks.EXPECTED_RULESETS, which an external vendored copy of the audit also runs.
    problems = [f"tag ledger: {problem}"
                for problem in release_checks.audit_tags(git.repo_dir, frozen, check_rulesets=False)]
    problems += check_rulesets(gh)
    problems += check_environment(gh)
    if previous is not None or no_baseline:
        # An unreadable list is already a ledger problem above, and accepts nothing here.
        rows = release_checks._tag_rows(frozen, "frozen tag list", [])
        if previous is not None:
            problems += compare_previous(previous, snapshot(git), rows)
        else:
            problems += uncovered(snapshot(git), rows)
    return problems


def as_result(problems: list[str]) -> Result:
    return Result(rule="tag-audit", label="tag-audit",
                  title="tag-audit: the fleet-v tag ledger, the marketplace rulesets or the release bot's environment changed", red=bool(problems),
                  detail="\n".join(f"- {problem}" for problem in problems) if problems else "Every tag-audit check passes.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="tag-audit's checks, and the frozen tag list")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("--repo-dir", default=".")
    check.add_argument("--frozen", required=True)
    baseline = check.add_mutually_exclusive_group()
    baseline.add_argument("--previous", help="the snapshot an earlier green run kept; the run is red if the file "
                                              "is not there")
    baseline.add_argument("--no-baseline", action="store_true",
                          help="there is no earlier snapshot (none was kept, it expired or it was deleted): the "
                               "frozen list has to record every fleet-v tag")
    check.add_argument("--snapshot")
    check.add_argument("--results", action="store_true", help="write the outputs results and red, and exit 0")
    freeze = sub.add_parser("freeze")
    freeze.add_argument("--repo-dir", default=".")
    freeze.add_argument("--out", required=True)
    freeze.add_argument("--accept", action="append", default=[], type=fleet_tag_name, metavar="fleet-vN",
                        help="let the freeze change or drop the row this tag already has in the list; give it once "
                             "for each such tag")
    args = parser.parse_args(argv)
    git = Git(args.repo_dir)
    if args.command == "freeze":
        text, lines = refreeze(git, args.out, args.accept)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        for line in lines:
            print(line)
        print(f"froze {len(git.fleet_tags())} fleet-v tags into {args.out}")
        return 0
    previous, absent = None, []
    if args.previous is not None:
        if os.path.exists(args.previous):
            with open(args.previous, encoding="utf-8") as handle:
                previous = json.load(handle)
        else:
            # The workflow says it downloaded a snapshot, so a file that is not there is a break in the wiring
            # between its steps, and reading it as "no baseline" would leave the comparison off for good.
            absent = [f"the snapshot the workflow downloaded ({args.previous}) is missing, so this run could not "
                      "compare the tags with the last green run's"]
    gh = GitHub(os.environ.get("GH_TOKEN", ""), os.environ["GITHUB_REPOSITORY"])
    problems = absent + run_check(git, gh, args.frozen, previous, no_baseline=args.no_baseline)
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
