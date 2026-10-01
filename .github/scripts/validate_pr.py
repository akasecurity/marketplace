#!/usr/bin/env python3
"""validate.yml's rules for every PR into this repository.

This runs from the BASE branch's copy (pull_request_target). It reads the PR's files as
data: `git show <sha>:<path>` of the head commit, never a checkout, and it never imports
or executes anything the PR contains.

It is a correctness check on the automated path, not a security boundary: code-owner
review of every change is the control.

Exit 0 = every rule holds, 1 = a rule failed, 2 = no verdict (git, network or API).
"""

from __future__ import annotations

import dataclasses
import functools
import json
import os
import re
import subprocess
import sys

import release_checks as rc

MANIFESTS = (rc.MANIFEST, ".agents/plugins/marketplace.json", "plugins.json")
WATCHED = (*MANIFESTS, rc.SAFETY_FILE)
MODE_LABEL = {"advance": "ADVANCE", "rollback": "ROLLBACK", "remove": "REMOVE", "restore": "RESTORE"}
REPO_NAME = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+")


@dataclasses.dataclass(frozen=True)
class PullRequest:
    number: int
    author: str
    author_type: str
    head_repo: str
    base_repo: str
    head_ref: str
    commits: tuple  # ({"sha", "author", "committer", "verified"}, ...): GitHub logins or None, and GitHub's signature verdict


@dataclasses.dataclass
class Report:
    failures: list = dataclasses.field(default_factory=list)
    notes: list = dataclasses.field(default_factory=list)
    rows: list = dataclasses.field(default_factory=list)
    infra: str = ""

    def fail(self, message: str) -> None:
        self.failures.append(message)

    def note(self, message: str) -> None:
        self.notes.append(message)

    def row(self, key: str, value: str) -> None:
        self.rows.append((key, value))

    @property
    def exit_code(self) -> int:
        if self.infra:
            return 2
        return 1 if self.failures else 0


def _code(value) -> str:
    """Inline code for the summary: PR-controlled text cannot break out of it."""
    text = " ".join(str(value).replace("`", "'").split())
    return f"`{text[:200]}`"


def _frozen_top_level(manifest: dict) -> dict:
    """The manifest without plugins, and without the three keys a PR may change."""
    top = {k: v for k, v in manifest.items() if k not in ("plugins", "description")}
    if isinstance(top.get("metadata"), dict):
        top["metadata"] = {k: v for k, v in top["metadata"].items() if k not in ("description", "version")}
    return top


def _names_ai_tc(value) -> bool:
    if value == rc.ENTRY_NAME:
        return True
    if isinstance(value, dict):
        return any(_names_ai_tc(k) or _names_ai_tc(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_names_ai_tc(v) for v in value)
    return False


def parse_manifests(files: dict, report: Report, *, label: str) -> dict:
    """Parse every manifest, reporting each problem. Returns path -> document."""
    docs = {}
    for path in MANIFESTS:
        text = files.get(path)
        if text is None:
            report.fail(f"{path} is missing at {label}")
            continue
        try:
            doc = rc.parse_json(text)
        except ValueError as exc:
            report.fail(f"{path} does not parse at {label} (duplicate keys and NaN are refused): {exc}")
            continue
        plugins = doc.get("plugins") if isinstance(doc, dict) else None
        if not isinstance(plugins, list) or not all(isinstance(p, dict) and isinstance(p.get("name"), str) for p in plugins):
            report.fail(f"{path} at {label}: plugins must be a list of objects that each have a string name")
            continue
        names = [p["name"] for p in plugins]
        repeated = sorted({n for n in names if names.count(n) > 1})
        if repeated:
            report.fail(f"{path} at {label}: plugin names must be unique; repeated: {', '.join(repeated)}")
        docs[path] = doc
    return docs


def every_pr_rules(base_doc: dict, head_doc: dict, report: Report):
    """The rules for every PR. Returns (base_entry, head_entry, mode), or None when the
    ai-tc entry is ambiguous, since then nothing further can be judged."""
    if _names_ai_tc(head_doc.get("renames")):
        report.fail("a renames key or value names ai-tc: the plugin id every managed Mac enables is never renamed")
    base_top, head_top = _frozen_top_level(base_doc), _frozen_top_level(head_doc)
    if base_top != head_top:
        changed = sorted(k for k in set(base_top) | set(head_top) if base_top.get(k) != head_top.get(k))
        report.fail(
            "top-level keys are frozen (only description, metadata.description and metadata.version "
            "may change); changed: " + ", ".join(changed)
        )
    try:
        base_entry = rc.find_ai_tc_entry(base_doc)
        head_entry = rc.find_ai_tc_entry(head_doc)
        mode = rc.diff_mode(base_doc, head_doc)
    except rc.ReleaseCheckError as exc:
        report.fail(f"{exc.check}: {exc.detail}")
        return None
    return base_entry, head_entry, mode


def _without(entry: dict, *keys: str) -> dict:
    return {k: v for k, v in entry.items() if k not in keys}


def safety_versions(text, report: Report, *, label: str):
    """The versions map of a rollback-safety.json text, or None (absent or malformed)."""
    if text is None:
        return None
    try:
        doc = rc.parse_json(text)
    except ValueError as exc:
        report.fail(f"{rc.SAFETY_FILE} does not parse at {label}: {exc}")
        return None
    problems = rc.safety_problems(doc)
    for problem in problems:
        report.fail(f"at {label}: {problem}")
    return None if problems else doc["versions"]


def bot_hint(pr: PullRequest, bot_login) -> str:
    if pr.author_type != "Bot":
        return ""
    if bot_login is None:
        return (
            " This PR's author is a bot, but no bot identity is configured "
            "(release_checks.BOT_LOGIN is None), so it is judged as a human PR."
        )
    return f" Its author {pr.author} is not the marketplace bot App ({bot_login})."


def _safety_edit_notes(base, head, changed, report: Report, *, pinned) -> None:
    """A person may correct or remove an entry in a reviewed PR, and validate calls each change
    out. Adding one is different: the file holds one entry per pinned version, computed by the
    pin PR that pins it, so an entry for a version nothing pins is typed ahead of its release."""
    if rc.SAFETY_FILE not in changed:
        return
    if head is None:
        report.fail(f"{rc.SAFETY_FILE} must stay, and stay well formed: without it no rollback floor can be read")
        return
    base = base or {}
    for version in sorted(set(base) | set(head), key=rc.vkey):
        before, after = base.get(version), head.get(version)
        if before == after:
            continue
        if before is None and version not in pinned:
            report.fail(
                f"{rc.SAFETY_FILE} gains {version}, which nothing pins: an entry is computed by the "
                "pin PR that pins it, never typed ahead of it"
            )
            continue
        old = before["classification"] if before else "absent"
        new = after["classification"] if after else "removed"
        lowers = "LOWERS THE ROLLBACK FLOOR: " if new == "additive" and old != "additive" else ""
        report.note(
            f"{lowers}HUMAN EDIT of {rc.SAFETY_FILE} {version}: {old} -> {new}; "
            "the approving code owner owns this classification"
        )


def human_rules(entries, base_safety, head_safety, changed, report: Report, *, bot_hint: str = "", pinned=frozenset()) -> None:
    """A human PR may change the ai-tc entry's description and nothing else of it. `pinned`
    is every version main or a fleet-v tag pins; with none given, no added entry is accepted."""
    base_entry, head_entry, mode = entries
    if mode == "none":
        report.row("Mode", "HUMAN PR, ai-tc entry unchanged")
    elif (
        mode == "human"
        and base_entry is not None
        and head_entry is not None
        and _without(base_entry, "description") == _without(head_entry, "description")
    ):
        report.row("Mode", "HUMAN PR, ai-tc description edit")
        report.note("ai-tc description changed: change all four files (AGENTS.md, 'Four files, one set of facts')")
    else:
        report.row("Mode", f"HUMAN PR, refused ({mode})")
        report.fail(
            "a human PR may change only the ai-tc entry's description: not its name, source, "
            "version, metadata or any other key, and it may not remove or add the entry. The pin "
            "moves only through the importer's bot PRs; a package or name change is an org "
            "owner's break-glass merge." + bot_hint
        )
    _safety_edit_notes(base_safety, head_safety, changed, report, pinned=pinned)
    touched = [p for p in changed if p.startswith(".github/")]
    if touched:
        report.note("touches automation or ownership, review the diff line by line: " + ", ".join(touched))


REF_PATTERNS = {
    "advance": "bot/pin-ai-tc-{head}",
    "rollback": "bot/rollback-ai-tc-{base}-to-{head}",
    "restore": "bot/restore-ai-tc-{head}",
}
REMOVE_REF = re.compile(r"bot/remove-ai-tc-[0-9]+")
# The bot-branches ruleset lets only the bot App create, update or delete these refs.
BOT_REF_PREFIX = "bot/"
# GitHub's own committer login. The importer makes every bot commit through the Git Data API
# with no author or committer, which GitHub records with the App as author and web-flow as
# committer, and signs. That signed shape is the only bot commit there is.
WEB_FLOW = "web-flow"


def commit_problems(commit: dict, bot_login: str) -> list:
    """Why one PR commit is not one GitHub created for the bot App and signed, or [].

    A login is only GitHub's match of the commit's email, which anyone can write into a
    commit, so no name is trusted alone. Every commit must also carry GitHub's verified
    signature, even one that names the App as both author and committer: anyone who can push
    to the branch can write those two lines. The signature narrows that gap, but it does not
    replace the bot-branches ruleset that lets only the App push the bot/ refs, and these
    checks sit beside that ruleset and the PR the App opened."""
    sha = str(commit.get("sha"))[:12]
    author, committer = commit.get("author"), commit.get("committer")
    signed = commit.get("verified") is True
    problems = []
    if author != bot_login:
        problems.append(f"commit {sha} is authored by {author}, not by {bot_login}")
    if committer == WEB_FLOW:
        if not signed:
            problems.append(f"commit {sha} is committed by {WEB_FLOW} without a verified signature")
    elif committer == bot_login:
        if not signed:
            problems.append(
                f"commit {sha} has no verified signature: a bot commit is one GitHub created for the App and signed"
            )
    else:
        problems.append(
            f"commit {sha} is committed by {committer}: a bot commit's committer is {bot_login} "
            f"or {WEB_FLOW}, with a verified signature"
        )
    return problems


def _floor_crossed(target, highest, tip_safety, report: Report, what: str, *, pinned=()) -> None:
    if tip_safety is None:
        report.fail(f"main's {rc.SAFETY_FILE} is missing or malformed, so no rollback floor can be read; refusing")
        return
    floor = rc.rollback_floor({"versions": tip_safety}, target, highest, pinned=pinned)
    report.row("Rollback floor", _code(floor) if floor else "none crossed")
    if floor:
        report.fail(
            f"BELOW THE ROLLBACK FLOOR: {what} {floor}, which main's {rc.SAFETY_FILE} flags "
            "not rollback-safe. Only an org owner's break-glass merge lands this PR."
        )


def _recorded_entry_rules(head_v, recorded, pinned, report: Report, *, verify, classify) -> None:
    """A forward PR for a version the base already records. The recorded entry is recomputed,
    never taken on trust: an entry typed in by hand for a release nobody classified would
    otherwise stand as evidence the release is rollback-safe.

    The commit the entry runs up to is the release's attested commit, which cannot change, so
    a different one is wrong. A recorded class weaker than the computed one is wrong. A
    stronger one is kept (fail-safe). A different starting commit is only noted: the highest
    pinned version below a release moves legitimately after a re-import of a lower version."""
    try:
        expected = rc.safety_entry(head_v, pinned, verify=verify, classify=classify)
    except rc.InfraError:
        raise
    except rc.ReleaseCheckError as exc:
        report.fail(f"could not compute {head_v}'s store-migration entry ({exc.check}): {exc.detail}")
        return
    if recorded["to"] != expected["to"]:
        report.fail(
            f"{rc.SAFETY_FILE} records {head_v} up to commit {_code(recorded['to'])}, but {head_v}'s "
            f"attested commit is {_code(expected['to'])}: the entry was not computed for this release"
        )
    if recorded["classification"] == "additive" and expected["classification"] == "not-rollback-safe":
        report.fail(
            f"{rc.SAFETY_FILE} records {head_v} as additive, but validate computes not-rollback-safe "
            f"({', '.join(expected['migrations']) or 'none'}); a code owner corrects the entry in a "
            "reviewed PR before this pin can merge"
        )
    if recorded["from"] != expected["from"]:
        report.note(
            f"{rc.SAFETY_FILE} records {head_v} from commit {_code(recorded['from'])}, but the highest "
            f"pinned version below it is now at {_code(expected['from'])}; only the commit it runs up to "
            "and its class are checked"
        )
    report.row("Store migration", f"{recorded['classification']} (recorded; validate computes {expected['classification']})")


def _advance_rules(head_v, pinned, highest, base_safety, head_safety, report: Report, *, verify, classify) -> None:
    if highest is not None and rc.vkey(head_v) <= rc.vkey(highest):
        report.note(
            f"RE-IMPORT: {head_v} is not above {highest}, the highest version ever pinned. Only a "
            "manual import dispatch with reimport: true opens this PR."
        )
    base_safety = base_safety or {}
    if head_safety is None:
        report.fail(f"{rc.SAFETY_FILE} is missing or malformed at the PR head")
        return
    if head_v in base_safety:
        if head_safety != base_safety:
            report.fail(f"{rc.SAFETY_FILE} already records {head_v}; a forward PR for it must leave the file unchanged")
        _recorded_entry_rules(head_v, base_safety[head_v], pinned, report, verify=verify, classify=classify)
        return
    added = sorted(set(head_safety) - set(base_safety), key=rc.vkey)
    unchanged = all(head_safety.get(v) == e for v, e in base_safety.items())
    if added != [head_v] or not unchanged:
        report.fail(
            f"{rc.SAFETY_FILE} must gain exactly one entry, for {head_v}, and change nothing else "
            f"(added: {', '.join(added) or 'none'})"
        )
        return
    try:
        expected = rc.safety_entry(head_v, pinned, verify=verify, classify=classify)
    except rc.InfraError:
        raise
    except rc.ReleaseCheckError as exc:
        report.fail(f"could not compute {head_v}'s store-migration entry ({exc.check}): {exc.detail}")
        return
    if head_safety[head_v] != expected:
        report.fail(
            f"{rc.SAFETY_FILE} {head_v} is {json.dumps(head_safety[head_v])}, but validate computes {json.dumps(expected)}"
        )
    report.row("Store migration", f"{expected['classification']} ({', '.join(expected['migrations']) or 'none'})")


def bot_rules(pr: PullRequest, entries, pins, base_safety, head_safety, tip_safety, changed, report: Report, *, bot_login, verify, classify) -> None:
    """A bot PR passes only as exactly one importer mode, from the bot, verified end to end."""
    base_entry, head_entry, mode = entries
    base_v, head_v = rc.entry_version(base_entry), rc.entry_version(head_entry)
    report.row("Mode", f"{MODE_LABEL.get(mode, mode.upper())} (bot PR)")
    report.row("Pin", f"{_code(base_v or 'absent')} -> {_code(head_v or 'absent')}")
    if pr.author != bot_login or pr.author_type != "Bot":
        report.fail(f"the PR is opened by {pr.author} ({pr.author_type}), not by the bot App {bot_login}")
    if pr.head_repo != pr.base_repo:
        report.fail(f"a bot PR's head repository must be {pr.base_repo}, not {pr.head_repo or 'a deleted fork'}")
    if not pr.head_ref.startswith(BOT_REF_PREFIX):
        report.fail(
            f"head ref {_code(pr.head_ref)} is not under refs/heads/{BOT_REF_PREFIX}, the only branches "
            "the bot-branches ruleset lets the bot App, and no one else, push"
        )
    if not pr.commits:
        report.fail("the PR lists no commits")
    for commit in pr.commits:
        for problem in commit_problems(commit, bot_login):
            report.fail(problem)
    report.note("Who pushed each commit is enforced by the bot-branches ruleset; the API exposes no pusher.")
    if mode not in MODE_LABEL:
        report.fail(f"a bot PR must be exactly one importer mode's shape (advance, rollback, remove or restore); this diff is {mode!r}")
        return
    if mode == "remove":
        ref_ok = REMOVE_REF.fullmatch(pr.head_ref) is not None
    else:
        ref_ok = pr.head_ref == REF_PATTERNS[mode].format(base=base_v, head=head_v)
    if not ref_ok:
        report.fail(f"head ref {_code(pr.head_ref)} is not the {mode} branch for this diff")
    allowed = {rc.MANIFEST, rc.SAFETY_FILE} if mode == "advance" else {rc.MANIFEST}
    extra = sorted(set(changed) - allowed)
    if extra:
        report.fail(f"a bot {mode} PR may change only {', '.join(sorted(allowed))}; it also changes: {', '.join(extra)}")
    if mode == "remove":
        report.note("REMOVE: this marketplace stops serving ai-tc until a restore merges")
        return
    try:
        release = verify(head_v)
    except rc.InfraError:
        raise
    except rc.ReleaseCheckError as exc:
        report.fail(f"{head_v} fails the release checks ({exc.check}): {exc.detail}")
        return
    report.row("Integrity", _code(release.integrity))
    report.row("Attested commit", _code(release.git_commit))
    report.row("On ai-tc main", "yes")
    report.row("Release run", release.run_url)
    recorded = (head_entry.get("metadata") or {}).get("integrity")
    if recorded != release.integrity:
        report.fail(f"metadata.integrity {_code(recorded)} is not the integrity npmjs serves for {head_v} ({release.integrity})")
    pinned = {v for v in pins.values() if v}
    highest = max(pinned, key=rc.vkey) if pinned else None
    if mode in ("rollback", "restore") and rc.vkey(head_v) < rc.vkey("0.9.14"):
        report.note(
            f"OLDER THAN 0.9.14: if {head_v} cannot open a store a newer build migrated, it reports only a "
            "generic 'could not open the store' error, whose advice to move the store aside would set aside "
            "a store that is only newer. Tell developers not to follow that advice."
        )
    if mode == "advance":
        _advance_rules(head_v, pinned, highest, base_safety, head_safety, report, verify=verify, classify=classify)
    elif mode == "rollback":
        tag_pinned = {v for ref, v in pins.items() if ref != "main" and v}
        if head_v not in tag_pinned:
            report.fail(f"rollback target {head_v} is not a version any fleet-v tag has pinned")
        if highest is None:
            report.fail("nothing is pinned, so a rollback has nothing to roll back from")
        else:
            _floor_crossed(head_v, highest, tip_safety, report, f"{head_v} is below", pinned=pinned)
    else:
        report.note("RESTORE: the ai-tc entry returns in the fixed npm shape")
        if highest is not None and rc.vkey(head_v) < rc.vkey(highest):
            _floor_crossed(head_v, highest, tip_safety, report, f"restoring {head_v} crosses", pinned=pinned)


def evaluate(pr: PullRequest, base_files: dict, head_files: dict, changed, pins, tip_safety_text, *, bot_login, verify, classify) -> Report:
    """Every rule validate applies to one PR.

    The base files come from the PR's merge base. The tip safety text is main's
    rollback-safety.json, which alone decides the floor."""
    report = Report()
    head_docs = parse_manifests(head_files, report, label="the PR head")
    for path in (rc.MANIFEST, rc.SAFETY_FILE):
        text = head_files.get(path)
        try:
            written = rc.dump_json(rc.parse_json(text)) if text is not None else text
        except ValueError:
            continue  # a parse failure is reported on its own
        if written != text:
            report.fail(
                f"{path} at the PR head is not in the one writer's format (json.dumps with indent=2, "
                "ensure_ascii=False and one trailing newline); the importer refuses to rewrite such a file"
            )
    base_docs = parse_manifests(base_files, Report(), label="the base")
    if rc.MANIFEST not in base_docs:
        report.fail(f"{rc.MANIFEST} does not parse at the base, so nothing can be compared")
    if rc.MANIFEST not in head_docs or rc.MANIFEST not in base_docs:
        return report
    entries = every_pr_rules(base_docs[rc.MANIFEST], head_docs[rc.MANIFEST], report)
    base_safety = safety_versions(base_files.get(rc.SAFETY_FILE), Report(), label="the base")
    head_safety = safety_versions(head_files.get(rc.SAFETY_FILE), report, label="the PR head")
    tip_safety = safety_versions(tip_safety_text, Report(), label="main")
    if entries is None:
        return report
    if bot_login is not None and pr.author == bot_login and pr.author_type == "Bot":
        bot_rules(pr, entries, pins, base_safety, head_safety, tip_safety, changed, report, bot_login=bot_login, verify=verify, classify=classify)
    else:
        human_rules(
            entries, base_safety, head_safety, changed, report,
            bot_hint=bot_hint(pr, bot_login), pinned={v for v in pins.values() if v},
        )
    return report


def _line(text) -> str:
    return " ".join(str(text).split())


def _cell(text) -> str:
    return _line(text).replace("|", "/")


def render_summary(report: Report, number) -> str:
    verdict = "NO VERDICT" if report.infra else ("FAIL" if report.failures else "PASS")
    lines = [
        f"## validate: PR #{number}: {verdict}",
        "",
        "validate.yml from the base branch, run on pull_request_target. Before trusting a green "
        "result, open this check run and confirm it is that workflow: any GitHub Actions job "
        "named validate satisfies the required check.",
        "",
    ]
    if report.rows:
        lines += ["| Check | Value |", "| --- | --- |"]
        lines += [f"| {_cell(key)} | {_cell(value)} |" for key, value in report.rows]
        lines.append("")
    sections = (("No verdict", [report.infra] if report.infra else []), ("Failures", report.failures), ("Notes", report.notes))
    for title, items in sections:
        if items:
            lines += [f"### {title}", ""] + [f"- {_line(item)}" for item in items] + [""]
    return "\n".join(lines)


def _run_git(repo: str, *args: str) -> str:
    result = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise rc.InfraError("git", f"git {' '.join(args)} failed: {result.stderr.strip()[:300]}")
    return result.stdout


def read_at(repo: str, rev: str, path: str):
    """A file's text at a commit, as data; None when the commit does not have it."""
    probe = subprocess.run(["git", "-C", repo, "cat-file", "-e", f"{rev}:{path}"], capture_output=True)
    if probe.returncode != 0:
        return None
    shown = subprocess.run(["git", "-C", repo, "show", f"{rev}:{path}"], capture_output=True)
    if shown.returncode != 0:
        raise rc.InfraError("git", f"git show {rev}:{path} failed")
    try:
        return shown.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise rc.ReleaseCheckError("utf-8", f"{path} at {rev[:12]} is not UTF-8") from exc


def changed_files(repo: str, start: str, end: str) -> list:
    """The paths the PR's own diff touches, with both sides of a rename listed."""
    out = _run_git(repo, "diff", "--no-renames", "--name-only", "-z", start, end)
    return sorted(path for path in out.split(chr(0)) if path)


# GitHub lists at most this many commits of a pull request, however many pages are asked for.
COMMIT_LISTING_CAP = 250


def pr_commits(base_repo: str, number: int, *, fetch) -> list:
    """Each PR commit's author and committer logins (None where GitHub matched no account to
    the commit's email) and whether GitHub verified its signature. A listing that reaches
    GitHub's cap may be truncated, so it is no verdict rather than a partial answer."""
    commits = []
    for page in (1, 2, 3):
        url = f"https://api.github.com/repos/{base_repo}/pulls/{number}/commits?per_page=100&page={page}"
        status, body = fetch(url, {})
        if status != 200:
            raise rc.InfraError("api", f"GET {url} answered {status}")
        batch = json.loads(body)
        commits += [
            {
                "sha": c.get("sha"),
                "author": (c.get("author") or {}).get("login"),
                "committer": (c.get("committer") or {}).get("login"),
                "verified": ((c.get("commit") or {}).get("verification") or {}).get("verified") is True,
            }
            for c in batch
        ]
        if len(batch) < 100:
            break
    if len(commits) >= COMMIT_LISTING_CAP:
        raise rc.InfraError("api", f"PR #{number} lists {len(commits)} commits, GitHub's listing cap, so the list may be incomplete")
    return commits


def main(*, repo: str = ".", env=None, fetch=None, verify=None, classify=None) -> int:
    env = os.environ if env is None else env
    fetch = fetch or rc.http_fetch
    verify = verify or functools.lru_cache(maxsize=None)(rc.verify_release)
    classify = classify or rc.classify_migrations
    number = env.get("PR_NUMBER", "?")
    main_sha = None
    try:
        head_sha, base_repo = env.get("HEAD_SHA", ""), env.get("BASE_REPO", "")
        if not rc.SHA40.fullmatch(head_sha) or not REPO_NAME.fullmatch(base_repo) or not str(number).isdigit():
            raise rc.InfraError("input", "HEAD_SHA, BASE_REPO and PR_NUMBER must be a 40-hex sha, owner/name and a number")
        # The commit of main this run reads the pins and the rollback floor from, resolved once.
        main_sha = _run_git(repo, "rev-parse", "--verify", f"{rc.main_ref(repo)}^{{commit}}").strip()
        start = _run_git(repo, "merge-base", "HEAD", head_sha).strip()
        base = {path: read_at(repo, start, path) for path in WATCHED}
        head = {path: read_at(repo, head_sha, path) for path in WATCHED}
        pr = PullRequest(
            int(number),
            env.get("AUTHOR_LOGIN", ""),
            env.get("AUTHOR_TYPE", ""),
            env.get("HEAD_REPO", ""),
            base_repo,
            env.get("HEAD_REF", ""),
            tuple(pr_commits(base_repo, int(number), fetch=fetch)),
        )
        report = evaluate(
            pr,
            base,
            head,
            changed_files(repo, start, head_sha),
            rc.pins_by_ref(repo),
            read_at(repo, main_sha, rc.SAFETY_FILE),
            bot_login=rc.BOT_LOGIN,
            verify=verify,
            classify=classify,
        )
    except rc.InfraError as exc:
        report = Report(infra=f"{exc.check}: {exc.detail}")
    except rc.ReleaseCheckError as exc:
        report = Report()
        report.fail(f"{exc.check}: {exc.detail}")
    if main_sha:
        # main moves without starting this check again, so the summary says which commit it read.
        report.row("Main read at", _code(main_sha[:12]))
    text = render_summary(report, number)
    print(text)
    summary_path = env.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(text)
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
