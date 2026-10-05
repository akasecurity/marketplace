"""Opens, updates and closes the marketplace's alert issues.

staleness, tag-audit and main-audit evaluate their rules in a job that cannot
write issues, and hand the results to a job that can do nothing else. Each
rule has one issue, found by a hidden rule marker among those the workflow's token filed; it is
assigned to the release approvers in .github/release-approvers.json and
mentions the code owners in .github/CODEOWNERS (a file that is missing or is
not UTF-8 text costs the mention, never the issue). A red rule comments only when
its detail changes, or once a day; after 48 hours the escalation owner is
assigned; a rule that clears closes its issue, unless its result says
otherwise (main-audit's results never do: the next run audits only its own push, so
a person closes them; its failed-job result is keyed to the push as well). GitHub mails a failed scheduled run only to whoever last edited
its cron line, which is why red goes to an issue.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field

from ghapi import GitHub

# The login every router job files issues under (they all use the workflow's token). find looks only at
# issues this login created, so an issue a person filed cannot stand in for a rule's.
ACTIONS_BOT = "github-actions[bot]"
# A rule that goes red again this soon after the router closed its issue reopens that issue (apply).
REOPEN_WITHIN = dt.timedelta(hours=48)
APPROVERS_FILE = ".github/release-approvers.json"
CODEOWNERS_FILE = ".github/CODEOWNERS"
COMMENT_EVERY = dt.timedelta(hours=24)
ESCALATE_AFTER = dt.timedelta(hours=48)
# The labels whose run audits only its own push: their results do not auto-close, and a failed job is filed under
# the push it failed on (route), so a later run neither reuses nor closes it.
PER_PUSH_LABELS = {"main-audit"}
# GitHub refuses an issue body or a comment longer than 65,536 characters, and a refused post loses the alert.
# The quoted block (the text, both fences and, when the text is cut, the note) is held to this many characters,
# which leaves room for everything else the post holds.
DETAIL_LIMIT = 60_000


@dataclass
class Result:
    """One rule's outcome. red None means not evaluated this run: its issue is left as it is."""

    rule: str
    label: str
    title: str
    red: bool | None
    detail: str = ""
    kind: str = "alert"  # "alert" fails the run while red; "notice" never does
    extra_labels: list[str] = field(default_factory=list)
    auto_close: bool = True


def results_to_json(results: list[Result]) -> str:
    return json.dumps([asdict(result) for result in results], separators=(",", ":"))


def results_from_json(text: str) -> list[Result]:
    return [Result(**item) for item in json.loads(text or "[]")]


def parse_codeowners(text: str) -> list[str]:
    """The owners of `*`; as in CODEOWNERS, the last matching line wins."""
    owners: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        pattern, *handles = line.split()
        if pattern == "*":
            owners = [handle[1:] for handle in handles if handle.startswith("@")]
    return owners


def read_owners(path: str = CODEOWNERS_FILE) -> list[str]:
    """The owners to mention. A file that is missing, cannot be opened or is not UTF-8 text gives none and a
    warning: the mention is a courtesy, and an alert that cannot be filed because of it is lost for good."""
    try:
        with open(path, encoding="utf-8") as handle:
            return parse_codeowners(handle.read())
    except (OSError, UnicodeDecodeError) as error:
        print(f"::warning::{path} was not read ({type(error).__name__}), so no code owner is mentioned")
        return []


def marker(name: str, value: str) -> str:
    return f"<!-- {name}:{value} -->"


def read_marker(body: str | None, name: str) -> str | None:
    match = re.search(rf"<!-- {re.escape(name)}:(.*?) -->", body or "")
    return match.group(1) if match else None


def set_marker(body: str, name: str, value: str) -> str:
    if read_marker(body, name) is None:
        return marker(name, value) + "\n" + body
    return re.sub(rf"<!-- {re.escape(name)}:.*? -->", lambda _: marker(name, value), body, count=1)


def drop_marker(body: str, name: str) -> str:
    return re.sub(rf"<!-- {re.escape(name)}:.*? -->\n?", "", body, count=1)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _units(text: str) -> int:
    """UTF-16 code units, the larger of the two ways GitHub could count a character."""
    return len(text) + sum(1 for character in text if ord(character) > 0xFFFF)


def quoted(detail: str, run_url: str) -> str:
    """The detail as a code block, with a note when it had to be cut.

    Part of a detail is text a person chose, a tag's name or the subject of its message. In a code block
    it cannot mention anyone, link back from another repository's issue or render as a link in an alert
    that reads as the project's own. The fence is one backtick longer than the longest run of backticks in
    the text, and at least three, so the text cannot end the block. The whole block, both fences and the
    note included, is held to DETAIL_LIMIT UTF-16 code units. The fence depends on the text that is kept (a
    long run of backticks makes a long fence, twice), so the text is cut as long as will still fit with the
    fence its own cut gives it. The digest is taken from the whole detail (see _refresh), so a cut never
    makes a comment of its own."""
    note = f"\n… truncated; the full detail is in the run log ({run_url})"

    def render(end: int) -> str:
        text = detail[:end]
        fence = "`" * max(3, max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
        block = f"{fence}\n{text}\n{fence}"
        return block if end == len(detail) else block + note

    # A character is at least one code unit, so a detail longer than the limit never fits as it is.
    if len(detail) <= DETAIL_LIMIT and _units(render(len(detail))) <= DETAIL_LIMIT:
        return render(len(detail))
    # Keeping one more character never shortens the block (the fence only grows or stays), so the longest
    # text that fits is found by bisection.
    low, high = 0, min(len(detail) - 1, DETAIL_LIMIT)
    while low < high:
        middle = (low + high + 1) // 2
        if _units(render(middle)) <= DETAIL_LIMIT:
            low = middle
        else:
            high = middle - 1
    return render(low)


def when(text: str) -> dt.datetime:
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


def stamp(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Router:
    def __init__(self, gh, *, approvers: list[str], escalation: str | None, owners: list[str],
                 now: dt.datetime, run_url: str) -> None:
        self.gh = gh
        self.approvers = approvers
        self.escalation = escalation
        self.owners = owners
        self.now = now
        self.run_url = run_url

    def _issues(self, state: str, since: dt.datetime | None = None):
        """The issues the workflow's own token filed (ACTIONS_BOT) in `state`, never a pull request.
        `since` keeps only those updated after that moment."""
        params = {"state": state, "creator": ACTIONS_BOT}
        if since is not None:
            params["since"] = stamp(since)
        return (issue for issue in self.gh.paginate(self.gh.repo_path("issues"), params)
                if "pull_request" not in issue)

    def find(self, result: Result) -> dict | None:
        """The rule's open issue: one the workflow's own token filed that carries the rule's hidden marker.
        The label is not part of the match, so taking it off an issue does not hide the issue (_refresh puts
        it back), and an issue a person filed with the label and marker copied is not the rule's."""
        for issue in self._issues("open"):
            if read_marker(issue.get("body"), "rule") == result.rule:
                return issue
        return None

    def find_cleared(self, result: Result) -> dict | None:
        """The rule's issue this router closed within REOPEN_WITHIN, the latest if several. The router leaves
        a `cleared` marker when it closes an issue (apply), so an issue only a person ever closed has no marker
        and never matches. One the router cleared, a person reopened and closed again keeps its marker, and
        matches while it is inside the window."""
        found: tuple[dt.datetime, dict] | None = None
        for issue in self._issues("closed", self.now - REOPEN_WITHIN):
            if read_marker(issue.get("body"), "rule") != result.rule:
                continue
            try:
                cleared = when(read_marker(issue.get("body"), "cleared") or "")
                age = self.now - cleared
            except (ValueError, TypeError):
                continue
            if age <= REOPEN_WITHIN and (found is None or cleared > found[0]):
                found = (cleared, issue)
        return found[1] if found else None

    def apply(self, result: Result) -> str:
        """Bring the rule's issue in line with its result.

        Red with no open issue opens one, unless the router closed this rule's issue less than REOPEN_WITHIN
        ago: that issue is reopened instead, so a rule that flaps keeps one issue, and keeps the creation time
        the 48-hour escalation counts from. Only a result that closes by itself (auto_close) is looked up that
        way; an issue only a person ever closed, or one the router never closes, is not reopened. Clear closes the
        issue and records when, in the same edit."""
        if result.red is None:
            return f"{result.rule}: not evaluated this run; its issue is left as it is"
        issue = self.find(result)
        if result.red:
            if issue is None and result.auto_close:
                cleared = self.find_cleared(result)
                if cleared is not None:
                    return self._reopen(result, cleared)
            return self._open(result) if issue is None else self._update(result, issue)
        if issue is not None and result.auto_close:
            self._comment(issue["number"], f"Cleared at {stamp(self.now)} ({self.run_url}).")
            self.gh.patch(self.gh.repo_path(f"issues/{issue['number']}"),
                          {"state": "closed", "state_reason": "completed",
                           "body": set_marker(issue.get("body") or "", "cleared", stamp(self.now))})
            return f"{result.rule}: cleared; closed #{issue['number']}"
        return f"{result.rule}: clear"

    def _open(self, result: Result) -> str:
        cc = " ".join(f"@{owner}" for owner in self.owners)
        closing = ("It closes by itself when the rule clears." if result.auto_close
                   else "A person closes it once it is explained.")
        body = "\n".join([marker("rule", result.rule), marker("state", digest(result.detail)),
                          marker("last-comment", stamp(self.now)), "", quoted(result.detail, self.run_url), "", "---",
                          f"Filed by {self.run_url}." + (f" cc {cc}" if cc else ""),
                          "Assigned to the release approvers; after 48 hours the escalation owner is assigned too. "
                          + closing])
        issue = self.gh.post(self.gh.repo_path("issues"), {"title": result.title, "body": body,
                                                           "labels": [result.label, *result.extra_labels],
                                                           "assignees": self.approvers})
        return f"{result.rule}: opened #{issue['number']}"

    def _reopen(self, result: Result, issue: dict) -> str:
        number, body = issue["number"], issue.get("body") or ""
        self._comment(number, f"Red again at {stamp(self.now)} (cleared at {read_marker(body, 'cleared')}).\n\n"
                              f"{quoted(result.detail, self.run_url)}\n\n({self.run_url})")
        # The `cleared` marker goes, so a person who closes the reopened issue is not overruled by it.
        body = set_marker(set_marker(drop_marker(body, "cleared"), "state", digest(result.detail)),
                          "last-comment", stamp(self.now))
        self.gh.patch(self.gh.repo_path(f"issues/{number}"), {"state": "open", "state_reason": "reopened", "body": body})
        actions = self._refresh(result, dict(issue, state="open", body=body))
        return f"{result.rule}: red again; reopened #{number}" + "".join(f", {action}" for action in actions)

    def _update(self, result: Result, issue: dict) -> str:
        return f"{result.rule}: #{issue['number']} " + (", ".join(self._refresh(result, issue)) or "unchanged")

    def _refresh(self, result: Result, issue: dict) -> list[str]:
        """Comment if the detail changed or a day passed, restore a missing label, escalate once the issue has
        been open 48 hours, and save the markers. Returns what it did."""
        number, body = issue["number"], issue.get("body") or ""
        new_body, actions = body, []
        state, last = digest(result.detail), read_marker(body, "last-comment")
        if state != read_marker(body, "state") or last is None or self.now - when(last) >= COMMENT_EVERY:
            self._comment(number, f"{quoted(result.detail, self.run_url)}\n\n({self.run_url})")
            new_body = set_marker(set_marker(new_body, "state", state), "last-comment", stamp(self.now))
            actions.append("commented")
        present = {label.get("name") for label in issue.get("labels", [])}
        missing = [label for label in [result.label, *result.extra_labels] if label not in present]
        if missing:
            self.gh.post(self.gh.repo_path(f"issues/{number}/labels"), {"labels": missing})
            actions.append("labelled")
        if self.now - when(issue["created_at"]) >= ESCALATE_AFTER:
            assigned = {assignee.get("login") for assignee in issue.get("assignees", [])}
            # Once per owner: the marker outlives the assignment, so an owner who takes themselves off the
            # issue is not assigned again, with another comment, on every run.
            if self.escalation and self.escalation not in assigned and read_marker(new_body, "escalated") != self.escalation:
                self.gh.post(self.gh.repo_path(f"issues/{number}/assignees"), {"assignees": [self.escalation]})
                self._comment(number, f"Open for more than 48 hours: assigning @{self.escalation}, the escalation "
                                      f"owner in {APPROVERS_FILE}.")
                new_body = set_marker(new_body, "escalated", self.escalation)
                actions.append("escalated")
            elif not self.escalation and read_marker(new_body, "escalation-unset") is None:
                self._comment(number, f"Open for more than 48 hours, and {APPROVERS_FILE} names no escalation "
                                      "owner, so nobody further is assigned.")
                new_body = set_marker(new_body, "escalation-unset", "1")
                actions.append("escalation owner unset")
        if new_body != body:
            self.gh.patch(self.gh.repo_path(f"issues/{number}"), {"body": new_body})
        return actions

    def _comment(self, number: int, text: str) -> None:
        self.gh.post(self.gh.repo_path(f"issues/{number}/comments"), {"body": text})


def route(results: list[Result] | None, *, label: str, job_result: str, router: Router, push: str | None = None) -> int:
    """Apply every result. Returns the exit code.

    An evaluation job that did not finish is itself a red result, and so is one that finished but handed
    over no output (None: it was absent, blank or could not be read), because reading that as "nothing is
    red" would leave the audit green for good if the wiring between the job and this step broke. An
    explicit empty list is different: it is the evaluator saying that nothing is red, so it is a clear
    result for every label. The one issue it can close is the label's own "<label>-workflow" issue, opened
    when an earlier run's job did not finish or handed over nothing (main-audit's is left for a person, see
    PER_PUSH_LABELS); it leaves every per-rule issue as it is, because only a clear result for that rule
    closes that rule's issue. It says nothing about which evaluator sends it: an evaluator that always
    appends a clear result of its own never sends one. The detail names no run URL: it is digested to decide
    whether anything changed, and every run has its own URL, while the comment appends it.

    A per-push label (main-audit) files this result under `push`, the sha the run was for: a failed job
    leaves its push unaudited, and a second failed run would otherwise find the first one's issue, see the
    same detail inside a day, and write nothing. Without a push the rule stays the shared one, so a missing
    key fails closed.
    """
    finished = job_result == "success"
    reported = finished and results is not None
    # main-audit checks one push per run, so a later clean run says nothing about the push whose job did
    # not finish: its workflow issue stays open for a person. The other rules re-check all state every run.
    key = push[:12] if push and label in PER_PUSH_LABELS else None
    job = f"{label} evaluation job" + (f" for the push to `{key}`" if key else "")
    if reported:
        problem = None
    elif finished:
        problem = (f"The {job} finished but reported no results that could be read, so none of "
                   "its checks ran and their issues were left as they were.")
    else:
        problem = (f"The {job} ended `{job_result or 'unknown'}`; its checks did not run, so "
                   "their issues were left as they were.")
    results = list(results or []) if reported else []
    results.append(Result(
        rule=f"{label}-workflow" + (f"-{key}" if key else ""), label=label, red=problem is not None,
        detail=problem or "", auto_close=label not in PER_PUSH_LABELS,
        title=f"{label}: the evaluation job" + (f" for the push to {key}" if key else "") + " "
              + ("reported no results" if finished else "did not finish")))
    red = False
    for result in results:
        print(router.apply(result))
        if result.red and result.kind == "alert":
            red = True
            first = result.detail.splitlines()[0] if result.detail else result.rule
            print(f"::error title={result.title}::{first}")
    return 1 if red else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Open, update or close one workflow's alert issues")
    parser.add_argument("command", choices=["apply"])
    parser.add_argument("--label", required=True, choices=["staleness", "tag-audit", "main-audit"])
    args = parser.parse_args(argv)
    env = os.environ
    run_url = f"{env['GITHUB_SERVER_URL']}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}"
    with open(APPROVERS_FILE, encoding="utf-8") as handle:
        config = json.load(handle)
    owners = read_owners()
    router = Router(GitHub(env.get("GH_TOKEN", ""), env["GITHUB_REPOSITORY"]), approvers=config["approvers"],
                    escalation=config.get("escalation"), owners=owners, now=dt.datetime.now(dt.timezone.utc),
                    run_url=run_url)
    job_result = env.get("JOB_RESULT", "")
    results: list[Result] | None = []
    if job_result == "success":
        raw = env.get("RESULTS_JSON", "")
        try:
            # Blank output is no output; only a parsed list, even an empty one, is a result.
            results = results_from_json(raw) if raw.strip() else None
        except (ValueError, TypeError):
            results = None
    return route(results, label=args.label, job_result=job_result, router=router, push=env.get("AFTER") or None)


if __name__ == "__main__":
    sys.exit(main())
