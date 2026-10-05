"""Tests for issue_router.py: one issue per rule, quiet unless something changes, escalation, closing."""
import datetime as dt
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import issue_router as rt
from fakes import REPO, FakeGitHub

NOW = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.timezone.utc)
RUN = "https://github.com/akasecurity/marketplace/actions/runs/9"


def R(suffix):
    return f"repos/{REPO}/{suffix}"


def red(detail="npm has 0.9.15, unpinned for 25 hours", **extra):
    return rt.Result(rule="staleness-i", label="staleness", title="staleness: an unpinned release", red=True,
                     detail=detail, **extra)


def existing(detail="npm has 0.9.15, unpinned for 25 hours", *, last="2026-10-01T11:00:00Z",
             created="2026-10-01T10:00:00Z", labels=("staleness",), assignees=("Vaishnav-OM", "venuverse"), extra=""):
    body = "\n".join([rt.marker("rule", "staleness-i"), rt.marker("state", rt.digest(detail)),
                      rt.marker("last-comment", last), "", detail, extra])
    return {"number": 40, "body": body, "created_at": created, "labels": [{"name": name} for name in labels],
            "assignees": [{"login": login} for login in assignees]}


def cleared_issue(cleared="2026-10-01T09:00:00Z", **kwargs):
    """An issue the router closed at `cleared`: closed, last updated then, and carrying the marker it leaves."""
    return dict(existing(extra=rt.marker("cleared", cleared), **kwargs), state="closed", updated_at=cleared)


class RouterCase(unittest.TestCase):
    def setUp(self):
        self.issues = []
        self.gh = FakeGitHub({
            ("GET", R("issues")): self.listed,
            ("POST", R("issues")): {"number": 41},
            ("POST", R("issues/40/comments")): {"id": 1},
            ("PATCH", R("issues/40")): {"number": 40},
            ("POST", R("issues/40/assignees")): {"number": 40},
            ("POST", R("issues/40/labels")): [],
        })

    def listed(self, body, params):
        """GitHub's issue list as the router asks for it: a filter that is not sent filters nothing, the state
        defaults to open, `since` keeps the issues updated after it (a fixture with no `updated_at` always
        qualifies), and a fixture without a `state` is open and one without a `user` was filed by the
        workflow's token."""
        return [issue for issue in self.issues
                if issue.get("state", "open") == params.get("state", "open")
                and issue.get("updated_at", params.get("since", "")) >= params.get("since", "")
                and ("creator" not in params or issue.get("user", {"login": rt.ACTIONS_BOT})["login"] == params["creator"])
                and ("labels" not in params or any(label["name"] == params["labels"] for label in issue["labels"]))]

    def router(self, escalation=None):
        return rt.Router(self.gh, approvers=["Vaishnav-OM", "venuverse"], escalation=escalation,
                         owners=["Vaishnav-OM", "venuverse"], now=NOW, run_url=RUN)


class TestRouter(RouterCase):
    def test_a_red_rule_with_no_issue_opens_one_for_the_approvers(self):
        self.assertEqual(self.router().apply(red()), "staleness-i: opened #41")
        sent = self.gh.called("POST", R("issues"))[0][2]
        self.assertEqual(sent["title"], "staleness: an unpinned release")
        self.assertEqual((sent["labels"], sent["assignees"]), (["staleness"], ["Vaishnav-OM", "venuverse"]))
        self.assertEqual(rt.read_marker(sent["body"], "rule"), "staleness-i")
        self.assertIn("cc @Vaishnav-OM @venuverse", sent["body"])
        self.assertIn("npm has 0.9.15", sent["body"])

    def test_an_unchanged_red_rule_stays_quiet_within_a_day(self):
        self.issues.append(existing())
        self.assertEqual(self.router().apply(red()), "staleness-i: #40 unchanged")
        self.assertEqual(self.gh.writes(), [])

    def test_a_changed_detail_comments_and_moves_the_markers(self):
        self.issues.append(existing(detail="npm has 0.9.15"))
        self.router().apply(red(detail="npm has 0.9.15 and 0.9.16"))
        self.assertIn("0.9.16", self.gh.called("POST", R("issues/40/comments"))[0][2]["body"])
        body = self.gh.called("PATCH", R("issues/40"))[0][2]["body"]
        self.assertEqual(rt.read_marker(body, "state"), rt.digest("npm has 0.9.15 and 0.9.16"))
        self.assertEqual(rt.read_marker(body, "last-comment"), "2026-10-01T12:00:00Z")

    def test_a_quiet_red_rule_comments_again_after_a_day(self):
        self.issues.append(existing(last="2026-09-30T11:00:00Z"))
        self.assertIn("commented", self.router().apply(red()))

    def test_after_48_hours_the_escalation_owner_is_assigned(self):
        self.issues.append(existing(created="2026-09-29T11:00:00Z"))
        self.assertIn("escalated", self.router(escalation="org-owner-example").apply(red()))
        self.assertEqual(self.gh.called("POST", R("issues/40/assignees"))[0][2], {"assignees": ["org-owner-example"]})

    def carry_edits_to_the_issue(self):
        """What GitHub keeps between two runs: the issue's body as the router last edited it. Nobody is
        assigned in the fake, which is the owner having taken themselves off the issue."""
        for call in self.gh.called("PATCH", R("issues/40")):
            self.issues[0] = dict(self.issues[0], body=call[2].get("body", self.issues[0]["body"]))
        self.gh.calls.clear()

    def test_the_escalation_owner_is_assigned_once_even_if_unassigned(self):
        self.issues.append(existing(created="2026-09-29T11:00:00Z"))
        self.assertIn("escalated", self.router(escalation="org-owner-example").apply(red()))
        self.carry_edits_to_the_issue()
        self.assertEqual(self.router(escalation="org-owner-example").apply(red()), "staleness-i: #40 unchanged")
        self.assertEqual(self.gh.writes(), [])
        self.assertEqual(rt.read_marker(self.issues[0]["body"], "escalated"), "org-owner-example")

    def test_a_new_escalation_owner_is_assigned_in_turn(self):
        self.issues.append(existing(created="2026-09-29T11:00:00Z"))
        self.router(escalation="org-owner-example").apply(red())
        self.carry_edits_to_the_issue()
        self.assertIn("escalated", self.router(escalation="next-owner-example").apply(red()))
        self.assertEqual(self.gh.called("POST", R("issues/40/assignees"))[0][2], {"assignees": ["next-owner-example"]})

    def test_without_an_escalation_owner_the_gap_is_noted_once(self):
        self.issues.append(existing(created="2026-09-29T11:00:00Z"))
        self.router().apply(red())
        self.assertIn("names no escalation owner", self.gh.called("POST", R("issues/40/comments"))[0][2]["body"])
        noted = self.gh.called("PATCH", R("issues/40"))[0][2]["body"]
        self.assertEqual(rt.read_marker(noted, "escalation-unset"), "1")
        self.issues[0] = dict(self.issues[0], body=noted)
        self.gh.calls.clear()
        self.assertEqual(self.router().apply(red()), "staleness-i: #40 unchanged")

    def test_an_issue_whose_label_was_removed_is_still_found_and_relabelled(self):
        self.issues.append(existing(labels=()))
        self.assertEqual(self.router().apply(red()), "staleness-i: #40 labelled")
        self.assertEqual(self.gh.called("POST", R("issues")), [])
        self.assertEqual(self.gh.called("POST", R("issues/40/labels"))[0][2], {"labels": ["staleness"]})

    def test_only_issues_the_workflow_filed_are_listed(self):
        self.router().apply(red())
        sent = self.gh.called("GET", R("issues"))[0][3]
        self.assertEqual((sent.get("state"), sent.get("creator")), ("open", "github-actions[bot]"))
        self.assertNotIn("labels", sent)

    def test_an_issue_filed_by_a_person_is_never_taken_for_the_rules_issue(self):
        copied = dict(existing(), user={"login": "some-writer"})
        self.issues.append(copied)
        self.assertEqual(self.router().apply(red()), "staleness-i: opened #41")
        self.assertEqual(self.gh.called("PATCH", R("issues/40")), [])
        self.assertEqual(self.gh.called("POST", R("issues/40/comments")), [])

    def test_a_missing_extra_label_is_added(self):
        self.issues.append(existing())
        self.router().apply(red(extra_labels=["rollback-hold"]))
        self.assertEqual(self.gh.called("POST", R("issues/40/labels"))[0][2], {"labels": ["rollback-hold"]})

    def test_a_cleared_rule_closes_its_issue(self):
        self.issues.append(existing())
        cleared = rt.Result(rule="staleness-i", label="staleness", title="t", red=False)
        self.assertEqual(self.router().apply(cleared), "staleness-i: cleared; closed #40")
        patches = self.gh.called("PATCH", R("issues/40"))
        self.assertEqual(len(patches), 1)
        closed = patches[0][2]
        self.assertEqual((closed["state"], closed["state_reason"]), ("closed", "completed"))
        # The marker goes in the same edit as the close, and the rest of the body is as it was.
        self.assertEqual(rt.read_marker(closed["body"], "cleared"), "2026-10-01T12:00:00Z")
        self.assertEqual(rt.drop_marker(closed["body"], "cleared"), self.issues[0]["body"])

    def test_a_rule_red_again_within_48_hours_reopens_its_issue(self):
        self.issues.append(cleared_issue())
        self.assertEqual(self.router().apply(red()), "staleness-i: red again; reopened #40")
        self.assertEqual(self.gh.called("POST", R("issues")), [])
        looked = self.gh.called("GET", R("issues"))[-1][3]
        self.assertEqual((looked["state"], looked["creator"], looked["since"]),
                         ("closed", "github-actions[bot]", "2026-09-29T12:00:00Z"))
        patched = self.gh.called("PATCH", R("issues/40"))[0][2]
        self.assertEqual((patched["state"], patched["state_reason"]), ("open", "reopened"))
        self.assertEqual(rt.read_marker(patched["body"], "state"), rt.digest(red().detail))
        self.assertEqual(rt.read_marker(patched["body"], "last-comment"), "2026-10-01T12:00:00Z")
        self.assertEqual(rt.read_marker(patched["body"], "rule"), "staleness-i")
        comments = self.gh.called("POST", R("issues/40/comments"))
        self.assertEqual(len(comments), 1)
        self.assertIn("Red again at 2026-10-01T12:00:00Z (cleared at 2026-10-01T09:00:00Z)", comments[0][2]["body"])
        self.assertIn("npm has 0.9.15", comments[0][2]["body"])
        self.assertIn(RUN, comments[0][2]["body"])

    def test_a_rule_red_again_after_48_hours_opens_a_new_issue(self):
        # 49 hours ago. The listing may still return the issue (a comment since then moves its update time),
        # so the marker, not only the listing's window, rules it out.
        for label, updated in (("untouched since", "2026-09-29T11:00:00Z"), ("commented on since", "2026-10-01T08:00:00Z")):
            with self.subTest(label):
                self.gh.calls.clear()
                self.issues[:] = [dict(cleared_issue("2026-09-29T11:00:00Z"), updated_at=updated)]
                self.assertEqual(self.router().apply(red()), "staleness-i: opened #41")
                self.assertEqual(self.gh.called("PATCH", R("issues/40")), [])

    def test_an_issue_a_person_closed_is_not_reopened(self):
        person_closed = dict(existing(), state="closed", updated_at="2026-10-01T11:00:00Z")
        cases = {
            "no cleared marker": person_closed,
            "an unreadable one": dict(cleared_issue("not a time")),
            "one without a zone": dict(cleared_issue("2026-10-01T09:00:00")),
            "filed by a person": dict(cleared_issue(), user={"login": "some-writer"}),
        }
        for label, issue in cases.items():
            with self.subTest(label):
                self.gh.calls.clear()
                self.issues[:] = [issue]
                self.assertEqual(self.router().apply(red()), "staleness-i: opened #41")
                self.assertEqual(self.gh.called("PATCH", R("issues/40")), [])

    def test_a_reopened_issue_a_person_then_closes_stays_closed(self):
        self.issues.append(cleared_issue())
        self.router().apply(red())
        reopened = self.gh.called("PATCH", R("issues/40"))[0][2]["body"]
        self.assertIsNone(rt.read_marker(reopened, "cleared"))
        self.gh.calls.clear()
        self.issues[:] = [dict(existing(), body=reopened, state="closed", updated_at="2026-10-01T11:30:00Z")]
        self.assertEqual(self.router().apply(red()), "staleness-i: opened #41")

    def test_a_result_the_router_never_closes_does_not_look_for_a_cleared_issue(self):
        self.issues.append(cleared_issue())
        self.assertEqual(self.router().apply(red(auto_close=False)), "staleness-i: opened #41")
        self.assertEqual([call[3]["state"] for call in self.gh.called("GET", R("issues"))], ["open"])

    def test_the_issue_cleared_last_is_the_one_reopened(self):
        self.issues[:] = [dict(cleared_issue("2026-09-30T16:00:00Z"), number=39), cleared_issue("2026-10-01T09:00:00Z")]
        self.assertEqual(self.router().apply(red()), "staleness-i: red again; reopened #40")

    def test_the_original_creation_time_still_drives_escalation_after_a_reopen(self):
        self.issues.append(cleared_issue(created="2026-09-28T10:00:00Z"))
        outcome = self.router(escalation="org-owner-example").apply(red())
        self.assertEqual(outcome, "staleness-i: red again; reopened #40, escalated")
        self.assertEqual(self.gh.called("POST", R("issues/40/assignees"))[0][2], {"assignees": ["org-owner-example"]})

    def test_a_rule_a_person_closes_is_never_closed_by_the_router(self):
        self.issues.append(existing())
        cleared = rt.Result(rule="staleness-i", label="staleness", title="t", red=False, auto_close=False)
        self.router().apply(cleared)
        self.assertEqual(self.gh.writes(), [])

    def test_a_rule_not_evaluated_touches_nothing(self):
        self.router().apply(rt.Result(rule="staleness-i", label="staleness", title="t", red=None))
        self.assertEqual(self.gh.calls, [])


class TestRoute(RouterCase):
    def test_only_red_alerts_fail_the_run(self):
        notice = rt.Result(rule="staleness-rollback-hold", label="staleness", title="rolled back, awaiting fix-forward",
                           red=True, kind="notice", extra_labels=["rollback-hold"])
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(rt.route([notice], label="staleness", job_result="success", router=self.router()), 0)
            self.assertEqual(rt.route([red()], label="staleness", job_result="success", router=self.router()), 1)

    def test_an_evaluation_job_that_did_not_finish_is_itself_red(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(rt.route([red()], label="staleness", job_result="failure", router=self.router()), 1)
        opened = [call[2] for call in self.gh.called("POST", R("issues"))]
        self.assertEqual([item["title"] for item in opened], ["staleness: the evaluation job did not finish"])


class TestFailedJobStaysQuiet(RouterCase):
    def test_a_job_that_keeps_failing_comments_once_however_many_runs_report_it(self):
        def run(number):
            router = rt.Router(self.gh, approvers=["Vaishnav-OM", "venuverse"], escalation=None,
                               owners=["Vaishnav-OM"], now=NOW, run_url=f"https://github.com/{REPO}/actions/runs/{number}")
            with mock.patch("sys.stdout", new_callable=io.StringIO):
                return rt.route([], label="staleness", job_result="failure", router=router)

        self.assertEqual(run(1), 1)
        opened = self.gh.called("POST", R("issues"))[0][2]
        self.assertIn("actions/runs/1", opened["body"])
        self.issues.append({"number": 40, "body": opened["body"], "created_at": "2026-10-01T10:00:00Z",
                            "labels": [{"name": "staleness"}], "assignees": []})
        del self.gh.calls[:]
        self.assertEqual(run(2), 1)
        self.assertEqual(self.gh.writes(), [])

    def test_the_run_url_is_not_part_of_the_digested_detail(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            rt.route([], label="staleness", job_result="failure", router=self.router())
        detail = rt.read_marker(self.gh.called("POST", R("issues"))[0][2]["body"], "state")
        self.assertEqual(detail, rt.digest(
            "The staleness evaluation job ended `failure`; its checks did not run, so their issues were left as "
            "they were."))


class TestNoResults(RouterCase):
    def route(self, results, job_result="success"):
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            return rt.route(results, label="staleness", job_result=job_result, router=self.router())

    def test_a_finished_job_that_reported_nothing_is_red(self):
        self.assertEqual(self.route(None), 1)
        opened = self.gh.called("POST", R("issues"))[0][2]
        self.assertEqual(opened["title"], "staleness: the evaluation job reported no results")
        self.assertEqual(rt.read_marker(opened["body"], "rule"), "staleness-workflow")

    def test_a_finished_job_whose_results_could_not_be_read_is_red(self):
        self.assertEqual(self.route(None), 1)
        self.assertEqual(len(self.gh.called("POST", R("issues"))), 1)

    def test_a_finished_job_that_reported_an_explicit_empty_list_is_clear(self):
        self.assertEqual(self.route([]), 0)
        self.assertEqual(self.gh.writes(), [])

    def test_an_explicit_empty_list_closes_an_earlier_no_results_alert(self):
        self.issues.append({"number": 40, "labels": [{"name": "staleness"}], "assignees": [],
                            "created_at": "2026-10-01T10:00:00Z",
                            "body": "\n".join([rt.marker("rule", "staleness-workflow"),
                                               rt.marker("state", rt.digest("x")), "", "x"])})
        self.assertEqual(self.route([]), 0)
        self.assertEqual(self.gh.called("POST", R("issues")), [])
        self.assertEqual([call[2].get("state") for call in self.gh.called("PATCH", R("issues/40"))], ["closed"])

    def test_an_explicit_empty_list_leaves_an_open_per_rule_issue_as_it_is(self):
        self.issues.append(existing())
        self.assertEqual(self.route([]), 0)
        self.assertEqual(self.gh.writes(), [])

    def test_a_finished_job_with_a_result_is_green_when_the_result_is(self):
        self.assertEqual(self.route([rt.Result(rule="staleness-i", label="staleness", title="t", red=False)]), 0)
        self.assertEqual(self.gh.writes(), [])


class TestMain(unittest.TestCase):
    """main() end to end: the files it reads, the environment it takes, the exit code it returns."""

    OWNERS = b"* @Vaishnav-OM\n"

    def run_main(self, *, job_result, results_json=None, label="staleness", codeowners=OWNERS, issues=()):
        """`codeowners` is the file's bytes, or None for no file. Leaves the fake GitHub and what main printed
        on self for a test that wants more than the exit code and the titles."""
        gh = FakeGitHub({("GET", R("issues")): list(issues), ("POST", R("issues")): {"number": 41},
                         ("POST", R("issues/40/comments")): {"id": 1}, ("PATCH", R("issues/40")): {"number": 40}})
        env = {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": REPO, "GITHUB_RUN_ID": "9",
               "JOB_RESULT": job_result}
        if results_json is not None:
            env["RESULTS_JSON"] = results_json
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".github"))
            with open(os.path.join(root, ".github", "release-approvers.json"), "w", encoding="utf-8") as handle:
                json.dump({"approvers": ["Vaishnav-OM"], "escalation": None}, handle)
            if codeowners is not None:
                with open(os.path.join(root, ".github", "CODEOWNERS"), "wb") as handle:
                    handle.write(codeowners)
            cwd = os.getcwd()
            os.chdir(root)
            try:
                with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(rt, "GitHub", return_value=gh), \
                        mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                    code = rt.main(["apply", "--label", label])
            finally:
                os.chdir(cwd)
        self.gh, self.printed = gh, out.getvalue()
        return code, [call[2]["title"] for call in gh.called("POST", R("issues"))]

    def test_a_success_with_no_results_output_is_red(self):
        self.assertEqual(self.run_main(job_result="success"),
                         (1, ["staleness: the evaluation job reported no results"]))

    def test_a_success_with_an_empty_string_is_red(self):
        self.assertEqual(self.run_main(job_result="success", results_json=""),
                         (1, ["staleness: the evaluation job reported no results"]))
        self.assertEqual(self.run_main(job_result="success", results_json="  \n")[0], 1)

    def test_a_success_with_an_explicit_empty_list_is_clear(self):
        self.assertEqual(self.run_main(job_result="success", results_json="[]"), (0, []))

    def test_main_audit_explicit_empty_list_is_clear(self):
        self.assertEqual(self.run_main(job_result="success", results_json="[]", label="main-audit"), (0, []))

    def test_main_audit_with_no_output_is_red(self):
        self.assertEqual(self.run_main(job_result="success", label="main-audit"),
                         (1, ["main-audit: the evaluation job reported no results"]))

    def test_a_success_with_unparsable_results_files_an_issue_instead_of_crashing(self):
        self.assertEqual(self.run_main(job_result="success", results_json="{not json"),
                         (1, ["staleness: the evaluation job reported no results"]))
        self.assertEqual(self.run_main(job_result="success", results_json='[{"unknown": 1}]')[0], 1)

    def test_a_success_with_a_clear_result_is_green(self):
        clear = rt.results_to_json([rt.Result(rule="staleness-i", label="staleness", title="t", red=False)])
        self.assertEqual(self.run_main(job_result="success", results_json=clear), (0, []))

    def test_a_red_result_is_filed_and_fails_the_run(self):
        code, titles = self.run_main(job_result="success", results_json=rt.results_to_json([red()]))
        self.assertEqual((code, titles), (1, ["staleness: an unpinned release"]))

    def test_a_job_that_did_not_finish_is_red(self):
        self.assertEqual(self.run_main(job_result="cancelled", results_json="[]"),
                         (1, ["staleness: the evaluation job did not finish"]))

    def test_the_code_owners_are_mentioned_when_the_file_reads(self):
        self.run_main(job_result="success", results_json=rt.results_to_json([red()]))
        self.assertIn("Filed by https://github.com/akasecurity/marketplace/actions/runs/9. cc @Vaishnav-OM\n",
                      self.gh.called("POST", R("issues"))[0][2]["body"])

    def test_a_codeowners_file_that_is_missing_or_not_text_costs_only_the_mention(self):
        # The alert is the point: a CODEOWNERS file nobody can read must not stop it being filed.
        unreadable = {"missing": None, "not UTF-8": b"* @Vaishnav-OM \xff\xfe\n", "empty": b""}
        for label, codeowners in unreadable.items():
            with self.subTest(label):
                code, titles = self.run_main(job_result="success", results_json=rt.results_to_json([red()]),
                                             codeowners=codeowners)
                self.assertEqual((code, titles), (1, ["staleness: an unpinned release"]))
                body = self.gh.called("POST", R("issues"))[0][2]["body"]
                self.assertNotIn("@", body)
                self.assertIn("/actions/runs/9.\n", body)
                self.assertEqual("::warning::" in self.printed, codeowners != b"")

    def test_a_codeowners_file_that_cannot_be_read_still_closes_a_cleared_rules_issue(self):
        issue = existing()
        clear = rt.results_to_json([rt.Result(rule="staleness-i", label="staleness", title="t", red=False)])
        for label, codeowners in {"missing": None, "not UTF-8": b"\xff\xfe"}.items():
            with self.subTest(label):
                code, titles = self.run_main(job_result="success", results_json=clear, codeowners=codeowners,
                                             issues=[issue])
                self.assertEqual((code, titles), (0, []))
                self.assertEqual([call[2].get("state") for call in self.gh.called("PATCH", R("issues/40"))], ["closed"])


class TestHelpers(unittest.TestCase):
    def test_parse_codeowners_takes_the_last_star_line(self):
        self.assertEqual(rt.parse_codeowners("# owners\n* @a @b\n/docs @c\n* @Vaishnav-OM @venuverse # all\n"),
                         ["Vaishnav-OM", "venuverse"])

    def test_results_round_trip_through_json(self):
        results = [red(extra_labels=["rollback-hold"]),
                   rt.Result(rule="x", label="tag-audit", title="t", red=None, auto_close=False)]
        self.assertEqual(rt.results_from_json(rt.results_to_json(results)), results)


if __name__ == "__main__":
    unittest.main()
