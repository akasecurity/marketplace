"""Tests for staleness.py: each rule, the rollback-hold notice and the drill."""
import contextlib
import datetime as dt
import io
import json
import os
import tempfile
import types
import unittest
from unittest import mock

import issue_router
import release_checks
import staleness as st
from fakes import (INTEGRITY, REPO, UNREADABLE_MANIFESTS, FakeGit, FakeGitHub, fleet_tag, manifest, pull,
                   pulls_route)
from release_checks import MANIFEST

# StalenessCase replaces release_checks.npm_candidates for every test; the tests that read the registry
# through the real one keep a reference to it.
REAL_NPM_CANDIDATES = release_checks.npm_candidates
NOW = dt.datetime(2026, 10, 5, 12, 0, tzinfo=dt.timezone.utc)
FROZEN = [{"tag": "fleet-v7", "object": "o7", "commit": "t7"}, {"tag": "fleet-v8", "object": "o8", "commit": "t8"}]


def R(suffix):
    return f"repos/{REPO}/{suffix}"


def stamp(ago: dt.timedelta) -> str:
    return (NOW - ago).strftime("%Y-%m-%dT%H:%M:%SZ")


def repo(*, main_entry=True, pin_change_age=dt.timedelta(hours=2), tags=None, messages=None) -> FakeGit:
    """main: t7 (fleet-v7, 0.9.13), t8 (fleet-v8, 0.9.14), a description-only commit a, then b pinning 0.9.15."""
    files = {("t7", MANIFEST): manifest("0.9.13"), ("t8", MANIFEST): manifest("0.9.14"),
             ("a", MANIFEST): manifest("0.9.14"),
             ("b", MANIFEST): manifest("0.9.15", INTEGRITY["0.9.15"], entry=main_entry)}
    times = {"a": int((NOW - dt.timedelta(days=3)).timestamp()), "b": int((NOW - pin_change_age).timestamp())}
    return FakeGit(chain=["t7", "t8", "a", "b"], files=files, times=times,
                   tags=tags if tags is not None else [fleet_tag(7, "t7"), fleet_tag(8, "t8")],
                   messages=messages or {"fleet-v8": "fleet-v8: ai-tc 0.9.14\n\nversion: 0.9.14\n"})


class StalenessCase(unittest.TestCase):
    def setUp(self):
        self.candidates, self.bad, self.down, self.pulls, self.times = [], {}, {}, [], {}
        self.log = io.StringIO()
        self.gh = FakeGitHub({("GET", R("pulls")): pulls_route(self.pulls)})
        # The reader of the one package document that npm_candidates is handed; the stub below ignores it.
        self.packument = lambda url, headers: (200, b"{}")
        stubs = {"pinned_versions": lambda repo_dir: {"0.9.13", "0.9.14", "0.9.15"},
                 "npm_candidates": lambda pinned, fetch=None: list(self.candidates),
                 "verify_release": self.fake_verify}
        self.stubs = {}
        for name, function in stubs.items():
            patcher = mock.patch.object(release_checks, name, side_effect=function)
            self.stubs[name] = patcher.start()
            self.addCleanup(patcher.stop)

    def fake_verify(self, version):
        if version in self.down:
            raise release_checks.InfraError(*self.down[version])
        if version in self.bad:
            raise release_checks.ReleaseCheckError(*self.bad[version])
        return types.SimpleNamespace(version=version)

    def rules(self, git=None, refs=("refs/heads/main", "refs/tags/fleet-v8", "refs/tags/fleet-v8^{}"), drill=False):
        with contextlib.redirect_stdout(self.log):
            results = st.evaluate(git=git or repo(), gh=self.gh, repo_dir="/fake/marketplace", frozen=FROZEN, now=NOW,
                                  times=self.times, packument=self.packument, remote_refs=list(refs), drill=drill,
                                  actor="venuverse")
        return {item.rule: item for item in results}


class TestRuleI(StalenessCase):
    def test_a_passing_release_unpinned_for_a_day_is_red(self):
        self.candidates = ["0.9.16", "0.9.17"]
        self.times = {"0.9.16": stamp(dt.timedelta(hours=30)), "0.9.17": stamp(dt.timedelta(hours=2))}
        rules = self.rules()
        self.assertTrue(rules["staleness-i"].red)
        self.assertIn("`0.9.16`", rules["staleness-i"].detail)
        self.assertNotIn("0.9.17", rules["staleness-i"].detail)
        self.assertFalse(rules["staleness-i-refused"].red)
        self.assertFalse(rules["staleness-entry"].red)

    def test_the_rule_says_the_release_is_above_every_pin_main_included(self):
        # The pinned set is main's pin and every fleet-v tag's, so the text must not say only the tags'.
        self.candidates = ["0.9.16"]
        self.times = {"0.9.16": stamp(dt.timedelta(hours=30))}
        rule = self.rules()["staleness-i"]
        self.assertEqual(rule.title,
                         "staleness: npm has had a passing ai-tc release above every pin for over 24 hours")
        self.assertIn("above `0.9.15`, the highest version `main` or any `fleet-v` tag pins, that pass", rule.detail)
        self.assertNotIn("no `fleet-v` tag pins", rule.detail)

    def test_a_refused_version_is_named_once_it_has_been_on_npm_for_an_hour(self):
        self.candidates = ["0.9.16", "0.9.17"]
        self.bad = {"0.9.16": ("provenance", "ref refs/heads/release"), "0.9.17": ("commit-on-main", "behind")}
        self.times = {"0.9.16": stamp(dt.timedelta(hours=3)), "0.9.17": stamp(dt.timedelta(minutes=30))}
        refused = self.rules()["staleness-i-refused"]
        self.assertTrue(refused.red)
        self.assertIn("`0.9.16` (published", refused.detail)
        self.assertIn("the `provenance` check refused it", refused.detail)
        self.assertNotIn("0.9.17", refused.detail)

    def test_the_refused_detail_says_the_signing_certificate_names_the_branch(self):
        # Who signed a release is read from the signing certificate, not from the statement the
        # publisher wrote, so the explanation for a branch publish must name the certificate.
        self.candidates = ["0.9.16"]
        self.bad = {"0.9.16": ("provenance", "ref refs/heads/release")}
        self.times = {"0.9.16": stamp(dt.timedelta(hours=3))}
        refused = self.rules()["staleness-i-refused"]
        self.assertTrue(refused.red)
        self.assertIn("its signing certificate names a branch, not the version's tag", refused.detail)
        self.assertNotIn("its attestation binds", refused.detail)

    def test_the_detail_names_only_the_check_so_a_moving_ai_tc_main_does_not_comment_again(self):
        # A commit-on-main refusal names ai-tc's current main head, which changes on every push there. The router
        # comments on an open issue whenever its text changes, so the head must stay out of the detail.
        self.candidates = ["0.9.16"]
        self.times = {"0.9.16": stamp(dt.timedelta(hours=3))}
        details = []
        for head in ("a" * 40, "b" * 40):
            self.bad = {"0.9.16": ("commit-on-main", f"compare {'c' * 40}...{head} is 'diverged'")}
            details.append(self.rules()["staleness-i-refused"].detail)
        self.assertEqual(details[0], details[1])
        self.assertIn("the `commit-on-main` check refused it", details[0])
        self.assertNotIn("compare", details[0])
        self.assertNotIn("a" * 40, details[0])

    def test_the_full_refusal_goes_to_the_run_log(self):
        self.candidates = ["0.9.16"]
        self.times = {"0.9.16": stamp(dt.timedelta(minutes=10))}
        self.bad = {"0.9.16": ("commit-on-main", f"compare {'c' * 40}...{'a' * 40} is 'diverged'")}
        self.rules()
        self.assertIn(f"::warning::refused 0.9.16: commit-on-main: compare {'c' * 40}...{'a' * 40} is 'diverged'",
                      self.log.getvalue())

    def test_nothing_new_on_npm_is_green(self):
        rules = self.rules()
        self.assertFalse(rules["staleness-i"].red)
        self.assertFalse(rules["staleness-i-refused"].red)
        self.assertFalse(rules["staleness-i-no-verdict"].red)

    def test_a_removed_entry_is_red_and_rule_i_is_not_evaluated(self):
        rules = self.rules(repo(main_entry=False))
        self.assertTrue(rules["staleness-entry"].red)
        self.assertIsNone(rules["staleness-i"].red)
        self.assertIsNone(rules["staleness-i-refused"].red)
        self.assertIsNone(rules["staleness-i-no-verdict"].red)
        self.stubs["pinned_versions"].assert_not_called()


class TestRuleINoVerdict(StalenessCase):
    """A check that could not finish (the registry, the network, npm or GitHub failed) is no verdict on the
    release. It is its own result: never a refused version, and never a release that is gone, which would
    close the open issue of the rule that names it."""

    def test_an_outage_is_its_own_result_and_never_clears_rule_i(self):
        self.candidates = ["0.9.16"]
        self.times = {"0.9.16": stamp(dt.timedelta(hours=30))}
        self.down = {"0.9.16": ("toolchain", "npm install did not finish")}
        rules = self.rules()
        self.assertIsNone(rules["staleness-i"].red)
        self.assertIsNone(rules["staleness-i-refused"].red)
        unverified = rules["staleness-i-no-verdict"]
        self.assertTrue(unverified.red)
        self.assertEqual((unverified.kind, unverified.title),
                         ("alert", "staleness: the release checks reached no verdict on an ai-tc version"))
        self.assertIn("- `0.9.16` (published", unverified.detail)
        self.assertIn("the `toolchain` check did not finish", unverified.detail)

    def test_a_verdict_still_names_the_refused_version_beside_an_outage(self):
        self.candidates = ["0.9.16", "0.9.17"]
        self.bad = {"0.9.16": ("provenance", "ref refs/heads/release")}
        self.down = {"0.9.17": ("network", "registry answered 503")}
        self.times = {"0.9.16": stamp(dt.timedelta(hours=3)), "0.9.17": stamp(dt.timedelta(hours=3))}
        rules = self.rules()
        self.assertTrue(rules["staleness-i-refused"].red)
        self.assertIn("`0.9.16`", rules["staleness-i-refused"].detail)
        self.assertNotIn("0.9.17", rules["staleness-i-refused"].detail)
        self.assertTrue(rules["staleness-i-no-verdict"].red)
        self.assertIn("`0.9.17`", rules["staleness-i-no-verdict"].detail)
        self.assertNotIn("0.9.16", rules["staleness-i-no-verdict"].detail)
        self.assertIsNone(rules["staleness-i"].red)

    def test_a_passing_release_is_still_red_beside_an_outage(self):
        self.candidates = ["0.9.16", "0.9.17"]
        self.down = {"0.9.17": ("network", "registry answered 503")}
        self.times = {"0.9.16": stamp(dt.timedelta(hours=30)), "0.9.17": stamp(dt.timedelta(hours=3))}
        rules = self.rules()
        self.assertTrue(rules["staleness-i"].red)
        self.assertIn("`0.9.16`", rules["staleness-i"].detail)
        self.assertNotIn("0.9.17", rules["staleness-i"].detail)
        self.assertIsNone(rules["staleness-i-refused"].red)
        self.assertIn("`0.9.17`", rules["staleness-i-no-verdict"].detail)

    def test_an_outage_in_the_first_hour_is_not_reported(self):
        self.candidates = ["0.9.16"]
        self.down = {"0.9.16": ("network", "registry answered 503")}
        for age_of_release, reported in ((dt.timedelta(minutes=30), False), (dt.timedelta(hours=1), False),
                                         (dt.timedelta(hours=1, seconds=1), True)):
            with self.subTest(on_npm=age_of_release):
                self.times = {"0.9.16": stamp(age_of_release)}
                rules = self.rules()
                self.assertEqual(rules["staleness-i-no-verdict"].red, reported)
                self.assertEqual(rules["staleness-i"].red, None if reported else False)
                self.assertEqual(rules["staleness-i-refused"].red, None if reported else False)

    def test_a_version_the_run_ran_out_of_time_for_is_no_verdict_and_clears_nothing(self):
        # Once the run's time budget is spent, release_checks raises InfraError("deadline") for every version still
        # to check. That is an outage like any other: it must neither pass as a clear result nor as a refusal.
        self.candidates = ["0.9.16", "0.9.17"]
        self.times = {"0.9.16": stamp(dt.timedelta(hours=30)), "0.9.17": stamp(dt.timedelta(hours=5))}
        self.down = {"0.9.17": ("deadline", "this run's 2400 s time budget ran out before GET could start")}
        rules = self.rules()
        self.assertTrue(rules["staleness-i"].red)
        self.assertIn("`0.9.16`", rules["staleness-i"].detail)
        self.assertIsNone(rules["staleness-i-refused"].red)
        self.assertTrue(rules["staleness-i-no-verdict"].red)
        self.assertIn("- `0.9.17` (published", rules["staleness-i-no-verdict"].detail)
        self.assertIn("the `deadline` check did not finish", rules["staleness-i-no-verdict"].detail)
        self.assertNotIn("2400", rules["staleness-i-no-verdict"].detail)
        self.assertIn("::warning::no verdict on 0.9.17: deadline: this run's 2400 s time budget ran out",
                      self.log.getvalue())

    def test_the_detail_says_which_versions_hold_the_other_rules(self):
        # Only a version on npm for over an hour, or with no known publish time, is reported
        # and holds the other two rules (test_an_outage_in_the_first_hour_is_not_reported).
        # The text a person reads must not claim more than that.
        self.candidates = ["0.9.16"]
        self.down = {"0.9.16": ("network", "registry answered 503")}
        for label, times in (("over an hour", {"0.9.16": stamp(dt.timedelta(hours=5))}), ("no publish time", {})):
            with self.subTest(label):
                self.times = times
                detail = self.rules()["staleness-i-no-verdict"].detail
                self.assertIn("until every version that has been on npm for over an hour, or whose publish time is "
                              "unknown, has a verdict", detail)
                self.assertNotIn("until every version has a verdict", detail)

    def test_an_outage_on_a_version_with_no_publish_time_is_reported(self):
        self.candidates = ["0.9.16"]
        self.down = {"0.9.16": ("npm", "registry answered 503")}
        rule = self.rules()["staleness-i-no-verdict"]
        self.assertTrue(rule.red)
        self.assertIn("(published at an unknown time)", rule.detail)

    def test_the_detail_names_only_the_check_so_a_lasting_outage_comments_once_a_day(self):
        self.candidates = ["0.9.16"]
        self.times = {"0.9.16": stamp(dt.timedelta(hours=5))}
        details = []
        for text in ("npm install failed, log at /home/runner/.npm/_logs/2026-10-05T11_00_00_000Z-debug-0.log",
                     "npm install failed, log at /home/runner/.npm/_logs/2026-10-05T12_00_00_000Z-debug-0.log"):
            self.down = {"0.9.16": ("toolchain", text)}
            details.append(self.rules()["staleness-i-no-verdict"].detail)
        self.assertEqual(details[0], details[1])
        self.assertNotIn("_logs", details[0])
        self.assertNotIn("npm install failed", details[0])

    def test_the_full_error_goes_to_the_run_log(self):
        self.candidates = ["0.9.16"]
        self.times = {"0.9.16": stamp(dt.timedelta(minutes=10))}
        self.down = {"0.9.16": ("toolchain", "npm install did not finish within 300 s")}
        self.rules()
        self.assertIn("::warning::no verdict on 0.9.16: toolchain: npm install did not finish within 300 s",
                      self.log.getvalue())

    def test_the_router_opens_the_new_issue_and_leaves_rule_is_open_issue_alone(self):
        self.candidates = ["0.9.16"]
        self.times = {"0.9.16": stamp(dt.timedelta(hours=30))}
        self.down = {"0.9.16": ("network", "registry answered 503")}
        open_issue = {"number": 40, "created_at": "2026-10-05T01:00:00Z", "labels": [{"name": "staleness"}],
                      "assignees": [], "body": issue_router.marker("rule", "staleness-i") + "\nnpm has 0.9.16"}
        router_gh = FakeGitHub({("GET", R("issues")): [open_issue], ("POST", R("issues")): {"number": 41}})
        router = issue_router.Router(router_gh, approvers=["venuverse"], escalation=None, owners=["venuverse"],
                                     now=NOW, run_url="https://github.com/akasecurity/marketplace/actions/runs/9")
        # a pin change younger than an hour, so rule (iii) is clear and the new rule is the only one to file
        outcomes = [router.apply(item) for item in self.rules(repo(pin_change_age=dt.timedelta(minutes=30))).values()]
        self.assertEqual([call[:2] for call in router_gh.calls if call[0] != "GET"], [("POST", R("issues"))])
        self.assertEqual(router_gh.called("POST", R("issues"))[0][2]["title"],
                         "staleness: the release checks reached no verdict on an ai-tc version")
        self.assertIn("staleness-i: not evaluated this run; its issue is left as it is", outcomes)


class FullRefOnly(FakeGit):
    """A checkout where main is refs/remotes/origin/main and the bare name is a hazard: a tag named main
    resolves before the branch of that name, so reading "main" can point anywhere."""

    def main(self):
        return "refs/remotes/origin/main"

    def rev_parse(self, rev):
        if rev == "main":
            raise AssertionError("main was read by its bare name")
        return self.chain[-1] if rev == "refs/remotes/origin/main" else rev


def full_ref_only(base: FakeGit, *, tags=None) -> FullRefOnly:
    return FullRefOnly(chain=base.chain, files=base.files, times=base.times,
                       tags=base.tags if tags is None else tags, messages=base.messages)


class TestMainIsReadByItsFullRef(StalenessCase):
    """Each place that reads main is its own case, so that undoing one of them fails one test."""

    def test_the_entry_is_read_from_the_full_ref(self):
        for main_entry in (True, False):
            with self.subTest(main_entry=main_entry):
                with contextlib.redirect_stdout(self.log):
                    entry = st.entry_and_rule_i(full_ref_only(repo(main_entry=main_entry)), "/fake/marketplace",
                                                NOW, {}, self.packument)[0]
                self.assertEqual(entry.red, not main_entry)

    def test_the_untagged_pin_change_walk_starts_from_the_full_ref(self):
        rule = st.rule_iii(full_ref_only(repo()), FROZEN, NOW)
        self.assertTrue(rule.red)
        self.assertIn("`b` (ai-tc 0.9.15", rule.detail)


class Reply:
    """What the opener behind release_checks.http_fetch hands back for a 200 answer."""

    status = 200

    def __init__(self, document):
        self.body = json.dumps(document).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.body


class RunMain(StalenessCase):
    """staleness.main() over fakes: the git checkout and the GitHub API are fakes, the registry is whatever the
    test routes the opener to, and the results are the ones it hands the issue router."""

    def setUp(self):
        super().setUp()
        # No test here may reach the registry: each routes it somewhere of its own.
        opener = mock.patch.object(release_checks._OPENER, "open", side_effect=AssertionError("reached the network"))
        opener.start()
        self.addCleanup(opener.stop)
        self.addCleanup(release_checks.clear_budget)

    def run_main(self, git=None):
        written = {}
        with tempfile.TemporaryDirectory() as tmp:
            frozen = os.path.join(tmp, "frozen.json")
            with open(frozen, "w", encoding="utf-8") as handle:
                json.dump(FROZEN, handle)
            with mock.patch.object(st, "Git", return_value=git or repo(pin_change_age=dt.timedelta(minutes=30))), \
                    mock.patch.object(st, "GitHub", return_value=self.gh), \
                    mock.patch.object(st, "write_output", side_effect=lambda key, value: written.update({key: value})), \
                    mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO}), \
                    contextlib.redirect_stdout(self.log):
                code = st.main(["--repo-dir", "/fake/marketplace", "--frozen", frozen])
        return code, {item.rule: item for item in issue_router.results_from_json(written["results"])}


class TestOnePackumentRead(RunMain):
    """The registry serves the package document from a CDN cache, so a second read a moment after a publish can
    show a version the first did not. The publish times and the list of versions come from one read."""

    def test_one_packument_read_feeds_the_times_and_the_candidates(self):
        self.stubs["npm_candidates"].side_effect = REAL_NPM_CANDIDATES
        published = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        before = {"versions": {"0.9.15": {}}, "time": {"0.9.15": "2026-10-01T00:00:00.000Z"}}
        after = {"versions": {"0.9.15": {}, "0.9.16": {}},
                 "time": {"0.9.15": "2026-10-01T00:00:00.000Z", "0.9.16": published}}
        with mock.patch.object(release_checks._OPENER, "open", side_effect=[Reply(before), Reply(after)]) as opened:
            code, rules = self.run_main()
        self.assertEqual(code, 0)
        self.assertEqual([call.args[0].full_url for call in opened.call_args_list], [st.REGISTRY_URL])
        for rule in ("staleness-i", "staleness-i-refused", "staleness-i-no-verdict"):
            with self.subTest(rule):
                self.assertFalse(rules[rule].red)
        self.assertNotIn("0.9.16", "".join(item.detail for item in rules.values() if item.red))

    def test_the_publish_times_come_from_the_one_read(self):
        # The one read lists 0.9.16, published two minutes ago, and its checks pass. Its age is what keeps rule (i)
        # clear: had the times been dropped or read from anywhere else, 0.9.16 would read as published at an unknown
        # time, which counts as older than a day, and the rule would go red on a release minutes old.
        self.stubs["npm_candidates"].side_effect = REAL_NPM_CANDIDATES
        published = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        document = {"versions": {"0.9.15": {}, "0.9.16": {}},
                    "time": {"0.9.15": "2026-10-01T00:00:00.000Z", "0.9.16": published}}
        with mock.patch.object(release_checks._OPENER, "open", side_effect=[Reply(document)]) as opened:
            code, rules = self.run_main()
        self.assertEqual(code, 0)
        self.assertEqual([call.args[0].full_url for call in opened.call_args_list], [st.REGISTRY_URL])
        self.stubs["verify_release"].assert_called_once_with("0.9.16")
        for rule in ("staleness-i", "staleness-i-refused", "staleness-i-no-verdict"):
            with self.subTest(rule):
                self.assertFalse(rules[rule].red)

    def test_the_one_read_is_served_for_the_package_document_only(self):
        with mock.patch.object(release_checks, "http_fetch", return_value=(200, b"{}")) as fetched:
            reader = st.read_packument()
        fetched.assert_called_once_with(st.REGISTRY_URL, {"Accept": "application/json"})
        self.assertEqual(reader(st.REGISTRY_URL, {}), (200, b"{}"))
        with self.assertRaises(ValueError):
            reader("https://registry.npmjs.org/some-other-package", {})


class TestRunBudget(RunMain):
    """main() gives the run one time budget, so that a run which cannot finish says "no verdict" itself before
    GitHub cancels the job (the job is allowed 45 minutes, and the budget is shorter)."""

    def setUp(self):
        super().setUp()
        self.reads = []
        registry = mock.patch.object(release_checks, "http_fetch", side_effect=self.registry)
        registry.start()
        self.addCleanup(registry.stop)

    def registry(self, url, headers):
        self.reads.append(release_checks.time_left())
        return 200, json.dumps({"versions": {}, "time": {}}).encode()

    def test_the_run_starts_one_budget_of_about_forty_minutes(self):
        seen = []
        evaluate = st.evaluate

        def watching(*args, **kwargs):
            seen.append(release_checks.time_left())
            return evaluate(*args, **kwargs)

        with mock.patch.object(st, "evaluate", side_effect=watching), mock.patch.object(
            release_checks, "start_budget", wraps=release_checks.start_budget
        ) as started:
            code, _ = self.run_main()
        self.assertEqual(code, 0)
        started.assert_called_once_with(release_checks.BUDGET_STALENESS)
        self.assertEqual(release_checks.BUDGET_STALENESS, 40 * 60)
        # the registry read comes first and the rules after it: the budget is running for both
        self.assertEqual(len(self.reads) + len(seen), 2)
        for left in self.reads + seen:
            self.assertIsNotNone(left, "no budget was running while staleness worked")
            self.assertTrue(release_checks.BUDGET_STALENESS - 60 < left <= release_checks.BUDGET_STALENESS)

    def test_the_budget_ends_with_the_run_however_it_ends(self):
        for error in (release_checks.InfraError("network", "down"), release_checks.ReleaseCheckError("version", "no"),
                      KeyError("status"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(st, "evaluate", side_effect=error), self.assertRaises(type(error)):
                    self.run_main()
                self.assertIsNone(release_checks.time_left())
        self.run_main()
        self.assertIsNone(release_checks.time_left())


class TestOtherRules(StalenessCase):
    def test_rule_ii_names_bot_prs_open_for_more_than_a_day(self):
        self.pulls += [pull(30, "bot/pin-ai-tc-0.9.16", created_at=stamp(dt.timedelta(hours=25))),
                       pull(31, "bot/rollback-ai-tc-0.9.15-to-0.9.14", created_at=stamp(dt.timedelta(hours=1))),
                       pull(32, "feature/docs", created_at=stamp(dt.timedelta(hours=50)))]
        rule = self.rules()["staleness-ii"]
        self.assertTrue(rule.red)
        self.assertIn("#30", rule.detail)
        self.assertNotIn("#31", rule.detail)
        self.assertNotIn("#32", rule.detail)

    def test_rule_ii_counts_only_prs_the_release_bot_opened(self):
        old = stamp(dt.timedelta(hours=30))
        self.pulls += [pull(40, "bot/pin-ai-tc-0.9.16", created_at=old, author="a-person"),
                       pull(41, "bot/pin-ai-tc-0.9.17", created_at=old)]
        rule = self.rules()["staleness-ii"]
        self.assertTrue(rule.red)
        self.assertIn("#41", rule.detail)
        self.assertNotIn("#40", rule.detail)

    def test_rule_ii_is_green_for_a_persons_old_pr_from_a_bot_branch(self):
        self.pulls.append(pull(40, "bot/pin-ai-tc-0.9.16", created_at=stamp(dt.timedelta(hours=30)), author="a-person"))
        self.assertFalse(self.rules()["staleness-ii"].red)

    def test_rule_ii_counts_nothing_while_no_bot_login_is_configured(self):
        self.pulls.append(pull(41, "bot/pin-ai-tc-0.9.17", created_at=stamp(dt.timedelta(hours=30))))
        with mock.patch.object(release_checks, "BOT_LOGIN", None):
            rule = self.rules()["staleness-ii"]
        self.assertFalse(rule.red)

    def test_rule_iii_names_a_pin_change_left_untagged_for_an_hour(self):
        rule = self.rules()["staleness-iii"]
        self.assertTrue(rule.red)
        self.assertIn("`b` (ai-tc 0.9.15", rule.detail)
        self.assertFalse(self.rules(repo(pin_change_age=dt.timedelta(minutes=30)))["staleness-iii"].red)
        tagged = repo(tags=[fleet_tag(7, "t7"), fleet_tag(8, "t8"), fleet_tag(9, "b")])
        self.assertFalse(self.rules(tagged)["staleness-iii"].red)

    def test_rule_iii_never_looks_before_the_last_frozen_tag(self):
        # u moved the pin to 0.9.11 weeks ago and was never tagged, like a historical gap before
        # fleet-v8; it sits before the frozen list's last commit, so it never counts
        git = repo(pin_change_age=dt.timedelta(minutes=5))
        git.chain.insert(1, "u")
        git.files[("u", MANIFEST)] = manifest("0.9.11")
        git.times["u"] = int((NOW - dt.timedelta(days=20)).timestamp())
        self.assertFalse(self.rules(git)["staleness-iii"].red)

    def test_rule_iv_names_stray_tags_and_other_refs_named_main(self):
        refs = ("refs/heads/main", "refs/heads/feature/main", "refs/pull/12/head", "refs/tags/fleet-v8",
                "refs/tags/fleet-v8^{}", "refs/tags/x4-probe", "refs/tags/main", "refs/tags/main^{}",
                "refs/tags/fleet-v0", "refs/tags/fleet-v08")
        rule = self.rules(refs=refs)["staleness-iv"]
        self.assertTrue(rule.red)
        self.assertIn("`refs/tags/main`", rule.detail)
        self.assertIn("`refs/tags/x4-probe`", rule.detail)
        self.assertIn("`refs/tags/fleet-v0`", rule.detail)
        self.assertIn("`refs/tags/fleet-v08`", rule.detail)
        self.assertNotIn("`refs/tags/fleet-v8`", rule.detail)
        self.assertNotIn("feature/main", rule.detail)
        self.assertNotIn("refs/pull", rule.detail)
        self.assertFalse(self.rules()["staleness-iv"].red)

    def test_rollback_hold_is_a_notice_while_the_latest_tag_is_a_rollback(self):
        held = repo(tags=[fleet_tag(8, "t8"), fleet_tag(9, "a")],
                    messages={"fleet-v9": "fleet-v9: ai-tc 0.9.14\n\nversion: 0.9.14\nrollback-from: 0.9.15\n"})
        notice = self.rules(held)["staleness-rollback-hold"]
        self.assertEqual((notice.red, notice.kind, notice.extra_labels, notice.title),
                         (True, "notice", ["rollback-hold"], "rolled back, awaiting fix-forward"))
        self.assertIn("rollback from 0.9.15", notice.detail)
        self.assertFalse(self.rules()["staleness-rollback-hold"].red)

    def test_every_rule_is_reported_once_and_the_drill_is_red_only_on_request(self):
        rules = self.rules(drill=True)
        self.assertEqual(sorted(rules), sorted(st.TITLES))
        self.assertTrue(rules["staleness-drill"].red)
        self.assertIn("venuverse", rules["staleness-drill"].detail)
        self.assertFalse(self.rules()["staleness-drill"].red)

    def test_publish_times_reads_the_registry_document(self):
        seen = []
        times = st.publish_times(lambda url: seen.append(url) or {"time": {"0.9.16": "2026-10-04T10:00:00.000Z"}})
        self.assertEqual(seen, ["https://registry.npmjs.org/@akasecurity%2Fai-tc-claude-code"])
        self.assertEqual(times, {"0.9.16": "2026-10-04T10:00:00.000Z"})


class TestUnreadableManifests(StalenessCase):
    """A commit already on main never gets better, so a manifest that cannot be read must not fail every run."""

    def test_rule_iii_goes_on_past_a_commit_whose_manifest_cannot_be_read(self):
        for label, text in UNREADABLE_MANIFESTS.items():
            with self.subTest(label):
                git = repo()
                git.files[("a", MANIFEST)] = text
                self.log = io.StringIO()
                rule = self.rules(git)["staleness-iii"]
                self.assertTrue(rule.red)
                self.assertIn("`b` (ai-tc 0.9.15", rule.detail)
                self.assertNotIn("`a`", rule.detail)
                # The reason goes to the run log, one warning for the commit; the issue's text does not carry it.
                self.assertRegex(self.log.getvalue(), r"(?m)^::warning::.*at a cannot be read.*not counted")
                self.assertNotIn("cannot be read", rule.detail)

    def test_a_manifest_broken_for_one_commit_and_mended_to_the_same_version_is_no_pin_change(self):
        git = repo()
        git.files[("a", MANIFEST)] = "{"
        git.files[("b", MANIFEST)] = manifest("0.9.14")
        self.assertFalse(self.rules(git)["staleness-iii"].red)

    def test_a_manifest_on_main_that_cannot_be_read_is_red_and_rule_i_is_not_evaluated(self):
        for label, text in UNREADABLE_MANIFESTS.items():
            with self.subTest(label):
                git = repo()
                git.files[("b", MANIFEST)] = text
                rules = self.rules(git)
                self.assertTrue(rules["staleness-entry"].red)
                self.assertIn("at b cannot be read", rules["staleness-entry"].detail)
                self.assertNotIn("has no ai-tc entry", rules["staleness-entry"].detail)
                for rule in ("staleness-i", "staleness-i-refused", "staleness-i-no-verdict"):
                    self.assertIsNone(rules[rule].red)
                self.assertFalse(rules["staleness-iii"].red)
                self.stubs["pinned_versions"].assert_not_called()

    def test_the_issue_title_is_true_of_a_missing_entry_and_of_a_manifest_that_cannot_be_read(self):
        # One rule, one issue, whichever way main has no usable entry: the title has to say both, since the
        # router titles an issue when it opens it and never again.
        missing = self.rules(repo(main_entry=False))["staleness-entry"]
        broken_git = repo()
        broken_git.files[("b", MANIFEST)] = "{"
        broken = self.rules(broken_git)["staleness-entry"]
        self.assertIn("has no ai-tc entry", missing.detail)
        self.assertIn("cannot be read", broken.detail)
        for case in (missing, broken):
            with self.subTest(case.detail[:40]):
                self.assertTrue(case.red)
                self.assertIn("ai-tc entry is missing from main", case.title)
                self.assertIn("manifest cannot be read", case.title)
        self.assertEqual(missing.title, broken.title)

    def test_main_is_resolved_from_its_full_ref_before_its_manifest_is_read(self):
        git = full_ref_only(repo())
        git.files[("b", MANIFEST)] = "{"
        with contextlib.redirect_stdout(self.log):
            entry = st.entry_and_rule_i(git, "/fake/marketplace", NOW, {}, self.packument)[0]
        self.assertTrue(entry.red)
        self.assertIn("cannot be read", entry.detail)


class TestUnreadableManifestsRun(RunMain):
    def test_a_run_over_a_manifest_that_cannot_be_read_reports_it_and_ends_green(self):
        git = repo(pin_change_age=dt.timedelta(minutes=30))
        git.files[("a", MANIFEST)] = "[" * 100_000
        git.files[("b", MANIFEST)] = "{"
        with mock.patch.object(release_checks._OPENER, "open", side_effect=[Reply({"versions": {}, "time": {}})]):
            code, rules = self.run_main(git)
        self.assertEqual(code, 0)
        self.assertTrue(rules["staleness-entry"].red)
        self.assertIsNone(rules["staleness-i"].red)
        self.assertFalse(rules["staleness-iii"].red)


if __name__ == "__main__":
    unittest.main()
