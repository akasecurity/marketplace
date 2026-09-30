"""Tests for staleness.py: each rule, the rollback-hold notice and the drill."""
import datetime as dt
import types
import unittest
from unittest import mock

import release_checks
import staleness as st
from fakes import INTEGRITY, REPO, FakeGit, FakeGitHub, fleet_tag, manifest, pull, pulls_route
from release_checks import MANIFEST

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
        self.candidates, self.bad, self.pulls, self.times = [], {}, [], {}
        self.gh = FakeGitHub({("GET", R("pulls")): pulls_route(self.pulls)})
        stubs = {"pinned_versions": lambda repo_dir: {"0.9.13", "0.9.14", "0.9.15"},
                 "npm_candidates": lambda pinned: list(self.candidates),
                 "verify_release": self.fake_verify}
        self.stubs = {}
        for name, function in stubs.items():
            patcher = mock.patch.object(release_checks, name, side_effect=function)
            self.stubs[name] = patcher.start()
            self.addCleanup(patcher.stop)

    def fake_verify(self, version):
        if version in self.bad:
            raise release_checks.ReleaseCheckError(*self.bad[version])
        return types.SimpleNamespace(version=version)

    def rules(self, git=None, refs=("refs/heads/main", "refs/tags/fleet-v8", "refs/tags/fleet-v8^{}"), drill=False):
        results = st.evaluate(git=git or repo(), gh=self.gh, repo_dir="/fake/marketplace", frozen=FROZEN, now=NOW,
                              times=self.times, remote_refs=list(refs), drill=drill, actor="venuverse")
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

    def test_a_refused_version_is_named_once_it_has_been_on_npm_for_an_hour(self):
        self.candidates = ["0.9.16", "0.9.17"]
        self.bad = {"0.9.16": ("provenance", "ref refs/heads/release"), "0.9.17": ("commit-on-main", "behind")}
        self.times = {"0.9.16": stamp(dt.timedelta(hours=3)), "0.9.17": stamp(dt.timedelta(minutes=30))}
        refused = self.rules()["staleness-i-refused"]
        self.assertTrue(refused.red)
        self.assertIn("`0.9.16` (published", refused.detail)
        self.assertIn("provenance: ref refs/heads/release", refused.detail)
        self.assertNotIn("0.9.17", refused.detail)

    def test_nothing_new_on_npm_is_green(self):
        rules = self.rules()
        self.assertFalse(rules["staleness-i"].red)
        self.assertFalse(rules["staleness-i-refused"].red)

    def test_a_removed_entry_is_red_and_rule_i_is_not_evaluated(self):
        rules = self.rules(repo(main_entry=False))
        self.assertTrue(rules["staleness-entry"].red)
        self.assertIsNone(rules["staleness-i"].red)
        self.assertIsNone(rules["staleness-i-refused"].red)
        self.stubs["pinned_versions"].assert_not_called()


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
                "refs/tags/fleet-v8^{}", "refs/tags/x4-probe", "refs/tags/main", "refs/tags/main^{}")
        rule = self.rules(refs=refs)["staleness-iv"]
        self.assertTrue(rule.red)
        self.assertIn("`refs/tags/main`", rule.detail)
        self.assertIn("`refs/tags/x4-probe`", rule.detail)
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


if __name__ == "__main__":
    unittest.main()
