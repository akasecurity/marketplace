"""Unit tests for validate_pr.py. No network: verify and classify are injected."""

from __future__ import annotations

import copy
import os
import unittest
from unittest import mock

import _testsupport as ts
import release_checks as rc
import validate_pr as vp

BOT = "aka-marketplace-bot[bot]"
NEXT = "0.9.15"
ATTESTED = {**ts.ATTESTED, NEXT: "f" * 40}
NEXT_ENTRY = {
    "classification": "not-rollback-safe",
    "from": ts.ATTESTED["0.9.14"],
    "to": ATTESTED[NEXT],
    "migrations": ["0036_migration"],
}


def verify(version):
    if version not in ATTESTED:
        raise rc.ReleaseCheckError("dist", f"npmjs does not serve {version}")
    return rc.VerifiedRelease(version, ts.INTEGRITY, ts.SHASUM, ATTESTED[version], ts.RUN_URL)


def classify(start, end):
    if end == ATTESTED[NEXT]:
        return rc.Classification("not-rollback-safe", ["0036_migration"])
    return rc.Classification("additive", [])


def files(doc, *, safety=None, agents=None, index=None):
    return {
        rc.MANIFEST: rc.dump_json(doc),
        ".agents/plugins/marketplace.json": rc.dump_json(agents or ts.AGENTS_MANIFEST),
        "plugins.json": rc.dump_json(index or ts.PLUGINS_INDEX),
        rc.SAFETY_FILE: rc.dump_json({"versions": ts.SEED if safety is None else safety}),
    }


def pull(**overrides):
    fields = dict(
        number=7,
        author=BOT,
        author_type="Bot",
        head_repo="akasecurity/marketplace",
        base_repo="akasecurity/marketplace",
        head_ref=f"bot/pin-ai-tc-{NEXT}",
        # What the importer's Git Data API commit carries: the App as author, GitHub's
        # web-flow as committer, and GitHub's verified signature.
        commits=({"sha": "e" * 40, "author": BOT, "committer": "web-flow", "verified": True},),
    )
    fields.update(overrides)
    return vp.PullRequest(**fields)


HUMAN = dict(author="venuverse", author_type="User", head_ref="docs/words", commits=())


def run(pr, base, head, changed, *, bot_login=BOT, pins=None, tip=None, tip_text=None, verify_fn=verify):
    if tip_text is None:
        tip_text = rc.dump_json({"versions": ts.SEED if tip is None else tip})
    return vp.evaluate(
        pr,
        base,
        head,
        sorted(changed),
        dict(ts.PINS) if pins is None else pins,
        tip_text,
        bot_login=bot_login,
        verify=verify_fn,
        classify=classify,
    )


def failed_with(testcase, report, text):
    testcase.assertTrue(any(text in f for f in report.failures), report.failures)


class TestEveryPrRules(unittest.TestCase):
    def human(self, head_doc=None, *, head_files=None, changed=(rc.MANIFEST,)):
        base = files(ts.manifest())
        head = head_files or files(head_doc or ts.manifest())
        return run(pull(**HUMAN), base, head, changed)

    def test_a_readme_only_pr_passes(self):
        report = self.human(changed=("README.md",))
        self.assertEqual((report.exit_code, report.failures), (0, []))
        self.assertIn(("Mode", "HUMAN PR, ai-tc entry unchanged"), report.rows)

    def test_a_missing_manifest_fails(self):
        head = files(ts.manifest())
        del head["plugins.json"]
        failed_with(self, self.human(head_files=head), "plugins.json is missing")

    def test_duplicate_keys_and_a_reformatted_manifest_fail(self):
        head = files(ts.manifest())
        head[".agents/plugins/marketplace.json"] = '{"name": "a", "name": "b", "plugins": []}'
        failed_with(self, self.human(head_files=head), "does not parse")
        head = files(ts.manifest())
        head[rc.MANIFEST] = rc.dump_json(ts.manifest())[:-1]  # the same JSON, one byte off the writer's format
        failed_with(self, self.human(head_files=head), "not in the one writer's format")

    def test_duplicate_plugin_names_fail(self):
        agents = copy.deepcopy(ts.AGENTS_MANIFEST)
        agents["plugins"].append(copy.deepcopy(agents["plugins"][0]))
        failed_with(self, self.human(head_files=files(ts.manifest(), agents=agents)), "repeated: preflight")

    def test_renames_naming_ai_tc_fail(self):
        head = ts.manifest()
        head["renames"] = {"ai-tc": "aitc"}
        failed_with(self, self.human(head), "a renames key or value names ai-tc")

    def test_top_level_keys_are_frozen(self):
        for key, value in (("name", "other"), ("forceRemoveDeletedPlugins", True), ("allowCrossMarketplaceDependenciesOn", ["x"])):
            with self.subTest(key):
                head = ts.manifest()
                head[key] = value
                failed_with(self, self.human(head), f"may change); changed: {key}")
        head = ts.manifest()
        head["metadata"]["pluginRoot"] = "./plugins"
        failed_with(self, self.human(head), "changed: metadata")

    def test_the_three_mutable_top_level_keys_may_change(self):
        head = ts.manifest()
        head["description"] = "New top-level description."
        head["metadata"]["description"] = "New words"
        head["metadata"]["version"] = "0.2.0"
        self.assertEqual(self.human(head).failures, [])

    def test_a_second_ai_tc_entry_fails(self):
        head = ts.manifest()
        head["plugins"].append(copy.deepcopy(head["plugins"][2]))
        failed_with(self, self.human(head), "exactly one entry named 'ai-tc'")

    def test_plugin_order_does_not_matter(self):
        head = ts.manifest()
        head["plugins"].reverse()
        self.assertEqual(self.human(head).failures, [])

    def test_a_base_that_does_not_parse_fails_closed(self):
        base = files(ts.manifest())
        base[rc.MANIFEST] = "{"
        report = run(pull(**HUMAN), base, files(ts.manifest()), ["README.md"])
        failed_with(self, report, "does not parse at the base")


def human_report(head_doc, *, base_doc=None, changed=(rc.MANIFEST,), head_safety=None):
    report = vp.Report()
    entries = vp.every_pr_rules(base_doc or ts.manifest(), head_doc, report)
    head = copy.deepcopy(ts.SEED) if head_safety is None else head_safety
    vp.human_rules(entries, copy.deepcopy(ts.SEED), head, sorted(changed), report, pinned={v for v in ts.PINS.values() if v})
    return report


class TestHumanRules(unittest.TestCase):
    def test_an_ai_tc_description_edit_passes_with_a_note(self):
        report = human_report(ts.manifest(description="Clearer words."))
        self.assertEqual(report.failures, [])
        self.assertIn(("Mode", "HUMAN PR, ai-tc description edit"), report.rows)
        self.assertTrue(any("change all four files" in n for n in report.notes))

    def test_a_perfect_advance_by_a_human_fails(self):
        report = human_report(ts.manifest("0.9.15", integrity=ts.OTHER_INTEGRITY))
        failed_with(self, report, "a human PR may change only the ai-tc entry's description")

    def test_a_registry_edit_fails(self):
        head = ts.manifest()
        ts.ai_tc(head)["source"]["registry"] = "https://registry.npmjs.org/"
        failed_with(self, human_report(head), "a human PR may change only")

    def test_adding_hooks_fails(self):
        head = ts.manifest()
        ts.ai_tc(head)["hooks"] = "./hooks/extra.json"
        failed_with(self, human_report(head), "a human PR may change only")

    def test_removing_the_entry_fails(self):
        head = ts.manifest()
        del head["plugins"][2]
        failed_with(self, human_report(head), "a human PR may change only")

    def test_an_edit_to_another_entry_passes(self):
        head = ts.manifest()
        head["plugins"][1]["description"] = "New words."
        self.assertEqual(human_report(head).failures, [])

    def test_a_human_edit_of_the_safety_file_is_called_out(self):
        head_safety = copy.deepcopy(ts.SEED)
        head_safety["0.9.14"]["classification"] = "additive"
        report = human_report(ts.manifest(), changed=(rc.SAFETY_FILE,), head_safety=head_safety)
        self.assertEqual(report.failures, [])
        self.assertIn(
            "LOWERS THE ROLLBACK FLOOR: HUMAN EDIT of rollback-safety.json 0.9.14: not-rollback-safe -> additive; "
            "the approving code owner owns this classification",
            report.notes,
        )

    def test_an_edit_that_does_not_lower_the_floor_is_not_labelled_so(self):
        head_safety = copy.deepcopy(ts.SEED)
        head_safety["0.9.13"]["classification"] = "not-rollback-safe"
        report = human_report(ts.manifest(), changed=(rc.SAFETY_FILE,), head_safety=head_safety)
        self.assertEqual(report.failures, [])
        self.assertIn(
            "HUMAN EDIT of rollback-safety.json 0.9.13: additive -> not-rollback-safe; "
            "the approving code owner owns this classification",
            report.notes,
        )
        self.assertFalse(any("LOWERS THE ROLLBACK FLOOR" in n for n in report.notes), report.notes)

    def test_a_hand_added_entry_for_a_version_nothing_pins_fails(self):
        head_safety = copy.deepcopy(ts.SEED)
        head_safety["0.9.15"] = copy.deepcopy(NEXT_ENTRY)
        report = human_report(ts.manifest(), changed=(rc.SAFETY_FILE,), head_safety=head_safety)
        failed_with(self, report, "rollback-safety.json gains 0.9.15, which nothing pins")
        failed_with(self, report, "never typed ahead of it")

    def test_an_entry_added_for_a_version_a_tag_pins_is_only_a_note(self):
        # 0.9.8 is pinned by fleet-v3, and the seed has no entry for it: a person may supply it.
        head_safety = {"0.9.8": copy.deepcopy(NEXT_ENTRY), **copy.deepcopy(ts.SEED)}
        report = human_report(ts.manifest(), changed=(rc.SAFETY_FILE,), head_safety=head_safety)
        self.assertEqual(report.failures, [])
        self.assertTrue(any("0.9.8: absent -> not-rollback-safe" in n for n in report.notes), report.notes)

    def test_a_human_added_entry_that_is_additive_for_a_pinned_version_lowers_the_floor(self):
        head_safety = {"0.9.8": {**copy.deepcopy(NEXT_ENTRY), "classification": "additive", "migrations": []}, **copy.deepcopy(ts.SEED)}
        report = human_report(ts.manifest(), changed=(rc.SAFETY_FILE,), head_safety=head_safety)
        self.assertEqual(report.failures, [])
        self.assertTrue(any(n.startswith("LOWERS THE ROLLBACK FLOOR: ") and "0.9.8: absent -> additive" in n for n in report.notes), report.notes)

    def test_evaluate_gives_a_human_pr_the_versions_main_and_the_tags_pin(self):
        head_safety = {**ts.SEED, "0.9.15": NEXT_ENTRY}
        report = run(pull(**HUMAN), files(ts.manifest()), files(ts.manifest(), safety=head_safety), [rc.SAFETY_FILE])
        failed_with(self, report, "rollback-safety.json gains 0.9.15, which nothing pins")
        pinned_now = run(pull(**HUMAN), files(ts.manifest()), files(ts.manifest(), safety=head_safety), [rc.SAFETY_FILE], pins={**ts.PINS, "main": "0.9.15"})
        self.assertEqual(pinned_now.failures, [])

    def test_removing_a_safety_entry_is_called_out(self):
        head_safety = copy.deepcopy(ts.SEED)
        del head_safety["0.9.9"]
        report = human_report(ts.manifest(), changed=(rc.SAFETY_FILE,), head_safety=head_safety)
        self.assertTrue(any("0.9.9: not-rollback-safe -> removed" in n for n in report.notes))

    def test_deleting_the_safety_file_fails(self):
        report = vp.Report()
        entries = vp.every_pr_rules(ts.manifest(), ts.manifest(), report)
        vp.human_rules(entries, copy.deepcopy(ts.SEED), None, [rc.SAFETY_FILE], report)
        failed_with(self, report, "rollback-safety.json must stay")

    def test_touching_automation_is_called_out(self):
        report = human_report(ts.manifest(), changed=(".github/workflows/validate.yml",))
        self.assertTrue(any(".github/workflows/validate.yml" in n for n in report.notes))

    def test_a_malformed_safety_file_is_reported(self):
        report = vp.Report()
        text = '{"versions": {"0.9.14": {"classification": "safe"}}}'
        self.assertIsNone(vp.safety_versions(text, report, label="the PR head"))
        failed_with(self, report, "at the PR head: rollback-safety.json '0.9.14'")

    def test_the_bot_hint_explains_an_unconfigured_identity(self):
        self.assertIn("release_checks.BOT_LOGIN is None", vp.bot_hint(pull(), None))
        self.assertIn("is not the marketplace bot App", vp.bot_hint(pull(author="dependabot[bot]"), BOT))
        self.assertEqual(vp.bot_hint(pull(**HUMAN), BOT), "")


def bot_report(
    head_doc, *, base_doc=None, pr=None, changed=None, base_safety=None, head_safety=None, tip=None, pins=None, verify_fn=verify
):
    report = vp.Report()
    entries = vp.every_pr_rules(base_doc or ts.manifest(), head_doc, report)
    vp.bot_rules(
        pr or pull(),
        entries,
        dict(ts.PINS) if pins is None else pins,
        copy.deepcopy(ts.SEED) if base_safety is None else base_safety,
        copy.deepcopy(ts.SEED) if head_safety is None else head_safety,
        copy.deepcopy(ts.SEED) if tip is None else tip,
        sorted(changed if changed is not None else [rc.MANIFEST]),
        report,
        bot_login=BOT,
        verify=verify_fn,
        classify=classify,
    )
    return report


FORWARD_SAFETY = {**ts.SEED, NEXT: NEXT_ENTRY}
ADDITIVE_TIP = {v: {**e, "classification": "additive"} for v, e in ts.SEED.items()}


class TestBotRules(unittest.TestCase):
    def advance(self, **overrides):
        kwargs = dict(changed=[rc.MANIFEST, rc.SAFETY_FILE], head_safety=copy.deepcopy(FORWARD_SAFETY))
        kwargs.update(overrides)
        return bot_report(ts.manifest(NEXT), **kwargs)

    def test_a_forward_pin_passes_and_reports_what_it_verified(self):
        report = self.advance()
        self.assertEqual(report.failures, [])
        for row in (
            ("Mode", "ADVANCE (bot PR)"),
            ("Pin", "`0.9.14` -> `0.9.15`"),
            ("Integrity", f"`{ts.INTEGRITY}`"),
            ("Attested commit", f"`{'f' * 40}`"),
            ("On ai-tc main", "yes"),
            ("Release run", ts.RUN_URL),
            ("Store migration", "not-rollback-safe (0036_migration)"),
        ):
            self.assertIn(row, report.rows)

    def test_the_wrong_head_ref_fails(self):
        failed_with(self, self.advance(pr=pull(head_ref="bot/pin-ai-tc-0.9.16")), "is not the advance branch")

    def test_a_fork_fails(self):
        failed_with(self, self.advance(pr=pull(head_repo="someone/marketplace")), "head repository must be akasecurity/marketplace")

    def test_a_pr_opened_by_anyone_else_fails(self):
        report = self.advance(pr=pull(author="venuverse", author_type="User"))
        failed_with(self, report, f"the PR is opened by venuverse (User), not by the bot App {BOT}")

    def test_a_head_ref_outside_bot_fails(self):
        failed_with(self, self.advance(pr=pull(head_ref=f"pin-ai-tc-{NEXT}")), "is not under refs/heads/bot/")

    def test_a_commit_by_anyone_else_fails(self):
        commits = (
            {"sha": "e" * 40, "author": BOT, "committer": "web-flow", "verified": True},
            {"sha": "d" * 40, "author": "venuverse", "committer": "venuverse", "verified": False},
        )
        report = self.advance(pr=pull(commits=commits))
        failed_with(self, report, f"commit dddddddddddd is authored by venuverse, not by {BOT}")
        failed_with(self, report, f"commit dddddddddddd is committed by venuverse: a bot commit's committer is {BOT}")
        self.assertFalse(any("eeeeeeeeeeee" in f for f in report.failures), report.failures)

    def test_an_unsigned_commit_fails_whoever_it_names_as_committer(self):
        # Naming the App as author and committer is two lines anyone who can push may write.
        for verified in (False, None):
            with self.subTest(verified=verified):
                commits = ({"sha": "e" * 40, "author": BOT, "committer": BOT, "verified": verified},)
                report = self.advance(pr=pull(commits=commits))
                failed_with(self, report, "commit eeeeeeeeeeee has no verified signature: a bot commit is one GitHub created for the App and signed")
                self.assertEqual(len(report.failures), 1, report.failures)

    def test_a_signed_commit_naming_the_app_as_committer_passes(self):
        commits = ({"sha": "e" * 40, "author": BOT, "committer": BOT, "verified": True},)
        self.assertEqual(self.advance(pr=pull(commits=commits)).failures, [])

    def test_a_web_flow_commit_needs_a_verified_signature(self):
        for verified in (False, None):
            commits = ({"sha": "e" * 40, "author": BOT, "committer": "web-flow", "verified": verified},)
            failed_with(self, self.advance(pr=pull(commits=commits)), "commit eeeeeeeeeeee is committed by web-flow without a verified signature")

    def test_a_signed_web_edit_by_a_person_fails(self):
        commits = ({"sha": "e" * 40, "author": "venuverse", "committer": "web-flow", "verified": True},)
        report = self.advance(pr=pull(commits=commits))
        failed_with(self, report, f"commit eeeeeeeeeeee is authored by venuverse, not by {BOT}")
        self.assertEqual(len(report.failures), 1, report.failures)

    def test_no_commits_fails(self):
        failed_with(self, self.advance(pr=pull(commits=())), "lists no commits")

    def test_an_extra_file_fails(self):
        failed_with(self, self.advance(changed=[rc.MANIFEST, rc.SAFETY_FILE, "README.md"]), "it also changes: README.md")

    def test_an_integrity_npm_does_not_serve_fails(self):
        report = bot_report(
            ts.manifest(NEXT, integrity=ts.OTHER_INTEGRITY),
            changed=[rc.MANIFEST, rc.SAFETY_FILE],
            head_safety=copy.deepcopy(FORWARD_SAFETY),
        )
        failed_with(self, report, "is not the integrity npmjs serves for 0.9.15")

    def test_a_release_that_fails_verification_fails(self):
        report = bot_report(ts.manifest("0.9.16"), pr=pull(head_ref="bot/pin-ai-tc-0.9.16"))
        failed_with(self, report, "0.9.16 fails the release checks (dist)")

    def test_a_missing_safety_entry_fails(self):
        failed_with(self, self.advance(head_safety=copy.deepcopy(ts.SEED)), "must gain exactly one entry, for 0.9.15")

    def test_a_wrong_safety_entry_fails(self):
        wrong = copy.deepcopy(FORWARD_SAFETY)
        wrong[NEXT]["classification"] = "additive"
        failed_with(self, self.advance(head_safety=wrong), "but validate computes")

    def test_a_forward_pin_may_not_rewrite_older_entries(self):
        rewritten = copy.deepcopy(FORWARD_SAFETY)
        rewritten["0.9.14"]["classification"] = "additive"
        failed_with(self, self.advance(head_safety=rewritten), "must gain exactly one entry, for 0.9.15, and change nothing else")

    def test_a_reimport_of_a_recorded_version_leaves_the_file_alone_and_says_so(self):
        report = bot_report(
            ts.manifest("0.9.14"),
            base_doc=ts.manifest("0.9.13"),
            pr=pull(head_ref="bot/pin-ai-tc-0.9.14"),
            pins={**ts.PINS, "main": "0.9.13"},
        )
        self.assertEqual(report.failures, [])
        self.assertTrue(any(n.startswith("RE-IMPORT: 0.9.14") for n in report.notes))
        # The recorded class is stronger than the computed one, so it stands.
        self.assertIn(("Store migration", "not-rollback-safe (recorded; validate computes additive)"), report.rows)

    def test_a_reimport_that_rewrites_its_recorded_entry_fails(self):
        rewritten = copy.deepcopy(ts.SEED)
        rewritten["0.9.14"]["classification"] = "additive"
        report = bot_report(
            ts.manifest("0.9.14"),
            base_doc=ts.manifest("0.9.13"),
            pr=pull(head_ref="bot/pin-ai-tc-0.9.14"),
            pins={**ts.PINS, "main": "0.9.13"},
            changed=[rc.MANIFEST, rc.SAFETY_FILE],
            head_safety=rewritten,
        )
        failed_with(self, report, "already records 0.9.14")

    def recorded_forward(self, entry, **overrides):
        """A forward PR for NEXT, which the base already records as `entry`; the file is left alone."""
        recorded = {**ts.SEED, NEXT: entry}
        kwargs = dict(base_safety=copy.deepcopy(recorded), head_safety=copy.deepcopy(recorded))
        kwargs.update(overrides)
        return bot_report(ts.manifest(NEXT), **kwargs)

    def test_a_recorded_entry_weaker_than_the_computed_one_fails(self):
        # validate computes not-rollback-safe for 0.9.15, so an entry that says additive was typed, not computed.
        entry = {"classification": "additive", "from": ts.ATTESTED["0.9.14"], "to": ATTESTED[NEXT], "migrations": []}
        report = self.recorded_forward(entry)
        failed_with(self, report, "records 0.9.15 as additive, but validate computes not-rollback-safe (0036_migration)")
        failed_with(self, report, "a code owner corrects the entry in a reviewed PR")

    def test_a_recorded_entry_for_another_commit_fails(self):
        entry = {**NEXT_ENTRY, "to": "2" * 40}
        failed_with(self, self.recorded_forward(entry), f"records 0.9.15 up to commit `{'2' * 40}`, but 0.9.15's attested commit is `{'f' * 40}`")

    def test_a_recorded_entry_that_matches_the_computation_passes(self):
        report = self.recorded_forward(NEXT_ENTRY)
        self.assertEqual(report.failures, [])
        self.assertFalse(any(n.startswith("rollback-safety.json records") for n in report.notes), report.notes)
        self.assertIn(("Store migration", "not-rollback-safe (recorded; validate computes not-rollback-safe)"), report.rows)

    def test_a_recorded_entry_stronger_than_the_computed_one_passes(self):
        # Fail-safe: validate computes additive for 0.9.13, and the recorded not-rollback-safe stands.
        report = bot_report(
            ts.manifest("0.9.13"),
            base_doc=ts.manifest("0.9.12"),
            pr=pull(head_ref="bot/pin-ai-tc-0.9.13"),
            pins={**ts.PINS, "main": "0.9.12"},
            base_safety={**ts.SEED, "0.9.13": {**ts.SEED["0.9.13"], "classification": "not-rollback-safe"}},
            head_safety={**ts.SEED, "0.9.13": {**ts.SEED["0.9.13"], "classification": "not-rollback-safe"}},
        )
        self.assertEqual(report.failures, [])
        self.assertIn(("Store migration", "not-rollback-safe (recorded; validate computes additive)"), report.rows)

    def test_a_different_starting_commit_is_only_a_note(self):
        entry = {**NEXT_ENTRY, "from": ts.ATTESTED["0.9.13"]}
        report = self.recorded_forward(entry)
        self.assertEqual(report.failures, [])
        self.assertTrue(any("records 0.9.15 from commit" in n and "only the commit it runs up to" in n for n in report.notes), report.notes)

    def test_an_outage_recomputing_a_recorded_entry_is_no_verdict(self):
        def down_below(version):
            if version == "0.9.14":
                raise rc.InfraError("network", "down")
            return verify(version)

        with self.assertRaises(rc.InfraError):
            self.recorded_forward(NEXT_ENTRY, verify_fn=down_below)

    def test_a_release_that_cannot_be_recomputed_fails(self):
        def gone_below(version):
            if version == "0.9.14":
                raise rc.ReleaseCheckError("dist", "npmjs does not serve 0.9.14")
            return verify(version)

        failed_with(self, self.recorded_forward(NEXT_ENTRY, verify_fn=gone_below), "could not compute 0.9.15's store-migration entry (dist)")

    def rollback(self, target="0.9.13", **overrides):
        kwargs = dict(pr=pull(head_ref=f"bot/rollback-ai-tc-0.9.14-to-{target}"), tip=copy.deepcopy(ADDITIVE_TIP))
        kwargs.update(overrides)
        return bot_report(ts.manifest(target), **kwargs)

    def test_a_rollback_above_the_floor_passes(self):
        report = self.rollback()
        self.assertEqual(report.failures, [])
        self.assertIn(("Mode", "ROLLBACK (bot PR)"), report.rows)
        self.assertIn(("Rollback floor", "none crossed"), report.rows)
        self.assertTrue(any(n.startswith("OLDER THAN 0.9.14: if 0.9.13") for n in report.notes), report.notes)

    def test_a_rollback_below_the_floor_fails(self):
        failed_with(self, self.rollback(tip=copy.deepcopy(ts.SEED)), "BELOW THE ROLLBACK FLOOR: 0.9.13 is below 0.9.14")
        # 0.9.14 is pinned (main, fleet-v8) but main's file has no entry for it: flagged, not safe.
        unrecorded = {v: e for v, e in ADDITIVE_TIP.items() if v != "0.9.14"}
        failed_with(self, self.rollback(tip=unrecorded), "BELOW THE ROLLBACK FLOOR: 0.9.13 is below 0.9.14")

    def test_the_floor_comes_from_main_not_from_the_pr(self):
        report = self.rollback(
            tip=copy.deepcopy(ts.SEED), head_safety=copy.deepcopy(ADDITIVE_TIP), changed=[rc.MANIFEST, rc.SAFETY_FILE]
        )
        failed_with(self, report, "BELOW THE ROLLBACK FLOOR")
        failed_with(self, report, "a bot rollback PR may change only .claude-plugin/marketplace.json")

    def test_a_rollback_to_a_version_no_tag_pinned_fails(self):
        failed_with(self, self.rollback("0.9.11"), "not a version any fleet-v tag has pinned")

    def test_a_rollback_without_a_readable_floor_fails(self):
        report = vp.Report()
        entries = vp.every_pr_rules(ts.manifest(), ts.manifest("0.9.13"), report)
        vp.bot_rules(
            pull(head_ref="bot/rollback-ai-tc-0.9.14-to-0.9.13"),
            entries,
            dict(ts.PINS),
            copy.deepcopy(ts.SEED),
            copy.deepcopy(ts.SEED),
            None,
            [rc.MANIFEST],
            report,
            bot_login=BOT,
            verify=verify,
            classify=classify,
        )
        failed_with(self, report, "no rollback floor can be read")

    def removed(self):
        doc = ts.manifest()
        del doc["plugins"][2]
        return doc

    def test_a_removal_on_its_branch_passes_without_verifying_anything(self):
        def never(version):
            raise AssertionError("a removal verifies no version")

        report = bot_report(self.removed(), pr=pull(head_ref="bot/remove-ai-tc-36123456789"), verify_fn=never)
        self.assertEqual(report.failures, [])
        self.assertTrue(any(n.startswith("REMOVE") for n in report.notes))

    def test_a_removal_on_another_branch_fails(self):
        failed_with(self, bot_report(self.removed(), pr=pull(head_ref="bot/remove-ai-tc-x")), "is not the remove branch")

    def test_a_restore_passes(self):
        report = bot_report(ts.manifest("0.9.14"), base_doc=self.removed(), pr=pull(head_ref="bot/restore-ai-tc-0.9.14"))
        self.assertEqual(report.failures, [])
        self.assertIn(("Mode", "RESTORE (bot PR)"), report.rows)

    def test_a_restore_below_the_floor_fails(self):
        report = bot_report(ts.manifest("0.9.13"), base_doc=self.removed(), pr=pull(head_ref="bot/restore-ai-tc-0.9.13"))
        failed_with(self, report, "BELOW THE ROLLBACK FLOOR: restoring 0.9.13 crosses 0.9.14")

    def test_a_bot_pr_with_a_human_shaped_diff_fails(self):
        report = bot_report(ts.manifest(description="Bot words."), pr=pull(head_ref="bot/pin-ai-tc-0.9.14"))
        failed_with(self, report, "must be exactly one importer mode's shape")

    def test_an_outage_is_no_verdict(self):
        def down(version):
            raise rc.InfraError("network", "down")

        with self.assertRaises(rc.InfraError):
            self.advance(verify_fn=down)


class TestEvaluate(unittest.TestCase):
    def forward(self, pr, **kwargs):
        head = files(ts.manifest(NEXT), safety=FORWARD_SAFETY)
        return run(pr, files(ts.manifest()), head, [rc.MANIFEST, rc.SAFETY_FILE], **kwargs)

    def test_a_bot_forward_pin_passes_end_to_end(self):
        report = self.forward(pull())
        self.assertEqual((report.exit_code, report.failures), (0, []))

    def test_without_a_configured_bot_the_same_pr_is_a_refused_human_pr(self):
        failed_with(self, self.forward(pull(), bot_login=None), "release_checks.BOT_LOGIN is None")

    def test_the_bot_login_on_a_user_account_is_not_the_bot(self):
        failed_with(self, self.forward(pull(author_type="User")), "a human PR may change only")

    def test_a_malformed_head_safety_file_fails_any_pr(self):
        head = files(ts.manifest())
        head[rc.SAFETY_FILE] = '{"versions": []}'
        failed_with(self, run(pull(**HUMAN), files(ts.manifest()), head, ["README.md"]), "at the PR head")

    def test_an_unparseable_main_safety_file_refuses_a_rollback(self):
        report = run(
            pull(head_ref="bot/rollback-ai-tc-0.9.14-to-0.9.13"),
            files(ts.manifest()),
            files(ts.manifest("0.9.13")),
            [rc.MANIFEST],
            tip_text="{",
        )
        failed_with(self, report, "no rollback floor can be read")

    def test_rules_stop_at_an_ambiguous_entry(self):
        head_doc = ts.manifest()
        head_doc["plugins"].append(copy.deepcopy(head_doc["plugins"][2]))
        report = run(pull(**HUMAN), files(ts.manifest()), files(head_doc), [rc.MANIFEST])
        self.assertEqual((report.rows, report.exit_code), ([], 1))


class TestSummary(unittest.TestCase):
    def test_a_pass_names_the_verdict_the_rows_and_the_run_to_confirm(self):
        report = vp.Report()
        report.row("Mode", "ADVANCE (bot PR)")
        text = vp.render_summary(report, 7)
        self.assertTrue(text.startswith("## validate: PR #7: PASS\n"))
        self.assertIn("confirm it is that workflow", text)
        self.assertIn("| Mode | ADVANCE (bot PR) |", text)
        self.assertTrue(text.endswith("\n"))

    def test_failures_notes_and_no_verdict_have_sections(self):
        report = vp.Report(infra="network: down")
        report.fail("one")
        report.note("two")
        text = vp.render_summary(report, 7)
        self.assertIn("## validate: PR #7: NO VERDICT", text)
        for section in ("### No verdict\n\n- network: down", "### Failures\n\n- one", "### Notes\n\n- two"):
            self.assertIn(section, text)

    def test_a_cell_cannot_break_the_table_and_no_line_can_start_a_command(self):
        report = vp.Report()
        report.row("Mode", "a|b")
        report.fail("first\n::error::injected")
        text = vp.render_summary(report, 7)
        self.assertIn("| Mode | a/b |", text)
        self.assertIn("- first ::error::injected", text)
        self.assertFalse(any(line.startswith("::") for line in text.splitlines()))

    def test_code_spans_cannot_be_escaped(self):
        self.assertEqual(vp._code("x`y\nz"), "`x'y z`")

    def test_exit_codes(self):
        self.assertEqual(vp.Report().exit_code, 0)
        failing = vp.Report()
        failing.fail("x")
        self.assertEqual(failing.exit_code, 1)
        self.assertEqual(vp.Report(infra="x").exit_code, 2)


class TestMain(unittest.TestCase):
    def setUp(self):
        self.repo = ts.Repo(self)
        base = files(ts.manifest())
        self.repo.commit(ts.manifest(), files={k: v for k, v in base.items() if k != rc.MANIFEST})
        self.repo.tag("fleet-v1")  # pins_by_ref refuses a checkout with no fleet-v tag
        self.summary = os.path.join(ts.Repo(self).path, "summary.md")

    def pr_commit(self, doc=None, extra=None):
        ts.git(self.repo.path, "checkout", "-q", "-b", "pr")
        head = self.repo.commit(doc, files=extra or {})
        ts.git(self.repo.path, "checkout", "-q", "main")
        return head

    def env(self, head, **overrides):
        values = dict(
            HEAD_SHA=head,
            PR_NUMBER="7",
            BASE_REPO="akasecurity/marketplace",
            HEAD_REPO="akasecurity/marketplace",
            HEAD_REF="docs/words",
            AUTHOR_LOGIN="venuverse",
            AUTHOR_TYPE="User",
            GITHUB_STEP_SUMMARY=self.summary,
        )
        values.update(overrides)
        return values

    COMMITS_URL = "https://api.github.com/repos/akasecurity/marketplace/pulls/7/commits?per_page=100&page=1"

    def commits(self, head, login="venuverse", *, committer=None, verified=False):
        """GET pulls/7/commits, shaped like the API's answer: one commit."""
        item = {
            "sha": head,
            "author": {"login": login},
            "committer": {"login": committer or login},
            "commit": {"verification": {"verified": verified, "reason": "valid" if verified else "unsigned"}},
        }
        return ts.FakeFetch({self.COMMITS_URL: (200, [item])})

    def main(self, head, fetch, **env):
        with mock.patch("sys.stdout"):
            return vp.main(repo=self.repo.path, env=self.env(head, **env), fetch=fetch, verify=verify, classify=classify)

    def summary_text(self):
        with open(self.summary, encoding="utf-8") as handle:
            return handle.read()

    def test_a_harmless_human_pr_passes_and_writes_the_summary(self):
        head = self.pr_commit(ts.manifest(), {"README.md": "hello\n"})
        self.assertEqual(self.main(head, self.commits(head)), 0)
        self.assertIn("## validate: PR #7: PASS", self.summary_text())

    def test_a_human_pin_edit_fails(self):
        doc = ts.manifest()
        ts.ai_tc(doc)["source"]["version"] = "0.9.13"
        head = self.pr_commit(doc)
        self.assertEqual(self.main(head, self.commits(head)), 1)
        self.assertIn("a human PR may change only", self.summary_text())

    def test_a_bot_forward_pin_passes(self):
        head = self.pr_commit(ts.manifest(NEXT), {rc.SAFETY_FILE: rc.dump_json({"versions": FORWARD_SAFETY})})
        fetch = self.commits(head, BOT, committer="web-flow", verified=True)
        with mock.patch.object(rc, "BOT_LOGIN", BOT):
            code = self.main(head, fetch, AUTHOR_LOGIN=BOT, AUTHOR_TYPE="Bot", HEAD_REF=f"bot/pin-ai-tc-{NEXT}")
        self.assertEqual(code, 0, self.summary_text())

    def test_pr_commits_reads_both_logins_and_the_signature_verdict(self):
        api = [
            {
                "sha": "e" * 40,
                "author": {"login": BOT},
                "committer": {"login": "web-flow"},
                "commit": {"verification": {"verified": True, "reason": "valid"}},
            },
            # No account matched the emails: GitHub answers null for both.
            {"sha": "d" * 40, "author": None, "committer": None, "commit": {"verification": {"verified": False, "reason": "unsigned"}}},
        ]
        fetch = ts.FakeFetch({self.COMMITS_URL: (200, api)})
        self.assertEqual(
            vp.pr_commits("akasecurity/marketplace", 7, fetch=fetch),
            [
                {"sha": "e" * 40, "author": BOT, "committer": "web-flow", "verified": True},
                {"sha": "d" * 40, "author": None, "committer": None, "verified": False},
            ],
        )

    def test_pr_commits_refuses_a_listing_that_reaches_githubs_cap(self):
        # GitHub lists at most 250 commits of a PR, so 100 + 100 + 50 may be a truncated listing.
        def page(n, count):
            item = lambda i: {"sha": f"{i:040x}", "author": {"login": "x"}, "committer": {"login": "x"}, "commit": {}}
            return (200, [item(n * 1000 + i) for i in range(count)])

        base = "https://api.github.com/repos/akasecurity/marketplace/pulls/7/commits?per_page=100&page="
        fetch = ts.FakeFetch({base + "1": page(1, 100), base + "2": page(2, 100), base + "3": page(3, 50)})
        with self.assertRaises(rc.InfraError) as caught:
            vp.pr_commits("akasecurity/marketplace", 7, fetch=fetch)
        self.assertIn("250", str(caught.exception.detail))

    def test_changed_files_are_the_pr_diff_from_the_merge_base(self):
        head = self.pr_commit(ts.manifest(), {"README.md": "hello\n"})
        self.repo.commit(files={"llms.txt": "moved on main\n"})
        start = ts.git(self.repo.path, "merge-base", "HEAD", head).strip()
        self.assertEqual(vp.changed_files(self.repo.path, start, head), ["README.md"])

    def test_a_non_hex_head_is_no_verdict(self):
        self.assertEqual(self.main("main", ts.FakeFetch()), 2)
        self.assertIn("NO VERDICT", self.summary_text())

    def test_an_unlistable_pr_is_no_verdict(self):
        head = self.pr_commit(ts.manifest(), {"README.md": "hello\n"})
        self.assertEqual(self.main(head, ts.FakeFetch()), 2)

    def test_a_manifest_that_is_not_utf8_fails(self):
        ts.git(self.repo.path, "checkout", "-q", "-b", "pr")
        with open(os.path.join(self.repo.path, rc.MANIFEST), "wb") as handle:
            handle.write(bytes([255, 254]))
        head = self.repo.commit()
        ts.git(self.repo.path, "checkout", "-q", "main")
        self.assertEqual(self.main(head, self.commits(head)), 1)
        self.assertIn("is not UTF-8", self.summary_text())

    def test_read_at_returns_none_for_an_absent_file(self):
        self.assertIsNone(vp.read_at(self.repo.path, "HEAD", "no/such/file.json"))
