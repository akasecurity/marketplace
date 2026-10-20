"""Unit tests for validate_pr.py. No network: verify and classify are injected."""

from __future__ import annotations

import copy
import os
import pathlib
import re
import unittest
from unittest import mock

import _testsupport as ts
import release_checks as rc
import validate_pr as vp
from fakes import BOT

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
        failed_with(self, self.human(head_files=files(ts.manifest(), agents=agents)), "repeated: `preflight`")

    def test_renames_naming_ai_tc_fail(self):
        head = ts.manifest()
        head["renames"] = {"ai-tc": "aitc"}
        failed_with(self, self.human(head), "a renames key or value names ai-tc")

    def test_top_level_keys_are_frozen(self):
        for key, value in (("name", "other"), ("forceRemoveDeletedPlugins", True), ("allowCrossMarketplaceDependenciesOn", ["x"])):
            with self.subTest(key):
                head = ts.manifest()
                head[key] = value
                failed_with(self, self.human(head), f"may change); changed: `{key}`")
        head = ts.manifest()
        head["metadata"]["pluginRoot"] = "./plugins"
        failed_with(self, self.human(head), "changed: `metadata`")

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

    def test_a_description_that_is_not_a_non_empty_string_fails(self):
        removed = object()
        for bad in (None, 123, "", "   ", ["x"], {"text": "x"}, True, removed):
            with self.subTest(description=bad if bad is not removed else "key removed"):
                head = ts.manifest()
                if bad is removed:
                    del ts.ai_tc(head)["description"]
                else:
                    ts.ai_tc(head)["description"] = bad
                report = human_report(head)
                failed_with(self, report, "the ai-tc entry's description must be a non-empty string")
                self.assertEqual(report.exit_code, 1)
                self.assertIn(("Mode", "HUMAN PR, ai-tc description edit"), report.rows)

    def test_the_description_failure_gives_the_reason_that_is_true(self):
        # Claude Code refuses a null or non-string description but accepts an empty, a blank or a
        # missing one, so the rule is the marketplace's own and the message must not say otherwise.
        for bad in (None, 123, ""):
            with self.subTest(description=bad):
                head = ts.manifest()
                ts.ai_tc(head)["description"] = bad
                report = human_report(head)
                messages = [f for f in report.failures if "description must be a non-empty string" in f]
                self.assertEqual(len(messages), 1, report.failures)
                self.assertIn("this marketplace requires one", messages[0])
                self.assertIn("Claude Code itself refuses a null or non-string description", messages[0])
                self.assertNotIn("anything else", messages[0])
                # Claude Code still adds a marketplace whose entry has such a description (checked
                # against a real install), and lists that one entry as unsupported with a schema
                # error, so the message must not say the manifest breaks the add for every user.
                self.assertIn("lists ai-tc as unsupported with a schema error", messages[0])
                self.assertNotIn("breaks", messages[0])
                self.assertNotIn("every user", messages[0])

    def test_a_description_that_is_a_string_with_words_in_it_passes(self):
        for good in ("Clearer words.", "  padded  ", "x", "Ünïcode ✓"):
            with self.subTest(description=good):
                report = human_report(ts.manifest(description=good))
                self.assertEqual((report.exit_code, report.failures), (0, []))

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
            "the approving reviewer owns this classification",
            report.notes,
        )

    def test_an_edit_that_does_not_lower_the_floor_is_not_labelled_so(self):
        head_safety = copy.deepcopy(ts.SEED)
        head_safety["0.9.13"]["classification"] = "not-rollback-safe"
        report = human_report(ts.manifest(), changed=(rc.SAFETY_FILE,), head_safety=head_safety)
        self.assertEqual(report.failures, [])
        self.assertIn(
            "HUMAN EDIT of rollback-safety.json 0.9.13: additive -> not-rollback-safe; "
            "the approving reviewer owns this classification",
            report.notes,
        )
        self.assertFalse(any("LOWERS THE ROLLBACK FLOOR" in n for n in report.notes), report.notes)

    def edited_safety_entry(self, version, **changes):
        head_safety = copy.deepcopy(ts.SEED)
        head_safety[version].update(changes)
        return human_report(ts.manifest(), changed=(rc.SAFETY_FILE,), head_safety=head_safety)

    def test_an_edit_that_keeps_the_class_names_the_fields_it_changes(self):
        other = "c" * 40
        for changes, fields in (
            ({"migrations": []}, "migrations"),
            ({"from": other}, "from"),
            ({"to": other}, "to"),
            ({"from": other, "to": other, "migrations": ["0001_other"]}, "from, to, migrations"),
        ):
            with self.subTest(fields=fields):
                report = self.edited_safety_entry("0.9.14", **changes)
                self.assertEqual((report.exit_code, report.failures), (0, []))
                self.assertIn(
                    f"HUMAN EDIT of rollback-safety.json 0.9.14: not-rollback-safe -> not-rollback-safe "
                    f"(class unchanged; changes {fields}); the approving reviewer owns this classification",
                    report.notes,
                )

    def test_an_edit_that_changes_the_class_and_more_names_the_rest(self):
        report = self.edited_safety_entry("0.9.14", classification="additive", migrations=[])
        self.assertEqual(report.failures, [])
        self.assertIn(
            "LOWERS THE ROLLBACK FLOOR: HUMAN EDIT of rollback-safety.json 0.9.14: not-rollback-safe -> additive "
            "(also changes migrations); the approving reviewer owns this classification",
            report.notes,
        )

    def test_an_edit_that_only_moves_the_class_names_no_other_field(self):
        report = self.edited_safety_entry("0.9.14", classification="additive")
        self.assertFalse(any("changes" in n for n in report.notes), report.notes)

    def test_an_entry_added_or_removed_names_no_field(self):
        head_safety = {"0.9.8": copy.deepcopy(NEXT_ENTRY), **copy.deepcopy(ts.SEED)}
        added = human_report(ts.manifest(), changed=(rc.SAFETY_FILE,), head_safety=head_safety)
        removed_safety = copy.deepcopy(ts.SEED)
        del removed_safety["0.9.9"]
        removed = human_report(ts.manifest(), changed=(rc.SAFETY_FILE,), head_safety=removed_safety)
        for report in (added, removed):
            self.assertTrue(any("HUMAN EDIT" in n for n in report.notes), report.notes)
            self.assertFalse(any("changes" in n for n in report.notes), report.notes)

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
        # 0.9.8 is pinned by fleet-v3 alone, not by main: a version only a tag pins is accepted too.
        tag_only = run(pull(**HUMAN), files(ts.manifest()), files(ts.manifest(), safety={"0.9.8": NEXT_ENTRY, **ts.SEED}), [rc.SAFETY_FILE])
        self.assertEqual(tag_only.failures, [])

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
        failed_with(self, report, "at the PR head: `rollback-safety.json '0.9.14'")

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

    def test_the_pusher_note_says_what_the_commit_listing_lacks(self):
        # GitHub does record who pushed a branch (its activity API), so the note must not say the API exposes
        # no pusher; what validate lacks is the pull request's commit listing, which names no pusher.
        notes = [note for note in self.advance().notes if note.startswith("Who pushed each commit")]
        self.assertEqual(len(notes), 1, notes)
        self.assertIn("bot-branches ruleset", notes[0])
        self.assertIn("validate does not check it", notes[0])
        self.assertIn("commit listing names authors and committers, not pushers", notes[0])
        self.assertNotIn("exposes no pusher", notes[0])

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
        failed_with(self, self.advance(changed=[rc.MANIFEST, rc.SAFETY_FILE, "README.md"]), "it also changes: `README.md`")

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
        failed_with(self, report, "a person corrects the entry in a reviewed PR")

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


def nested(levels):
    """JSON `levels` lists deep, built as text: json.dumps would recurse as deeply as it nests."""
    return "[" * levels + "]" * levels


class TestDeepJson(unittest.TestCase):
    """A file a pull request supplies that nests too deeply is a file that does not parse: a failed
    check with a summary, not a stack trace and not a missing verdict."""

    def test_the_depth_limit_is_exact(self):
        self.assertEqual(vp._depth(rc.parse_json(nested(vp.MAX_JSON_DEPTH))), vp.MAX_JSON_DEPTH)
        self.assertEqual(vp._depth(rc.parse_json(nested(vp.MAX_JSON_DEPTH + 1))), vp.MAX_JSON_DEPTH + 1)
        self.assertEqual(vp._depth({"a": [{"b": [1]}], "c": []}), 4)
        self.assertEqual(vp._depth([]), 1)
        self.assertEqual(vp._depth(7), 0)
        vp.parse_pr_json(nested(vp.MAX_JSON_DEPTH))
        with self.assertRaises(ValueError):
            vp.parse_pr_json(nested(vp.MAX_JSON_DEPTH + 1))

    def test_a_real_manifest_is_far_below_the_limit(self):
        self.assertLess(vp._depth(ts.manifest()), vp.MAX_JSON_DEPTH // 4)

    def test_nesting_past_the_parser_and_nesting_inside_it_both_fail_to_parse(self):
        # 100,000 levels end the JSON parser itself in RecursionError, which rc.parse_json reports
        # as a ValueError of its own. 2,000 parse, and would end the code that reads the parsed
        # value (comparisons, the rename search) instead, so validate's depth limit refuses them.
        for levels in (vp.MAX_JSON_DEPTH + 1, 2000, 100_000):
            reason = "too deeply nested" if levels == 100_000 else "nests deeper"
            with self.subTest(levels=levels):
                deep = '{"renames": %s, "plugins": []}' % nested(levels)
                for path in (rc.MANIFEST, ".agents/plugins/marketplace.json", "plugins.json"):
                    head = files(ts.manifest())
                    head[path] = deep
                    report = run(pull(**HUMAN), files(ts.manifest()), head, [path])
                    failed_with(self, report, f"{path} does not parse at the PR head")
                    failed_with(self, report, reason)
                    self.assertEqual((report.exit_code, report.infra), (1, ""))
                head = files(ts.manifest())
                head[rc.SAFETY_FILE] = '{"versions": %s}' % nested(levels)
                report = run(pull(**HUMAN), files(ts.manifest()), head, [rc.SAFETY_FILE])
                failed_with(self, report, "rollback-safety.json does not parse at the PR head")
                self.assertEqual((report.exit_code, report.infra), (1, ""))

    def test_a_deep_file_does_not_hide_a_second_problem(self):
        head = files(ts.manifest())
        head[rc.SAFETY_FILE] = '{"versions": %s}' % nested(100_000)
        doc = ts.manifest()
        ts.ai_tc(doc)["source"]["version"] = "0.9.13"
        head[rc.MANIFEST] = rc.dump_json(doc)
        report = run(pull(**HUMAN), files(ts.manifest()), head, [rc.MANIFEST, rc.SAFETY_FILE])
        failed_with(self, report, "rollback-safety.json does not parse at the PR head")
        failed_with(self, report, "a human PR may change only")


EXTRA = ".github/workflows/extra.yml"
WORKFLOWS_DIR = pathlib.Path(__file__).resolve().parents[1] / "workflows"


def workflow_text(job="build", *, name=None, top=None, job_extra="", step="- run: echo hello", bare=False):
    """A small workflow in the plain block style this repository's own workflows use. It declares
    `permissions: {}` at the top unless `top` says otherwise or `bare` leaves permissions out."""
    lines = ["name: extra", "", "on: pull_request", ""]
    top = "" if bare else ("permissions: {}" if top is None else top)
    if top:
        lines += [top, ""]
    lines += ["jobs:", f"  {job}:"]
    if name is not None:
        lines.append(f"    name: {name}")
    lines.append("    runs-on: ubuntu-latest")
    if job_extra:
        lines.append(job_extra)
    lines += ["    steps:", f"      {step}", ""]
    return "\n".join(lines)


def workflow_pr(text, *, path=EXTRA, pr=None, extra_changed=()):
    """validate's report for a PR that adds one workflow file and nothing else."""
    head = files(ts.manifest())
    head[path] = text
    return run(pr or pull(**HUMAN), files(ts.manifest()), head, [path, *extra_changed])


class TestWorkflowFiles(unittest.TestCase):
    """A workflow file a PR adds or changes is read as text, never run. Any job named validate
    satisfies the required check, so a PR that defines one, or that lets a job create a check
    run or status of that name, fails; a file the scan cannot read with confidence fails too."""

    def assert_refused(self, text, fragment, *, path=EXTRA):
        report = workflow_pr(text, path=path)
        failed_with(self, report, fragment)
        self.assertEqual((report.exit_code, report.infra), (1, ""))
        return report

    def test_a_job_id_of_validate_fails_in_both_extensions(self):
        for path in (".github/workflows/extra.yml", ".github/workflows/extra.yaml", ".github/workflows/EXTRA.YML"):
            with self.subTest(path=path):
                report = self.assert_refused(workflow_text("validate"), "defines a job with the id validate", path=path)
                failed_with(self, report, f"`{path}` defines")
                failed_with(self, report, "so only .github/workflows/validate.yml may have one")

    def test_a_job_id_spelled_another_way_still_fails(self):
        for job in ('"validate"', "'validate'", "Validate", "VALIDATE", "validate "):
            with self.subTest(job=job):
                self.assert_refused(workflow_text(job), "defines a job with the id validate")

    def test_a_job_name_of_validate_fails_in_both_extensions(self):
        for path in (".github/workflows/extra.yml", ".github/workflows/extra.yaml"):
            with self.subTest(path=path):
                self.assert_refused(workflow_text(name="validate"), "names job `build` validate", path=path)

    def test_a_job_name_spelled_another_way_still_fails(self):
        for name in ('"validate"', "'validate'", "Validate", "validate # the required one", "&label validate", "!!str validate", '" validate "'):
            with self.subTest(name=name):
                self.assert_refused(workflow_text(name=name), "names job `build` validate")

    def test_the_failure_quotes_a_job_id_the_pr_wrote(self):
        report = workflow_pr(workflow_text("a`b|c", name="validate"))
        failed_with(self, report, "names job `a'b|c` validate")
        self.assertFalse(any("`a`b" in failure for failure in report.failures))

    def test_a_workflow_that_may_create_a_check_run_or_status_fails(self):
        grants = {
            "top level": dict(top="permissions:\n  checks: write"),
            "statuses": dict(top="permissions:\n  statuses: write"),
            "one job": dict(job_extra="    permissions:\n      checks: write"),
            "mixed in": dict(top="permissions:\n  contents: read\n  statuses: write\n  issues: read"),
            "flow": dict(top="permissions: {checks: write}"),
            "flow, quoted": dict(top="permissions: { 'statuses': \"write\", contents: read }"),
            "quoted key": dict(top='permissions:\n  "checks": "write"'),
            "write-all": dict(top="permissions: write-all"),
            "write-all, job": dict(job_extra="    permissions: write-all"),
            "app token action input": dict(step="- uses: actions/create-github-app-token@v3\n        with:\n          permission-checks: write"),
            "app token action input, statuses": dict(step="- uses: actions/create-github-app-token@v3\n        with:\n          permission-statuses: write"),
        }
        for label, kwargs in grants.items():
            with self.subTest(label):
                self.assert_refused(workflow_text(**kwargs), "writes checks: write, statuses: write or write-all out plainly")

    def test_a_workflow_that_may_approve_a_pull_request_fails(self):
        # With "Allow GitHub Actions to create and approve pull requests" on, the workflow token's approval counts
        # toward the one the main ruleset needs, and `github-actions[bot]` has write access. Neither the setting nor
        # the grant can be audited from the repository, so the grant is refused where a PR would add it.
        grants = {
            "top level": dict(top="permissions:\n  pull-requests: write"),
            "one job": dict(job_extra="    permissions:\n      pull-requests: write"),
            "mixed in": dict(top="permissions:\n  contents: read\n  pull-requests: write\n  issues: read"),
            "flow": dict(top="permissions: {pull-requests: write}"),
            "flow, quoted": dict(top="permissions: { 'pull-requests': \"write\", contents: read }"),
            "quoted key": dict(top='permissions:\n  "pull-requests": "write"'),
        }
        for label, kwargs in grants.items():
            with self.subTest(label):
                report = self.assert_refused(workflow_text(**kwargs), "writes pull-requests: write out plainly")
                failed_with(self, report, "approve a pull request")

    APP_TOKEN = "- uses: actions/create-github-app-token@v3\n        with:\n          permission-pull-requests: write"
    BOT_JOB = "    environment: marketplace-bot"

    def test_the_app_token_input_for_pull_requests_is_allowed_only_in_the_importer_in_the_bot_environment(self):
        # The input mints the release bot's own token. Whether a pull request can reach the secrets behind it rests
        # on where they are stored, which nothing in the repository can read, so the carve-out is as narrow as
        # the importer's own job: that one file, and only in a job that enters the marketplace-bot environment.
        allowed = workflow_pr(workflow_text(step=self.APP_TOKEN, job_extra=self.BOT_JOB), path=vp.IMPORTER_WORKFLOW)
        self.assertEqual((allowed.exit_code, allowed.failures), (0, []))
        refused = {
            "another workflow, with the environment": dict(path=".github/workflows/extra.yml", job_extra=self.BOT_JOB),
            "the importer, without the environment": dict(path=vp.IMPORTER_WORKFLOW, job_extra=""),
            "the importer, in another environment": dict(path=vp.IMPORTER_WORKFLOW, job_extra="    environment: production"),
            "a workflow with no environment, as a pull request would write it": dict(path=".github/workflows/extra.yml", job_extra=""),
        }
        for label, kwargs in refused.items():
            with self.subTest(label):
                report = self.assert_refused(workflow_text(step=self.APP_TOKEN, job_extra=kwargs["job_extra"]),
                                             "asks the App-token action for pull-requests: write", path=kwargs["path"])
                failed_with(self, report, "marketplace-bot")

    SECOND_JOB = ("  second:\n    permissions:\n      contents: read\n    runs-on: ubuntu-latest\n    steps:\n"
                  "      - uses: actions/create-github-app-token@v3\n        with:\n"
                  "          permission-pull-requests: write\n")

    def test_the_carve_out_belongs_to_the_job_that_enters_the_environment_not_to_the_file(self):
        # A second job that asks for the token without entering the environment is not gated by its deployment rule,
        # whatever another job in the same file enters.
        text = workflow_text(step=self.APP_TOKEN, job_extra=self.BOT_JOB) + self.SECOND_JOB
        report = self.assert_refused(text, "asks the App-token action for pull-requests: write", path=vp.IMPORTER_WORKFLOW)
        failed_with(self, report, "only in a job that itself enters the marketplace-bot environment")
        both = workflow_text(step=self.APP_TOKEN, job_extra=self.BOT_JOB) + self.SECOND_JOB.replace(
            "    permissions:\n", f"    environment: marketplace-bot\n    permissions:\n")
        allowed = workflow_pr(both, path=vp.IMPORTER_WORKFLOW)
        self.assertEqual((allowed.exit_code, allowed.failures), (0, []))

    def test_words_in_a_script_do_not_stand_for_the_environment(self):
        script = ("- run: |\n          cat <<Y\n          environment: marketplace-bot\n          Y\n"
                  "      - uses: actions/create-github-app-token@v3\n        with:\n"
                  "          permission-pull-requests: write")
        self.assert_refused(workflow_text(step=script), "asks the App-token action for pull-requests: write",
                            path=vp.IMPORTER_WORKFLOW)

    def test_an_app_token_request_outside_every_job_is_refused_in_the_importer(self):
        text = workflow_text(step=self.APP_TOKEN, job_extra=self.BOT_JOB) + "# kept\nenv:\n  permission-pull-requests: write\n"
        self.assert_refused(text, "asks the App-token action for pull-requests: write", path=vp.IMPORTER_WORKFLOW)

    def test_the_environment_is_read_in_the_forms_github_documents(self):
        entering = {
            "a plain value": "    environment: marketplace-bot",
            "a quoted value": '    environment: "marketplace-bot"',
            "a single-quoted value": "    environment: 'marketplace-bot'",
            "a quoted key": '    "environment": marketplace-bot',
            "a name under it": "    environment:\n      name: marketplace-bot",
            "a name and a url under it": "    environment:\n      url: https://example.org\n      name: marketplace-bot",
            "a quoted name under it": "    environment:\n      \"name\": 'marketplace-bot'",
        }
        for label, job_extra in entering.items():
            with self.subTest(label):
                report = workflow_pr(workflow_text(step=self.APP_TOKEN, job_extra=job_extra), path=vp.IMPORTER_WORKFLOW)
                self.assertEqual((report.exit_code, report.failures), (0, []))
        other = {
            "another environment": "    environment: production",
            "another name under it": "    environment:\n      name: production",
            "the right name nested one level too deep": "    environment:\n      extra:\n        name: marketplace-bot",
            "flow style": "    environment: {name: marketplace-bot}",
            "an expression": "    environment: ${{ inputs.target }}",
            "a similar name": "    environment: marketplace-bot-2",
        }
        for label, job_extra in other.items():
            with self.subTest(label):
                self.assert_refused(workflow_text(step=self.APP_TOKEN, job_extra=job_extra),
                                    "asks the App-token action", path=vp.IMPORTER_WORKFLOW)
        on_a_step = workflow_text(step=self.APP_TOKEN + "\n        environment: marketplace-bot")
        self.assert_refused(on_a_step, "asks the App-token action", path=vp.IMPORTER_WORKFLOW)

    def test_an_unreadable_validate_yml_is_refused_like_any_other_file(self):
        # validate.yml may define the job named validate, and that is all it is exempt from.
        unread = "name: validate\non: pull_request_target\njobs: {validate: {runs-on: x}}\n"
        for path in (vp.VALIDATE_WORKFLOW, EXTRA):
            with self.subTest(path=path):
                self.assert_refused(unread, "is written in a form this check does not read", path=path)
        bare = "name: validate\non: pull_request_target\njobs:\n  validate:\n    runs-on: x\n"
        self.assert_refused(bare, "declares no top-level permissions", path=vp.VALIDATE_WORKFLOW)
        self.assertEqual(workflow_pr(bare.replace("jobs:", "permissions: {}\njobs:"), path=vp.VALIDATE_WORKFLOW).failures, [])

    def test_a_key_a_job_spells_twice_is_unreadable_whichever_comes_first(self):
        # Neither the first nor the last of two `name:` or `environment:` keys is taken to be the one in force, the
        # way a duplicate key in a manifest is refused instead of resolved.
        duplicated = {
            "the first name is validate": "    name: validate\n    name: build",
            "the last name is validate": "    name: build\n    name: validate",
            "two other names": "    name: one\n    name: two",
            "the bot environment first": "    environment: marketplace-bot\n    environment: production",
            "the bot environment last": "    environment: production\n    environment: marketplace-bot",
            "another key": "    timeout-minutes: 5\n    timeout-minutes: 6",
        }
        for label, job_extra in duplicated.items():
            with self.subTest(label):
                report = self.assert_refused(workflow_text(job_extra=job_extra, step=self.APP_TOKEN),
                                             "is written in a form this check does not read", path=vp.IMPORTER_WORKFLOW)
                failed_with(self, report, "twice")
        once = workflow_pr(workflow_text(job_extra="    timeout-minutes: 5"))
        self.assertEqual((once.exit_code, once.failures), (0, []))

    def test_a_key_the_environment_mapping_spells_twice_is_unreadable_whichever_comes_first(self):
        # The carve-out grants pull-requests: write on the strength of the environment's name, so the name inside the
        # mapping is the one place where guessing which of two is in force would hand out the grant.
        duplicated = {
            "the bot environment first": "    environment:\n      name: marketplace-bot\n      name: production",
            "the bot environment last": "    environment:\n      name: production\n      name: marketplace-bot",
            "two copies of the bot environment": "    environment:\n      name: marketplace-bot\n      name: marketplace-bot",
            "another key": "    environment:\n      name: marketplace-bot\n      url: https://a.example\n      url: https://b.example",
        }
        for label, job_extra in duplicated.items():
            with self.subTest(label):
                report = self.assert_refused(workflow_text(job_extra=job_extra, step=self.APP_TOKEN),
                                             "is written in a form this check does not read", path=vp.IMPORTER_WORKFLOW)
                failed_with(self, report, "environment of job `build` has the key")
                failed_with(self, report, "asks the App-token action")
        once = workflow_text(job_extra="    environment:\n      name: marketplace-bot\n      url: https://a.example",
                             step=self.APP_TOKEN)
        report = workflow_pr(once, path=vp.IMPORTER_WORKFLOW)
        self.assertEqual((report.exit_code, report.failures), (0, []))

    def test_the_unreadable_failure_names_only_what_applies_to_the_file(self):
        unread = "name: x\non: push\njobs: {build: {runs-on: x}}\n"
        other = vp.workflow_problems(EXTRA, unread)[0]
        self.assertIn("what its jobs are named or which token permissions they take", other)
        validate = vp.workflow_problems(vp.VALIDATE_WORKFLOW, unread)[0]
        self.assertIn("so it cannot tell which token permissions its jobs take;", validate)
        self.assertNotIn("named", validate)

    def test_a_job_can_be_hashed_though_it_holds_rows(self):
        jobs = []
        vp._read_jobs(vp._rows(["jobs:", "  build:", "    runs-on: x"]), jobs)
        self.assertEqual(len(jobs), 1)
        self.assertEqual(len({jobs[0], jobs[0]}), 1)

    def test_a_file_is_read_once_and_an_unreadable_one_gets_one_answer(self):
        text = workflow_text(step=self.APP_TOKEN, job_extra=self.BOT_JOB)
        with mock.patch.object(vp, "_rows", wraps=vp._rows) as spy:
            vp.workflow_problems(vp.IMPORTER_WORKFLOW, text)
        self.assertEqual(spy.call_count, 1)
        unread = "name: x\non: push\njobs: {build: {runs-on: x}}\n"
        for path in (vp.VALIDATE_WORKFLOW, EXTRA):
            problems = vp.workflow_problems(path, unread)
            self.assertEqual(len(problems), 1, problems)

    def test_the_declares_message_agrees_in_number(self):
        one = vp.workflow_problems(EXTRA, workflow_text(bare=True))
        self.assertIn("`build` declares none of its own, so it takes the repository's default token", one[0])
        many = vp.workflow_problems(EXTRA, "name: x\non: push\njobs:\n  one:\n    runs-on: x\n  two:\n    runs-on: x\n")
        self.assertIn("`one`, `two` declare none of their own, so they take the repository's default token", many[0])

    def test_the_repositorys_importer_keeps_its_app_token_only_where_the_rule_allows(self):
        text = (WORKFLOWS_DIR / "import-plugin-release.yml").read_text(encoding="utf-8")
        self.assertEqual(vp.workflow_problems(vp.IMPORTER_WORKFLOW, text), [])
        for label, path, source in (("a copy elsewhere", ".github/workflows/copy.yml", text),
                                    ("the importer without its environment", vp.IMPORTER_WORKFLOW,
                                     re.sub(r"(?m)^\s+environment: marketplace-bot\n", "", text))):
            with self.subTest(label):
                self.assertNotEqual(source, "")
                problems = vp.workflow_problems(path, source)
                self.assertEqual(len(problems), 3, problems)
                for fragment in ("asks the App-token action for pull-requests: write", "uses the App-token action",
                                 "reads a MARKETPLACE_BOT_* secret"):
                    self.assertTrue(any(fragment in problem for problem in problems), (fragment, problems))
        self.assertNotEqual(re.sub(r"(?m)^\s+environment: marketplace-bot\n", "", text), text)

    def test_the_repositorys_tag_release_keeps_its_app_token_only_where_the_rule_allows(self):
        text = (WORKFLOWS_DIR / "tag-release.yml").read_text(encoding="utf-8")
        self.assertEqual(vp.workflow_problems(vp.TAG_RELEASE_WORKFLOW, text), [])
        without = re.sub(r"(?m)^\s+environment: marketplace-bot\n", "", text)
        self.assertNotEqual(without, text)
        for path, source in ((".github/workflows/copy.yml", text), (vp.TAG_RELEASE_WORKFLOW, without)):
            with self.subTest(path=path):
                problems = vp.workflow_problems(path, source)
                self.assertEqual(len(problems), 2, problems)
                self.assertTrue(any("uses the App-token action" in problem for problem in problems), problems)
                self.assertTrue(any("reads a MARKETPLACE_BOT_* secret" in problem for problem in problems), problems)
        # The importer alone may ask for pull-requests: write, whatever the other bot workflow enters.
        elevated = text.replace("permission-pull-requests: read", "permission-pull-requests: write")
        self.assertNotEqual(elevated, text)
        problems = vp.workflow_problems(vp.TAG_RELEASE_WORKFLOW, elevated)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("asks the App-token action for pull-requests: write", problems[0])

    def test_the_app_token_action_with_no_permission_input_is_refused_outside_the_bot_jobs(self):
        # With no permission-* input the action mints a token with every permission the installation has.
        step = ("- uses: actions/create-github-app-token@v3\n        with:\n"
                "          client-id: ${{ secrets.MARKETPLACE_BOT_CLIENT_ID }}\n"
                "          private-key: ${{ secrets.MARKETPLACE_BOT_PRIVATE_KEY }}")
        for path in (EXTRA, vp.VALIDATE_WORKFLOW):
            with self.subTest(path=path):
                report = self.assert_refused(workflow_text(step=step), "uses the App-token action", path=path)
                failed_with(self, report, "with no permission input it mints a token with every permission")
        second = workflow_text(step=step, job_extra=self.BOT_JOB) + (
            "  other:\n    permissions: {}\n    runs-on: x\n    steps:\n      " + step + "\n")
        for path in vp.BOT_WORKFLOWS:
            with self.subTest(path=path, shape="a second job that does not enter the environment"):
                self.assert_refused(second, "uses the App-token action", path=path)
            with self.subTest(path=path, shape="the job that enters it"):
                named = step + "\n          permission-contents: read"
                report = workflow_pr(workflow_text(step=named, job_extra=self.BOT_JOB), path=path)
                self.assertEqual((report.exit_code, report.failures), (0, []))

    def test_a_bot_step_has_to_name_its_permission_inputs(self):
        # In the two files where the action is allowed, a step that names no permission input mints a token with every
        # permission the installation has: the widening is the allowed job itself, so the inputs have to be explicit.
        for name in ("import-plugin-release.yml", "tag-release.yml"):
            with self.subTest(name):
                text = (WORKFLOWS_DIR / name).read_text(encoding="utf-8")
                bare = re.sub(r"(?m)^\s+permission-[a-z-]+: \w+\n", "", text)
                self.assertNotEqual(bare, text)
                problems = vp.workflow_problems(f".github/workflows/{name}", bare)
                self.assertEqual(len(problems), 1, problems)
                self.assertIn("names no permission input", problems[0])
                one = re.sub(r"(?m)^(\s+)permission-pull-requests: \w+\n", "", text)
                if one != text:
                    self.assertEqual(vp.workflow_problems(f".github/workflows/{name}", one), [])

    def test_each_token_step_is_judged_on_its_own_inputs(self):
        plain = "- uses: actions/create-github-app-token@v3\n        with:\n          permission-contents: read"
        bare = "- uses: actions/create-github-app-token@v3"
        reordered = "- with:\n          permission-contents: read\n        uses: actions/create-github-app-token@v3"
        flow = "- {uses: actions/create-github-app-token@v3, with: {permission-contents: read}}"
        for label, step, ok in (("one named step", plain, True), ("a step whose inputs come first", reordered, True),
                                ("a flow-style step", flow, True), ("a step with no input", bare, False),
                                ("a named step and a bare one", plain + "\n      " + bare, False),
                                ("a bare step and a named one", bare + "\n      " + plain, False),
                                ("a bare step beside another step's input",
                                 bare + "\n      - uses: actions/checkout@v4\n        with:\n          permission-x: y", False)):
            with self.subTest(label):
                report = workflow_pr(workflow_text(step=step, job_extra=self.BOT_JOB), path=vp.TAG_RELEASE_WORKFLOW)
                self.assertEqual(report.failures == [], ok, report.failures)
                if not ok:
                    failed_with(self, report, "names no permission input")
        flow_steps = workflow_text(job_extra=self.BOT_JOB).replace(
            "    steps:\n      - run: echo hello",
            "    steps: [{uses: actions/create-github-app-token@v3, with: {permission-contents: read}}]")
        self.assertIn("steps: [", flow_steps)
        self.assert_refused(flow_steps, "names no permission input", path=vp.TAG_RELEASE_WORKFLOW)

    def test_a_permission_variable_set_in_a_script_is_seen_too(self):
        # The action reads INPUT_PERMISSION-* from the environment, and a step can append to $GITHUB_ENV.
        for line in ('echo "INPUT_PERMISSION-PULL-REQUESTS=write" >> "$GITHUB_ENV"',
                     "echo INPUT_PERMISSION_PULL_REQUESTS=write >> $GITHUB_ENV"):
            for path in (EXTRA, vp.TAG_RELEASE_WORKFLOW):
                with self.subTest(line=line, path=path):
                    self.assert_refused(workflow_text(job_extra=self.BOT_JOB, step=f"- run: {line}"),
                                        "asks the App-token action for pull-requests: write", path=path)
        self.assert_refused(workflow_text(step='- run: echo "INPUT_PERMISSION-CHECKS=write" >> "$GITHUB_ENV"'),
                            "writes checks: write, statuses: write or write-all out plainly")
        for path in (EXTRA, vp.IMPORTER_WORKFLOW, vp.TAG_RELEASE_WORKFLOW):
            with self.subTest(path=path, name="another permission"):
                report = self.assert_refused(
                    workflow_text(job_extra=self.BOT_JOB, step='- run: echo "INPUT_PERMISSION-ADMINISTRATION=write" >> $GITHUB_ENV'),
                    "sets an INPUT_PERMISSION-* variable", path=path)
                failed_with(self, report, "write the permission as an input")

    def test_the_bots_secrets_are_read_only_in_the_bot_jobs_whatever_reads_them(self):
        # Another action that mints App tokens, or a script that mints one by hand, still needs the key.
        other = ("- uses: tibdex/github-app-token@v2\n        with:\n"
                 "          app_id: ${{ secrets.MARKETPLACE_BOT_CLIENT_ID }}\n"
                 "          private_key: ${{ secrets.MARKETPLACE_BOT_PRIVATE_KEY }}")
        by_hand = "- run: ./mint.sh\n        env:\n          KEY: ${{ secrets.marketplace_bot_private_key }}"
        for label, step in (("another action", other), ("a script", by_hand)):
            for path in (EXTRA, vp.VALIDATE_WORKFLOW):
                with self.subTest(label=label, path=path):
                    report = self.assert_refused(workflow_text(step=step), "reads a MARKETPLACE_BOT_* secret", path=path)
                    failed_with(self, report, "the release bot's credentials")
        for path in vp.BOT_WORKFLOWS:
            with self.subTest(path=path, shape="a bot job"):
                report = workflow_pr(workflow_text(step=by_hand, job_extra=self.BOT_JOB), path=path)
                self.assertEqual((report.exit_code, report.failures), (0, []))
            with self.subTest(path=path, shape="a second job that does not enter the environment"):
                second = workflow_text(step="- run: echo hi", job_extra=self.BOT_JOB) + (
                    "  other:\n    permissions: {}\n    runs-on: x\n    steps:\n      " + by_hand + "\n")
                self.assert_refused(second, "reads a MARKETPLACE_BOT_* secret", path=path)
        commented = workflow_text() + "# ${{ secrets.MARKETPLACE_BOT_PRIVATE_KEY }}\n"
        self.assertEqual(workflow_pr(commented).failures, [])

    def test_the_action_is_found_however_the_step_spells_it(self):
        spellings = ["actions/create-github-app-token@v3", '"actions/create-github-app-token@v3"',
                     "'actions/create-github-app-token@abc # v3'", "Actions/Create-GitHub-App-Token@v3",
                     "actions/create-github-app-token"]
        for spelling in spellings:
            with self.subTest(spelling):
                self.assert_refused(workflow_text(step=f"- uses: {spelling}"), "uses the App-token action")
        self.assert_refused(workflow_text(step='- "uses": actions/create-github-app-token@v3'), "uses the App-token action")
        self.assert_refused(workflow_text(step="- {uses: actions/create-github-app-token@v3}"), "uses the App-token action")
        elsewhere = workflow_text(step="- uses: actions/checkout@v4\n      - run: echo create-github-app-token")
        self.assertEqual(workflow_pr(elsewhere).failures, [])

    def test_the_permission_variables_the_action_reads_are_refused_as_the_grants_they_name(self):
        # The action reads INPUT_PERMISSION-* from the environment, so a step can ask without writing the input.
        for variable in ("INPUT_PERMISSION-PULL-REQUESTS", "INPUT_PERMISSION_PULL_REQUESTS",
                         "input_permission-pull-requests", '"INPUT_PERMISSION-PULL-REQUESTS"'):
            for path in (EXTRA, vp.TAG_RELEASE_WORKFLOW):
                with self.subTest(variable=variable, path=path):
                    text = workflow_text(job_extra=f"    environment: marketplace-bot\n    env:\n      {variable}: write")
                    self.assert_refused(text, "asks the App-token action for pull-requests: write", path=path)
        for variable in ("INPUT_PERMISSION-CHECKS", "INPUT_PERMISSION_STATUSES"):
            with self.subTest(variable=variable):
                self.assert_refused(workflow_text(job_extra=f"    env:\n      {variable}: write"),
                                    "writes checks: write, statuses: write or write-all out plainly")
        allowed = workflow_text(step=self.APP_TOKEN,
                                job_extra=f"{self.BOT_JOB}\n    env:\n      INPUT_PERMISSION-PULL-REQUESTS: write")
        report = workflow_pr(allowed, path=vp.IMPORTER_WORKFLOW)
        self.assertEqual((report.exit_code, report.failures), (0, []))

    def test_the_read_form_of_the_app_token_input_is_not_a_second_rule_for_the_bot_jobs(self):
        # It is the step that is refused outside the bot jobs, not the input: there it is fine, and elsewhere the
        # action itself is the problem, so the read form does not make the step acceptable.
        step = "- uses: actions/create-github-app-token@v3\n        with:\n          permission-pull-requests: read"
        report = workflow_pr(workflow_text(step=step, job_extra=self.BOT_JOB), path=vp.TAG_RELEASE_WORKFLOW)
        self.assertEqual((report.exit_code, report.failures), (0, []))
        report = self.assert_refused(workflow_text(step=step), "uses the App-token action")
        self.assertEqual(len(report.failures), 1, report.failures)

    def test_a_workflow_that_grants_both_reports_both(self):
        # Two unrelated powers, found by independent scans: neither may hide the other.
        report = self.assert_refused(workflow_text(top="permissions:\n  checks: write\n  pull-requests: write"),
                                     "writes checks: write, statuses: write or write-all out plainly")
        failed_with(self, report, "writes pull-requests: write out plainly")
        self.assertEqual(len(report.failures), 2, report.failures)
        report = self.assert_refused(workflow_text(top="permissions: write-all"), "write-all out plainly")
        self.assertEqual(len(report.failures), 1, report.failures)

    def test_text_that_only_mentions_a_grant_is_refused_and_the_message_does_not_claim_a_grant(self):
        # The scan reads text, not structure, so a `run:` that prints the words is refused as well. That is the
        # price of not parsing YAML; the message says the words were written, not that the file grants them.
        for words in ("pull-requests: write", "checks: write"):
            with self.subTest(words):
                text = workflow_text(top="permissions:\n  contents: read",
                                     step=f"- run: |\n          echo \"needs {words}\"")
                report = self.assert_refused(text, f"writes {words}")
                self.assertNotIn("grants", " ".join(report.failures))

    def test_a_workflow_that_declares_no_permissions_fails_closed(self):
        # With no permissions: the jobs take the repository's default token, and whether that default can write
        # is a repository setting nothing here can read. So a changed workflow has to say what its token may do.
        text = workflow_text(bare=True, step="- run: gh pr review --approve ${{ github.event.number }}")
        report = self.assert_refused(text, "declares no top-level permissions")
        failed_with(self, report, "`build`")
        failed_with(self, report, "repository's default token")

    def test_a_workflow_declares_permissions_at_the_top_or_on_every_job(self):
        two_jobs = ("name: x\non: push\njobs:\n  one:\n    permissions: {}\n    runs-on: x\n"
                    "  two:\n    permissions:\n      contents: read\n    runs-on: x\n")
        for label, text in {"at the top": workflow_text(top="permissions:\n  contents: read"),
                            "a quoted key at the top": workflow_text(top='"permissions": {}'),
                            "on every job": two_jobs}.items():
            with self.subTest(label):
                report = workflow_pr(text)
                self.assertEqual((report.exit_code, report.failures), (0, []))
        one_missing = two_jobs.replace("  two:\n    permissions:\n      contents: read\n", "  two:\n")
        report = self.assert_refused(one_missing, "declares no top-level permissions")
        failed_with(self, report, "`two`")
        self.assertFalse(any("`one`" in failure for failure in report.failures), report.failures)

    def test_forms_the_scan_cannot_read_with_confidence_fail(self):
        unreadable = {
            "jobs in flow style": "name: x\non: push\njobs: {build: {runs-on: ubuntu-latest}}\n",
            "jobs as an alias": "name: x\non: push\njobs: *shared\n",
            "the whole file as JSON": '{"on": "push", "jobs": {"build": {"runs-on": "ubuntu-latest"}}}',
            "an escaped top-level key": 'on: push\n"\\x6aobs":\n  build:\n    runs-on: x\n',
            "a job in flow style": "on: push\njobs:\n  build: {runs-on: ubuntu-latest, name: validate}\n",
            "a job as an alias": "on: push\njobs:\n  build: *base\n",
            "a merge key among the jobs": "on: push\njobs:\n  <<: *base\n",
            "a merge key in a job": "on: push\njobs:\n  build:\n    <<: *base\n    runs-on: x\n",
            "an escaped job id": 'on: push\njobs:\n  "\\x76alidate":\n    runs-on: x\n',
            "an escaped job name": workflow_text(name='"\\x76alidate"'),
            "an escaped job name, unicode": workflow_text(name='"\\u0076alidate"'),
            "a job name that is an alias": workflow_text(name="*label"),
            "a job name on the next line": "on: push\njobs:\n  build:\n    name:\n      validate\n    runs-on: x\n",
            "a job name that is a block scalar": "on: push\njobs:\n  build:\n    name: |\n      validate\n    runs-on: x\n",
            "a job name with an open quote": 'on: push\njobs:\n  build:\n    name: "validate\n    runs-on: x\n',
            "a complex key": "on: push\njobs:\n  ? build\n  : runs-on: x\n",
            "tab indentation": "on: push\njobs:\n\tbuild:\n\t\truns-on: x\n",
            "jobs indented unevenly": "on: push\njobs:\n    build:\n      runs-on: x\n  other:\n    runs-on: x\n",
        }
        for label, text in unreadable.items():
            with self.subTest(label):
                self.assert_refused(text, "is written in a form this check does not read")

    def test_the_unreadable_failure_names_the_reason_and_the_fix(self):
        report = workflow_pr("name: x\non: push\njobs: {build: {runs-on: x}}\n")
        failed_with(self, report, "(its jobs are given in flow style or as an alias)")
        failed_with(self, report, "write its jobs in plain block style")

    def test_a_problem_found_before_an_unreadable_part_is_still_reported(self):
        text = "on: push\njobs:\n  validate:\n    runs-on: x\n  other: {runs-on: x}\n"
        report = workflow_pr(text)
        failed_with(self, report, "defines a job with the id validate")
        failed_with(self, report, "is written in a form this check does not read")

    def test_ordinary_workflows_pass(self):
        passing = {
            "a step named validate": workflow_text(step="- name: validate\n        run: echo hello"),
            "a name that only starts with validate": workflow_text(name="validate (docs)"),
            "an id that only starts with validate": workflow_text("validate-docs"),
            "an expression name": workflow_text(name="${{ matrix.name }}"),
            "read permissions": workflow_text(top="permissions:\n  checks: read\n  statuses: read\n  contents: write"),
            "no permissions": workflow_text(top="permissions: {}"),
            "write to others": workflow_text(job_extra="    permissions:\n      contents: write\n      issues: write"),
            "read pull requests": workflow_text(top="permissions:\n  pull-requests: read"),
            "a comment about pull requests": workflow_text() + "# pull-requests: write\n",
            "a comment about it": workflow_text() + "# name: validate\n# checks: write\n# permissions: write-all\n",
            "a trailing comment": workflow_text(top="permissions:\n  checks: read # never write"),
            "a shell script that says so": workflow_text(step="- run: |\n          echo 'name: validate'\n          echo 'checks: read'"),
            "no jobs at all": "name: nothing\non: push\n",
            "an empty file": "",
            "documents with markers": "---\nname: x\non: push\npermissions: {}\njobs:\n  build:\n    runs-on: x\n...\n",
            "an anchor on a job": "on: push\npermissions: {}\njobs:\n  build: &base\n    runs-on: x\n    name: build\n",
            "a keyed matrix": "on: push\npermissions: {}\njobs:\n  build:\n    strategy:\n      matrix:\n        name: [validate, other]\n    runs-on: x\n",
            "jobs before another key": "jobs:\n  build:\n    runs-on: x\nconcurrency:\n  group: g\npermissions: {}\n",
            "everything indented": "  on: push\n  permissions: {}\n  jobs:\n    build:\n      runs-on: x\n",
        }
        for label, text in passing.items():
            with self.subTest(label):
                report = workflow_pr(text)
                self.assertEqual((report.exit_code, report.failures), (0, []))

    def test_the_repositorys_own_workflows_pass_and_the_scan_sees_validate_in_validate_yml(self):
        for workflow in sorted(WORKFLOWS_DIR.glob("*.yml")):
            with self.subTest(workflow.name):
                self.assertEqual(vp.workflow_problems(f".github/workflows/{workflow.name}", workflow.read_text(encoding="utf-8")), [])
        text = (WORKFLOWS_DIR / "validate.yml").read_text(encoding="utf-8")
        copied = vp.workflow_problems(".github/workflows/copy.yml", text)
        self.assertEqual(len(copied), 2, copied)
        self.assertTrue(any("defines a job with the id validate" in problem for problem in copied), copied)
        self.assertTrue(any("names job `validate` validate" in problem for problem in copied), copied)

    def test_validate_yml_may_define_the_job_but_not_grant_those_permissions(self):
        path = ".github/workflows/validate.yml"
        text = (WORKFLOWS_DIR / "validate.yml").read_text(encoding="utf-8")
        report = workflow_pr(text, path=path)
        self.assertEqual((report.exit_code, report.failures), (0, []))
        self.assertTrue(any(path in note for note in report.notes), report.notes)  # still called out for review
        for grant, fragment in (("permissions: write-all", "writes checks: write, statuses: write or write-all out plainly"),
                                ("permissions:\n  checks: write", "writes checks: write, statuses: write or write-all out plainly"),
                                ("permissions:\n  pull-requests: write", "writes pull-requests: write out plainly")):
            with self.subTest(grant):
                changed = text.replace("permissions:\n  contents: read", grant, 1)
                self.assertNotEqual(changed, text)
                failed_with(self, workflow_pr(changed, path=path), fragment)

    def test_only_workflow_files_in_the_prs_diff_are_read(self):
        bad = workflow_text("validate")
        for path in ("docs/validate.yml", ".github/workflows/sub/extra.yml", ".github/workflows/extra.txt", ".github/validate.yml", "workflows/extra.yml"):
            with self.subTest(path=path):
                report = workflow_pr(bad, path=path)
                self.assertEqual((report.exit_code, report.failures), (0, []))
        head = files(ts.manifest())
        head[EXTRA] = bad  # present at the head, but the PR's diff does not touch it
        report = run(pull(**HUMAN), files(ts.manifest()), head, [rc.MANIFEST])
        self.assertEqual((report.exit_code, report.failures), (0, []))
        deleted = files(ts.manifest())  # a deleted file has no text at the head
        report = run(pull(**HUMAN), files(ts.manifest()), deleted, [EXTRA])
        self.assertEqual((report.exit_code, report.failures), (0, []))

    def test_each_changed_workflow_is_read_and_a_bad_one_fails_a_bot_pr_too(self):
        head = files(ts.manifest())
        head[".github/workflows/one.yml"] = workflow_text("validate")
        head[".github/workflows/two.yaml"] = workflow_text(name="validate")
        head[".github/workflows/three.yml"] = workflow_text()
        changed = [".github/workflows/one.yml", ".github/workflows/two.yaml", ".github/workflows/three.yml"]
        report = run(pull(**HUMAN), files(ts.manifest()), head, changed)
        failed_with(self, report, "`.github/workflows/one.yml` defines a job with the id validate")
        failed_with(self, report, "`.github/workflows/two.yaml` names job `build` validate")
        self.assertFalse(any("three.yml" in failure for failure in report.failures), report.failures)
        report = run(pull(), files(ts.manifest()), head, changed)  # the bot's PR: it may change no workflow at all
        failed_with(self, report, "`.github/workflows/one.yml` defines a job with the id validate")
        failed_with(self, report, "a bot PR must be exactly one importer mode")

    def test_a_workflow_problem_does_not_hide_a_manifest_problem_or_the_reverse(self):
        head = files(ts.manifest())
        head[EXTRA] = workflow_text("validate")
        head[rc.SAFETY_FILE] = "{"
        report = run(pull(**HUMAN), files(ts.manifest()), head, [EXTRA, rc.SAFETY_FILE])
        failed_with(self, report, "defines a job with the id validate")
        failed_with(self, report, "rollback-safety.json does not parse at the PR head")
        head = files(ts.manifest())
        head[EXTRA] = workflow_text("validate")
        head[rc.MANIFEST] = "{"
        report = run(pull(**HUMAN), files(ts.manifest()), head, [EXTRA, rc.MANIFEST])
        failed_with(self, report, "defines a job with the id validate")
        failed_with(self, report, f"{rc.MANIFEST} does not parse at the PR head")


class TestWorkflow(unittest.TestCase):
    """validate.yml cannot run here, but what it promises the script can be read from it."""

    WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / "workflows" / "validate.yml"
    # The first Node 24 release that bundles an npm of MIN_NPM or later: v24.15.0 ships npm
    # 11.12.1 (nodejs.org/dist/index.json), and every later 24.x ships a newer one.
    FIRST_NODE_WITH_MIN_NPM = (24, 15, 0)

    @staticmethod
    def lowest_admitted(spec):
        """The lowest release setup-node's version spec can resolve to, or None when it can
        resolve to a Node that does not ship the npm the gate needs: a bare major, an x-range,
        an alias, another major (Node 25.0.0 through 25.8.2 bundle npm 11.6 to 11.11), or a range
        with no upper bound, which setup-node resolves to the highest cached copy of any major.
        Only an exact 24.x.y, or a range from one up to but not including 25, is accepted."""
        match = re.fullmatch(r"24\.(\d+)\.(\d+)", spec) or re.fullmatch(r">=24\.(\d+)\.(\d+) <25", spec)
        return (24, int(match.group(1)), int(match.group(2))) if match else None

    def test_the_lowest_release_a_spec_admits(self):
        for spec, lowest in (
            ("24.15.0", (24, 15, 0)),
            ("24.16.1", (24, 16, 1)),
            (">=24.15.0 <25", (24, 15, 0)),
            (">=24.16.1 <25", (24, 16, 1)),
            # Another major bundles another npm: Node 25.0.0 through 25.8.2 ship npm 11.6 to 11.11.
            ("25.0.0", None),
            (">=25.9.0 <26", None),
            # No upper bound, or one past 25: the highest cached copy of any major can be chosen.
            (">=24.15.0", None),
            (">=24.16.1", None),
            (">=24.15.0 <26", None),
            (">=24.15.0 <24.99.0", None),
            ("<25", None),
            ("24", None),
            ("24.x", None),
            ("^24.15.0", None),
            (">=24", None),
            ("lts/*", None),
            ("latest", None),
        ):
            with self.subTest(spec):
                self.assertEqual(self.lowest_admitted(spec), lowest)

    def test_the_workflow_runs_a_node_that_ships_an_npm_the_gate_accepts(self):
        text = self.WORKFLOW.read_text(encoding="utf-8")
        specs = re.findall(r"uses: actions/setup-node@[0-9a-f]{40}.*\n\s+with:\n\s+node-version: \"([^\"]+)\"", text)
        self.assertEqual(len(specs), 1, "validate.yml must install Node exactly once, with a quoted node-version")
        lowest = self.lowest_admitted(specs[0])
        self.assertIsNotNone(lowest, f"node-version {specs[0]!r} can resolve to a cached Node with an older npm")
        self.assertGreaterEqual(lowest, self.FIRST_NODE_WITH_MIN_NPM)

    def test_the_run_budget_ends_before_the_job_is_cancelled(self):
        # validate reaches its own "no verdict" first; GitHub's cancellation of the job is not one.
        limits = re.findall(r"^\s+timeout-minutes: (\d+)\s*$", self.WORKFLOW.read_text(encoding="utf-8"), re.M)
        self.assertEqual(len(limits), 1, "validate.yml must set one job timeout")
        self.assertLess(rc.BUDGET_JOB, int(limits[0]) * 60)

    def test_the_npm_floor_the_node_version_was_chosen_for_is_the_gates(self):
        # If the gate's floor moves, the Node release above has to move with it.
        self.assertEqual(rc.MIN_NPM, (11, 12, 0))

    def test_the_workflow_names_the_npm_it_needs_rather_than_just_a_major(self):
        text = self.WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("npm 11 (Node 24)", text)
        self.assertIn("npm 11.12", text)


class TestScriptTestsWorkflow(unittest.TestCase):
    """The unit tests read workflow files, so a change to one must run them."""

    WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / "workflows" / "script-tests.yml"

    @staticmethod
    def under_pull_request(text):
        """What script-tests.yml nests under `on: pull_request:` (comments left out); the
        standard library has no YAML reader, and this file's `on:` block is plain."""
        lines = text.splitlines()
        block = []
        for line in lines[lines.index("on:") + 1:]:
            if line.strip() and not line.startswith(" "):
                break
            block.append(line)
        keys = [i for i, line in enumerate(block) if re.fullmatch(r"  pull_request:\s*(#.*)?", line)]
        if len(keys) != 1:
            return None
        nested = []
        for line in block[keys[0] + 1:]:
            if line.strip() and not line.startswith("    "):
                break
            if line.strip() and not line.strip().startswith("#"):
                nested.append(line.strip())
        return nested

    def test_the_unit_tests_run_on_every_pull_request(self):
        nested = self.under_pull_request(self.WORKFLOW.read_text(encoding="utf-8"))
        self.assertIsNotNone(nested, "script-tests.yml must declare pull_request exactly once, under on:")
        self.assertEqual(nested, [], "a path, branch or type filter on pull_request leaves some changes untested")

    def test_the_reader_sees_a_filter_wherever_it_is_written(self):
        for text, expected in (
            ("on:\n  pull_request:\n  push:\n    branches: [main]\n", []),
            ("on:\n  pull_request:   # every PR\n  push:\n", []),
            ("on:\n  pull_request:\n    paths:\n      - 'a'\n  push:\n", ["paths:", "- 'a'"]),
            ("on:\n  pull_request:\n    branches: [main]\n", ["branches: [main]"]),
            ("on:\n  push:\n    branches: [main]\n", None),
        ):
            with self.subTest(text=text):
                self.assertEqual(self.under_pull_request(text), expected)


class TestSummary(unittest.TestCase):
    def test_pull_request_text_is_inert_in_the_summary(self):
        # Every name a pull request supplies reaches the summary, which renders as markdown.
        hostile = {
            "plugin": "<h2>PASS</h2>",
            "key": "<img src=x onerror=alert(1)>",
            "path": ".github/<b>workflow</b>.yml",
            "duplicate": "<u>twice</u>",
            "version": "<i>9.9.9</i>",
            "safety key": "[approve here](https://example.invalid) <img src=x>",
        }
        agents = copy.deepcopy(ts.AGENTS_MANIFEST)
        agents["plugins"] += [{"name": hostile["plugin"]}, {"name": hostile["plugin"]}]
        head = files(ts.manifest(), agents=agents)
        head_doc = ts.manifest()
        head_doc[hostile["key"]] = True
        head[rc.MANIFEST] = rc.dump_json(head_doc)
        head["plugins.json"] = '{"%s": 1, "%s": 2, "plugins": []}' % (hostile["duplicate"], hostile["duplicate"])
        head[rc.SAFETY_FILE] = rc.dump_json({"versions": {hostile["version"]: {}}})
        report = run(pull(**HUMAN), files(ts.manifest()), head, [rc.MANIFEST, hostile["path"]])
        # A rollback-safety.json that repeats a key is refused with the key quoted in the message.
        repeated = files(ts.manifest())
        repeated[rc.SAFETY_FILE] = '{"versions": {}, "%s": 1, "%s": 2}' % ((hostile["safety key"],) * 2)
        unparsed = run(pull(**HUMAN), files(ts.manifest()), repeated, [rc.SAFETY_FILE])
        failed_with(self, unparsed, "rollback-safety.json does not parse at the PR head")
        human = vp.Report()
        vp.human_rules((None, None, "none"), {}, {}, [hostile["path"]], human)
        bot = vp.Report()
        vp.bot_rules(
            pull(), (ts.ai_tc(ts.manifest()), ts.ai_tc(ts.manifest("0.9.15")), "advance"), dict(ts.PINS), {}, {}, {},
            [rc.MANIFEST, hostile["path"]], bot, bot_login=BOT, verify=verify, classify=classify,
        )
        text = "\n".join(vp.render_summary(r, 7) for r in (report, unparsed, human, bot))
        for what, value in hostile.items():
            with self.subTest(what):
                self.assertIn(value, text)  # it reached the summary ...
        # ... and every one of them sits inside a code span, so none is left to be read as markup.
        outside = re.sub(r"`[^`]*`", "", text)
        self.assertNotIn("<", outside)
        self.assertNotIn("](", outside)

    def test_a_pass_names_the_verdict_the_rows_and_the_run_to_confirm(self):
        report = vp.Report()
        report.row("Mode", "ADVANCE (bot PR)")
        text = vp.render_summary(report, 7)
        self.assertTrue(text.startswith("## validate: PR #7: PASS\n"))
        self.assertIn("confirm it is that workflow", text)
        # pull_request_target runs the default branch's copy, whatever branch the PR targets.
        self.assertIn("validate.yml from main (the default branch)", text)
        self.assertNotIn("base branch", text)
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

    def test_the_diff_starts_at_the_merge_base_not_at_main(self):
        # Main moves on after the PR branched. What main gained is not the PR's change, so the
        # run must not report it as a touched workflow or ownership file.
        head = self.pr_commit(ts.manifest(), {"README.md": "hello\n"})
        self.repo.commit(files={".github/other.txt": "moved on main\n"})
        self.assertEqual(self.main(head, self.commits(head)), 0)
        text = self.summary_text()
        self.assertNotIn("other.txt", text)
        self.assertNotIn("touches automation", text)

    def test_the_diff_starts_from_the_main_the_run_resolved_whatever_is_checked_out(self):
        # The base is the merge base of the main commit the run resolved and the PR head. It is
        # not whatever the work tree holds: with the PR head checked out, a base taken from the
        # work tree would be the PR itself, and a pin edit would compare equal to itself.
        doc = ts.manifest()
        ts.ai_tc(doc)["source"]["version"] = "0.9.13"
        head = self.pr_commit(doc)
        ts.git(self.repo.path, "checkout", "-q", "--detach", head)
        self.assertEqual(self.main(head, self.commits(head)), 1)
        self.assertIn("a human PR may change only", self.summary_text())

    def test_the_summary_names_the_main_commit_it_read(self):
        head = self.pr_commit(ts.manifest(), {"README.md": "hello\n"})
        self.repo.commit(files={"llms.txt": "moved on main\n"})
        tip = ts.git(self.repo.path, "rev-parse", "main").strip()
        self.assertEqual(self.main(head, self.commits(head)), 0)
        self.assertIn(f"| Main read at | `{tip[:12]}` |", self.summary_text())

    def test_the_pins_are_read_at_the_main_commit_the_run_resolved(self):
        # Main gains a commit that pins 0.9.15 after the run resolved it. The summary names the
        # commit the run read, so the pins must come from that one too: an entry for 0.9.15 is
        # still one nothing pins.
        head = self.pr_commit(ts.manifest(), {rc.SAFETY_FILE: rc.dump_json({"versions": {**ts.SEED, "0.9.15": NEXT_ENTRY}})})
        resolved = ts.git(self.repo.path, "rev-parse", "main").strip()
        read_pins = rc.pins_by_ref

        def pins_after_main_moves(*args, **kwargs):
            self.repo.commit(ts.manifest(NEXT))
            return read_pins(*args, **kwargs)

        with mock.patch.object(rc, "pins_by_ref", side_effect=pins_after_main_moves):
            self.assertEqual(self.main(head, self.commits(head)), 1)
        text = self.summary_text()
        self.assertIn("rollback-safety.json gains 0.9.15, which nothing pins", text)
        self.assertIn(f"| Main read at | `{resolved[:12]}` |", text)

    def test_a_failing_pr_names_the_main_commit_it_read_too(self):
        doc = ts.manifest()
        ts.ai_tc(doc)["source"]["version"] = "0.9.13"
        head = self.pr_commit(doc)
        tip = ts.git(self.repo.path, "rev-parse", "main").strip()
        self.assertEqual(self.main(head, self.commits(head)), 1)
        self.assertIn(f"| Main read at | `{tip[:12]}` |", self.summary_text())

    def test_a_commit_listing_that_is_not_json_or_not_a_list_is_no_verdict(self):
        head = self.pr_commit(ts.manifest(), {"README.md": "hello\n"})
        for body in (b"not json", {"a": 1}, [1], [{"sha": "x"}, "text"]):
            with self.subTest(body=body):
                if os.path.exists(self.summary):
                    os.remove(self.summary)  # the summary file is appended to, so read this run's alone
                code = self.main(head, ts.FakeFetch({self.COMMITS_URL: (200, body)}))
                self.assertEqual(code, 2)
                text = self.summary_text()
                self.assertIn("NO VERDICT", text)
                self.assertIn("api: GET ", text)

    def test_a_manifest_that_nests_too_deeply_fails_with_a_summary(self):
        for levels in (2000, 100_000):
            with self.subTest(levels=levels):
                if os.path.exists(self.summary):
                    os.remove(self.summary)
                ts.git(self.repo.path, "checkout", "-q", "-b", f"deep-{levels}")
                head = self.repo.commit(files={rc.MANIFEST: '{"renames": %s}' % nested(levels)})
                ts.git(self.repo.path, "checkout", "-q", "main")
                self.assertEqual(self.main(head, self.commits(head)), 1)
                text = self.summary_text()
                self.assertIn("## validate: PR #7: FAIL", text)
                self.assertIn("claude-plugin/marketplace.json does not parse at the PR head", text)

    def branch(self, name, files=None, *, remove=()):
        """A commit on a new branch off main, then back to main: the PR head."""
        ts.git(self.repo.path, "checkout", "-q", "-b", name)
        for path in remove:
            os.remove(os.path.join(self.repo.path, path))
        head = self.repo.commit(files=files or {})
        ts.git(self.repo.path, "checkout", "-q", "main")
        return head

    def test_a_workflow_with_a_job_named_validate_fails_with_a_summary(self):
        for name, path in (("yml", ".github/workflows/extra.yml"), ("yaml", ".github/workflows/extra.yaml")):
            with self.subTest(path):
                if os.path.exists(self.summary):
                    os.remove(self.summary)
                head = self.branch(f"wf-{name}", {path: workflow_text("validate")})
                self.assertEqual(self.main(head, self.commits(head)), 1)
                text = self.summary_text()
                self.assertIn("## validate: PR #7: FAIL", text)
                self.assertIn(f"`{path}` defines a job with the id validate", text)
        if os.path.exists(self.summary):
            os.remove(self.summary)
        head = self.branch("wf-name", {".github/workflows/named.yml": workflow_text(name="validate")})
        self.assertEqual(self.main(head, self.commits(head)), 1)
        self.assertIn("`.github/workflows/named.yml` names job `build` validate", self.summary_text())

    def test_workflows_a_pr_adds_deletes_or_renames_are_read_where_they_stand_at_the_head(self):
        self.repo.commit(files={".github/workflows/old.yml": workflow_text()})
        added = self.branch("wf-add-ok", {".github/workflows/new.yml": workflow_text("other")})
        self.assertEqual(self.main(added, self.commits(added)), 0, self.summary_text())
        deleted = self.branch("wf-delete", remove=[".github/workflows/old.yml"])
        self.assertEqual(self.main(deleted, self.commits(deleted)), 0, self.summary_text())
        renamed = self.branch("wf-rename", {".github/workflows/renamed.yml": workflow_text("validate")}, remove=[".github/workflows/old.yml"])
        os.remove(self.summary)
        self.assertEqual(self.main(renamed, self.commits(renamed)), 1)
        text = self.summary_text()
        self.assertIn("`.github/workflows/renamed.yml` defines a job with the id validate", text)
        self.assertNotIn("old.yml` defines", text)

    def test_an_unexpected_error_is_no_verdict_with_a_summary(self):
        head = self.pr_commit(ts.manifest(), {"README.md": "hello\n"})
        with mock.patch.object(vp, "evaluate", side_effect=KeyError("surprise")):
            self.assertEqual(self.main(head, self.commits(head)), 2)
        text = self.summary_text()
        self.assertIn("NO VERDICT", text)
        self.assertIn("internal: KeyError", text)

    def test_the_run_starts_one_budget_of_about_twenty_five_minutes(self):
        head = self.pr_commit(ts.manifest(), {"README.md": "hello\n"})
        seen = []
        evaluate = vp.evaluate

        def watching(*args, **kwargs):
            seen.append(rc.time_left())
            return evaluate(*args, **kwargs)

        with mock.patch.object(vp, "evaluate", side_effect=watching), mock.patch.object(
            rc, "start_budget", wraps=rc.start_budget
        ) as started:
            self.assertEqual(self.main(head, self.commits(head)), 0)
        started.assert_called_once_with(rc.BUDGET_JOB)
        self.assertEqual(rc.BUDGET_JOB, 25 * 60)
        self.assertEqual(len(seen), 1)
        self.assertIsNotNone(seen[0], "no budget was running while validate worked")
        self.assertTrue(rc.BUDGET_JOB - 60 < seen[0] <= rc.BUDGET_JOB)

    def test_the_budget_ends_with_the_run_however_it_ends(self):
        head = self.pr_commit(ts.manifest(), {"README.md": "hello\n"})
        for error in (rc.InfraError("network", "down"), rc.ReleaseCheckError("version", "no"), KeyError("status")):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(vp, "evaluate", side_effect=error):
                    self.main(head, self.commits(head))
                self.assertIsNone(rc.time_left())
        with mock.patch.object(vp, "evaluate", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.main(head, self.commits(head))
        self.assertIsNone(rc.time_left())

    def test_an_interrupt_is_not_swallowed_by_the_net(self):
        head = self.pr_commit(ts.manifest(), {"README.md": "hello\n"})
        with mock.patch.object(vp, "evaluate", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.main(head, self.commits(head))

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
