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
    vp.human_rules(entries, copy.deepcopy(ts.SEED), head, sorted(changed), report)
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
            "HUMAN EDIT of rollback-safety.json 0.9.14: not-rollback-safe -> additive; "
            "the approving code owner owns this classification",
            report.notes,
        )

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
