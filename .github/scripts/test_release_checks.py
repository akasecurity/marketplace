"""Unit tests for release_checks.py. Standard library only and no network: every fetch,
npm run and sleep is injected. live_release_checks.py holds the three live checks."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import subprocess
import unittest
from unittest import mock

import _testsupport as ts
import release_checks as rc


class TestJsonHelpers(unittest.TestCase):
    def test_duplicate_keys_are_refused(self):
        with self.assertRaisesRegex(ValueError, "duplicate key 'version'"):
            rc.parse_json('{"version": "0.9.13", "version": "0.9.14"}')

    def test_nan_is_refused(self):
        with self.assertRaisesRegex(ValueError, "NaN"):
            rc.parse_json('{"n": NaN}')

    def test_the_writer_keeps_non_ascii_and_ends_in_a_newline(self):
        text = rc.dump_json(ts.manifest())
        self.assertIn("—", text)
        self.assertTrue(text.endswith("}\n"))
        self.assertEqual(rc.load_round_trip(text), ts.manifest())

    def test_a_reformatted_file_is_refused_before_any_rewrite(self):
        compact = json.dumps(ts.manifest(), ensure_ascii=False)
        with self.assertRaises(rc.ReleaseCheckError) as caught:
            rc.load_round_trip(compact)
        self.assertEqual(caught.exception.check, "round-trip")


class TestSelectEntry(unittest.TestCase):
    def test_selects_the_one_ai_tc_entry(self):
        doc = ts.manifest()
        self.assertIs(rc.select_ai_tc_entry(doc), doc["plugins"][2])

    def test_no_entry_named_ai_tc_is_refused(self):
        doc = ts.manifest()
        doc["plugins"][2]["name"] = "ai-tc-2"
        with self.assertRaisesRegex(rc.ReleaseCheckError, "exactly one entry named 'ai-tc', found 0"):
            rc.select_ai_tc_entry(doc)

    def test_two_entries_named_ai_tc_are_refused(self):
        doc = ts.manifest()
        doc["plugins"].append(copy.deepcopy(doc["plugins"][2]))
        with self.assertRaisesRegex(rc.ReleaseCheckError, "exactly one entry named 'ai-tc', found 2"):
            rc.select_ai_tc_entry(doc)

    def test_a_second_entry_pinning_the_package_is_refused(self):
        doc = ts.manifest()
        twin = copy.deepcopy(doc["plugins"][2])
        twin["name"] = "ai-tc-canary"
        doc["plugins"].append(twin)
        with self.assertRaisesRegex(rc.ReleaseCheckError, "pinning @akasecurity/ai-tc-claude-code, found 2"):
            rc.select_ai_tc_entry(doc)

    def test_the_name_and_the_package_on_different_entries_is_refused(self):
        doc = ts.manifest()
        doc["plugins"][2]["name"] = "renamed"
        doc["plugins"][0]["name"] = "ai-tc"
        with self.assertRaisesRegex(rc.ReleaseCheckError, "is not the entry that pins"):
            rc.select_ai_tc_entry(doc)

    def test_a_path_source_string_is_not_an_error(self):
        doc = ts.manifest()
        doc["plugins"].insert(0, {"name": "local", "source": "./plugins/local"})
        self.assertEqual(rc.select_ai_tc_entry(doc)["name"], "ai-tc")

    def test_find_returns_none_when_nothing_names_or_pins_ai_tc(self):
        doc = ts.manifest()
        del doc["plugins"][2]
        self.assertIsNone(rc.find_ai_tc_entry(doc))

    def test_find_still_refuses_ambiguity(self):
        doc = ts.manifest()
        doc["plugins"].append(copy.deepcopy(doc["plugins"][2]))
        with self.assertRaises(rc.ReleaseCheckError):
            rc.find_ai_tc_entry(doc)

    def test_entry_version_accepts_only_exact_versions(self):
        entry = ts.ai_tc(ts.manifest("0.9.14"))
        self.assertEqual(rc.entry_version(entry), "0.9.14")
        for bad in ("0.9.14-rc1", "0.9.09", "^0.9.14", "0.9", "latest"):
            entry["source"]["version"] = bad
            self.assertIsNone(rc.entry_version(entry), bad)

    def test_versions_order_by_number(self):
        self.assertLess(rc.vkey("0.9.9"), rc.vkey("0.9.10"))
        with self.assertRaises(rc.ReleaseCheckError):
            rc.vkey("latest")
