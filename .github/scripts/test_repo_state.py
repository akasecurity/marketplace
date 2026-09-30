"""Guards on what main holds: the ai-tc entry's shape and the seeded rollback-safety.json.
They read the committed files, so every bot pin PR must keep them true."""

from __future__ import annotations

import os
import unittest

import _testsupport as ts
import release_checks as rc

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as handle:
        return handle.read()


class TestCommittedManifest(unittest.TestCase):
    def setUp(self):
        self.raw = read(rc.MANIFEST)
        self.entry = rc.select_ai_tc_entry(rc.parse_json(self.raw))

    def test_the_file_round_trips_through_the_one_writer(self):
        self.assertEqual(rc.dump_json(rc.load_round_trip(self.raw)), self.raw)

    def test_the_ai_tc_source_names_the_public_registry(self):
        version = rc.entry_version(self.entry)
        self.assertIsNotNone(version)
        self.assertEqual(
            self.entry["source"],
            {"source": "npm", "package": rc.PACKAGE, "version": version, "registry": rc.REGISTRY},
        )

    def test_the_ai_tc_entry_records_the_pin_integrity(self):
        self.assertEqual(list(self.entry.get("metadata", {})), ["integrity"])
        self.assertIsNotNone(rc.INTEGRITY.fullmatch(self.entry["metadata"]["integrity"]))

    def test_the_other_manifests_parse_without_duplicate_keys(self):
        for rel in (".agents/plugins/marketplace.json", "plugins.json"):
            with self.subTest(rel):
                rc.parse_json(read(rel))
