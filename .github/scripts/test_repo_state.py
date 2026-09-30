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


def journal_numbers(entry):
    return [tag.split("_", 1)[0] for tag in entry["migrations"]]


class TestCommittedRollbackSafety(unittest.TestCase):
    def setUp(self):
        self.raw = read(rc.SAFETY_FILE)
        self.doc = rc.parse_json(self.raw)

    def test_well_formed_and_written_by_the_one_writer(self):
        self.assertEqual(rc.safety_problems(self.doc), [])
        self.assertEqual(rc.dump_json(self.doc), self.raw)

    def test_the_seed_is_what_the_classifier_computed(self):
        # A reviewed reclassification of a seeded version updates SEED in the same PR.
        for version, want in ts.SEED.items():
            with self.subTest(version):
                got = self.doc["versions"][version]
                self.assertEqual(
                    (got["classification"], got["from"], got["to"], journal_numbers(got)),
                    (want["classification"], want["from"], want["to"], journal_numbers(want)),
                )

    def test_every_seeded_release_with_a_migration_is_flagged(self):
        flagged = {v for v, e in self.doc["versions"].items() if e["classification"] == "not-rollback-safe"}
        self.assertTrue({"0.9.9", "0.9.10", "0.9.12", "0.9.14"} <= flagged)
        self.assertEqual(self.doc["versions"]["0.9.13"]["classification"], "additive")
