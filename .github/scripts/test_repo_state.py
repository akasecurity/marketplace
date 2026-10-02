"""Guards on what main holds: the ai-tc entry's shape, the seeded rollback-safety.json, and the
entries recorded after the seed. They read the committed files, so every bot pin PR must keep
them true: nothing here may name the version main currently pins."""

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


# Entries recorded after the seed was taken, each as release_checks.py safety-entry computed it
# from the two attested commits. An entry is never rewritten once recorded, so these stay true
# however far the pin moves on.
RECORDED = {
    "0.9.15": {
        "classification": "not-rollback-safe",
        "from": ts.ATTESTED["0.9.14"],
        "to": "b65d0ab867e7827e21d0532ae2e1845885933449",
        "migrations": ["0036_secret_vault_identity_fingerprint"],
    },
}


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

    def test_the_recorded_entries_are_what_safety_entry_computed(self):
        for version, want in RECORDED.items():
            with self.subTest(version):
                self.assertEqual(self.doc["versions"][version], want)

    def test_the_version_main_pins_has_an_entry(self):
        # The rollback floor counts a pinned version with no entry as flagged, so a pin that
        # reached main without one blocks every rollback across it until its entry is recorded.
        pinned = rc.entry_version(rc.select_ai_tc_entry(rc.parse_json(read(rc.MANIFEST))))
        self.assertIsNotNone(pinned)
        self.assertIn(pinned, self.doc["versions"])

    def test_every_seeded_release_with_a_migration_is_flagged(self):
        flagged = {v for v, e in self.doc["versions"].items() if e["classification"] == "not-rollback-safe"}
        self.assertTrue({"0.9.9", "0.9.10", "0.9.12", "0.9.14"} <= flagged)
        self.assertEqual(self.doc["versions"]["0.9.13"]["classification"], "additive")
