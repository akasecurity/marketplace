"""Live checks of release_checks.py against npmjs and the GitHub API.

Not collected by the unit-test pattern (test_*.py), so CI never needs the network. Run
them by hand before merging any change to the release checks, with npm 11.12 or later on PATH:

    python3 -m unittest discover -s .github/scripts -p 'live_*.py' -v
"""

from __future__ import annotations

import json
import unittest

import _testsupport as ts
import release_checks as rc


class TestLiveRelease(unittest.TestCase):
    """The comparison's direction, pinned against a real ancestor of ai-tc main."""

    def test_a_real_ancestor_of_ai_tc_main_is_ahead(self):
        self.assertEqual(rc.commit_on_ai_tc_main(ts.ATTESTED["0.9.14"]), "ahead")

    def test_the_reverse_comparison_is_behind(self):
        status, body = rc.http_fetch(f"{rc.AI_TC_API}/compare/main...{ts.ATTESTED['0.9.14']}?per_page=1", {})
        self.assertEqual((status, json.loads(body)["status"]), (200, "behind"))

    def test_0_9_14_verifies_end_to_end(self):
        release = rc.verify_release("0.9.14")
        self.assertEqual(
            (release.integrity, release.git_commit, release.run_url),
            (ts.REAL_INTEGRITY_0_9_14, ts.ATTESTED["0.9.14"], ts.RUN_URL),
        )

    def test_every_fleet_pinned_version_still_verifies(self):
        # The rollback targets: each release a fleet-v tag can pin must pass the same
        # checks today, now that the signer is read from the certificate.
        for version, commit in ts.ATTESTED.items():
            with self.subTest(version):
                self.assertEqual(rc.verify_release(version).git_commit, commit)

    def test_the_real_migrations_listing_finds_the_one_new_migration_and_no_edit(self):
        # Reads ai-tc's real directory listings (blob shas) at both attested commits. 0.9.14
        # added one migration and edited none; 0.9.13 added none.
        added = classify_pair("0.9.13", "0.9.14")
        self.assertEqual(
            (added.classification, added.migrations, list(added.kinds)),
            ("not-rollback-safe", ["0035_share_destination_provider_id"], ["0035_share_destination_provider_id"]),
        )
        unchanged = classify_pair("0.9.12", "0.9.13")
        self.assertEqual((unchanged.classification, unchanged.migrations), ("additive", []))


def classify_pair(earlier, later):
    return rc.classify_migrations(ts.ATTESTED[earlier], ts.ATTESTED[later])
