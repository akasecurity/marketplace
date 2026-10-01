"""Live checks of release_checks.py against npmjs and the GitHub API.

Not collected by the unit-test pattern (test_*.py), so CI never needs the network. Run
them by hand before merging any change to the release checks, with npm 11.12 or later on PATH:

    python3 -m unittest discover -s .github/scripts -p 'live_*.py' -v
"""

from __future__ import annotations

import json
import pathlib
import unittest

import _testsupport as ts
import release_checks as rc

REPO = pathlib.Path(__file__).resolve().parents[2]

# Every release a fleet-v tag pins, with the commit its signing certificate names: the
# versions the fleet can be rolled back to. 0.9.11 is on npm, but no tag pins it. The
# first test below fails when a tag pins a version this table lacks, so add it here.
FLEET_PINNED = {
    # The oldest rollback target (fleet-v2); the unit fixtures hold no commit for it.
    "0.9.6": "dc73c73f3ca46aa644bda144cc99e972b60814f7",
    **{v: ts.ATTESTED[v] for v in ("0.9.8", "0.9.9", "0.9.10", "0.9.12", "0.9.13", "0.9.14")},
}


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

    def test_the_table_names_every_version_a_fleet_tag_pins(self):
        # Reads this checkout's tags: run `git fetch --tags` first, or nothing is checked.
        pinned = rc.tag_pinned_versions(str(REPO))
        self.assertTrue(pinned, "this checkout has no fleet-v tags that pin a version: fetch the tags")
        self.assertEqual(sorted(pinned - set(FLEET_PINNED), key=rc.vkey), [])

    def test_every_fleet_pinned_version_still_verifies(self):
        # The rollback targets: each release a fleet-v tag pins must pass the same checks
        # today, now that the signer is read from the certificate.
        for version, commit in FLEET_PINNED.items():
            with self.subTest(version):
                self.assertEqual(rc.verify_release(version).git_commit, commit)
