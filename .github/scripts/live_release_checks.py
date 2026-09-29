"""Live checks of release_checks.py against npmjs and the GitHub API.

Not collected by the unit-test pattern (test_*.py), so CI never needs the network. Run
them by hand before merging any change to the release checks, with npm 11 on PATH:

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
        head = rc.ai_tc_main_head()
        status, body = rc.http_fetch(f"{rc.AI_TC_API}/compare/{head}...{ts.ATTESTED['0.9.14']}?per_page=1", {})
        self.assertEqual((status, json.loads(body)["status"]), (200, "behind"))

    def test_0_9_14_verifies_end_to_end(self):
        release = rc.verify_release("0.9.14")
        self.assertEqual(
            (release.integrity, release.git_commit, release.run_url),
            (ts.REAL_INTEGRITY_0_9_14, ts.ATTESTED["0.9.14"], ts.RUN_URL),
        )
