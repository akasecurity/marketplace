"""Live checks of release_checks.py against npmjs and the GitHub API.

Not collected by the unit-test pattern (test_*.py), so CI never needs the network. Run
them by hand before merging any change to the release checks, with npm 11.12 or later on PATH:

    python3 -m unittest discover -s .github/scripts -p 'live_*.py' -v
"""

from __future__ import annotations

import json
import os
import pathlib
import unittest
import urllib.parse
from unittest import mock

import _testsupport as ts
import release_checks as rc

REPO = pathlib.Path(__file__).resolve().parents[2]
STORE_CODE = f"{rc.STORE_CODE_DIR}/{rc.STORE_CODE_ENTRY}"

# Every release a fleet-v tag pins, with the commit its signing certificate names: the
# versions the fleet can be rolled back to. 0.9.11 is on npm, but no tag pins it. The
# table test below fails when a tag pins a version this table lacks, so add it here.
FLEET_PINNED = {
    # The oldest rollback target (fleet-v2); the unit fixtures hold no commit for it.
    "0.9.6": "dc73c73f3ca46aa644bda144cc99e972b60814f7",
    **{v: ts.ATTESTED[v] for v in ("0.9.8", "0.9.9", "0.9.10", "0.9.12", "0.9.13", "0.9.14")},
    # What fleet-v9 pins. The unit fixtures use 0.9.15 as an invented next release with a stand-in
    # commit, so the real one is spelled here.
    "0.9.15": "b65d0ab867e7827e21d0532ae2e1845885933449",
}


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

    def test_the_table_names_every_version_a_fleet_tag_pins(self):
        # Reads this checkout's tags: run `git fetch --tags` first. With no fleet-v tags that
        # pin a version the test fails, and with only some of them it checks only those.
        pinned = rc.tag_pinned_versions(str(REPO))
        self.assertTrue(pinned, "this checkout has no fleet-v tags that pin a version: fetch the tags")
        self.assertEqual(sorted(pinned - set(FLEET_PINNED), key=rc.vkey), [])

    def test_every_fleet_pinned_version_still_verifies(self):
        # The rollback targets: each release a fleet-v tag pins must pass the same checks
        # today, now that the signer is read from the certificate.
        for version, commit in FLEET_PINNED.items():
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

    def test_the_real_store_code_listing_flags_a_change_with_no_new_migration(self):
        # Reads ai-tc's real persistence source listings. 0.9.11 changed migrations.ts and added
        # no migration; the change was to comments, which a whole-file comparison cannot tell
        # from any other, so the release counts. 0.9.13 changed other files in that directory and
        # neither of the two store-code files.
        commented = classify_pair("0.9.10", "0.9.11")
        self.assertEqual(
            (commented.classification, commented.migrations, commented.kinds),
            ("not-rollback-safe", [], {STORE_CODE: rc.STORE_CODE_CHANGED}),
        )
        unchanged = classify_pair("0.9.12", "0.9.13")
        self.assertEqual((unchanged.classification, unchanged.migrations, unchanged.kinds), ("additive", [], {}))


class TestLiveBotApp(unittest.TestCase):
    """BOT_LOGIN names a real Bot account, and its App slug is the login's. The user endpoint is public. The App
    endpoint answers 404 to a caller without a token while the App is private, so the owner is checked only when
    GITHUB_TOKEN is set (http_fetch sends it to api.github.com alone); without one that test skips."""

    def get(self, path):
        return rc.http_fetch(f"https://api.github.com/{path}", {})

    def test_the_configured_login_is_a_bot_account(self):
        status, body = self.get(f"users/{urllib.parse.quote(rc.BOT_LOGIN, safe='')}")
        self.assertEqual(status, 200, body[:200])
        user = json.loads(body)
        self.assertEqual((user["login"], user["type"]), (rc.BOT_LOGIN, "Bot"))

    def test_the_apps_slug_is_the_logins_and_akasecurity_owns_it(self):
        slug = rc.BOT_LOGIN[: -len("[bot]")]
        status, body = self.get(f"apps/{urllib.parse.quote(slug, safe='')}")
        if status == 404 and not os.environ.get("GITHUB_TOKEN"):
            self.skipTest("GitHub answers an unauthenticated read of /apps/<slug> only for a public App; set "
                          "GITHUB_TOKEN to check the owner of this one")
        self.assertEqual(status, 200, body[:200])
        app = json.loads(body)
        self.assertEqual((app["slug"], app["owner"]["login"]), (slug, "akasecurity"))


def classify_pair(earlier, later):
    return rc.classify_migrations(ts.ATTESTED[earlier], ts.ATTESTED[later])
