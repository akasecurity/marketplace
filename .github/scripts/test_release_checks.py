"""Unit tests for release_checks.py. Standard library only and no outside network: every fetch,
npm run and sleep is injected. live_release_checks.py holds the three live checks."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import http.client
import http.server
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import _testsupport as ts
import release_checks as rc

# A manifest nested far past the depth json.loads reads: it raises RecursionError, not ValueError.
NESTED_TOO_DEEP = '{"plugins": ' + "[" * 100_000 + "]" * 100_000 + "}"


class TestJsonHelpers(unittest.TestCase):
    def test_duplicate_keys_are_refused(self):
        with self.assertRaisesRegex(ValueError, "duplicate key 'version'"):
            rc.parse_json('{"version": "0.9.13", "version": "0.9.14"}')

    def test_nan_is_refused(self):
        with self.assertRaisesRegex(ValueError, "NaN"):
            rc.parse_json('{"n": NaN}')

    def test_nesting_deeper_than_the_parser_reads_is_a_value_error(self):
        # json.loads raises RecursionError past the interpreter's depth, and RecursionError is
        # not a ValueError. Every caller of parse_json handles an unreadable document as a
        # ValueError, so the conversion is made here, once, for all of them.
        for label, text in (
            ("arrays inside a manifest", NESTED_TOO_DEEP),
            ("bare arrays", "[" * 100_000 + "]" * 100_000),
            ("objects", '{"a":' * 100_000 + "1" + "}" * 100_000),
        ):
            with self.subTest(label):
                with self.assertRaisesRegex(ValueError, "too deeply nested"):
                    rc.parse_json(text)

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


class TestErrorClasses(unittest.TestCase):
    def test_no_verdict_is_never_caught_as_a_verdict(self):
        self.assertFalse(issubclass(rc.InfraError, rc.ReleaseCheckError))
        self.assertFalse(issubclass(rc.ReleaseCheckError, rc.InfraError))

    def test_both_carry_the_check_and_the_detail(self):
        for cls in (rc.ReleaseCheckError, rc.InfraError):
            with self.subTest(cls=cls.__name__):
                error = cls("npm", "the registry is down")
                self.assertEqual(error.check, "npm")
                self.assertEqual(error.detail, "the registry is down")
                self.assertEqual(str(error), "npm: the registry is down")

    def test_a_handler_written_for_a_verdict_lets_an_outage_through(self):
        # _tag_pin is lenient about what a tag's manifest says, so every verdict-shaped
        # failure pins nothing. A failed read is no verdict and must not be dropped with them.
        with mock.patch.object(rc, "_manifest_at", side_effect=rc.InfraError("git", "show failed")):
            with self.assertRaises(rc.InfraError):
                rc._tag_pin("unused", "fleet-v1")
        for verdict in (rc.ReleaseCheckError("manifest", "no plugins list"), ValueError("does not parse")):
            with self.subTest(verdict=repr(verdict)):
                with mock.patch.object(rc, "_manifest_at", side_effect=verdict):
                    self.assertIsNone(rc._tag_pin("unused", "fleet-v1"))


class TestRunningTheFile(unittest.TestCase):
    def test_running_the_file_runs_the_command_line(self):
        # The in-process tests call main() and never run the file as a program, so a guard left
        # in front of the command line (one that exits before it) would pass all of them. A
        # workflow or a person runs the file itself.
        repo = ts.Repo(self)
        base = repo.write("base.json", rc.dump_json(ts.manifest("0.9.14")))
        head = repo.write("head.json", rc.dump_json(ts.manifest("0.9.14")))
        result = subprocess.run(
            [sys.executable, rc.__file__, "diff-mode", base, head], capture_output=True, text=True
        )
        self.assertEqual((result.returncode, result.stderr), (0, ""))
        self.assertEqual(json.loads(result.stdout), {"mode": "none"})


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


class TestPinnedVersions(unittest.TestCase):
    def setUp(self):
        self.repo = ts.Repo(self)
        unpinned = ts.manifest()
        del ts.ai_tc(unpinned)["source"]["version"]
        self.repo.commit(unpinned)
        self.repo.tag("fleet-v1")
        self.repo.commit(ts.manifest("0.9.6"))
        self.repo.tag("fleet-v2")
        self.repo.commit(ts.manifest("0.9.11"))  # pinned on main once, never tagged
        self.repo.commit(ts.manifest("0.9.12"))
        self.repo.tag("fleet-v10")  # numeric order, not text order
        self.repo.commit(ts.manifest("0.9.13"))
        self.repo.tag("release-1")  # not a fleet tag: ignored here
        self.repo.commit(ts.manifest("0.9.14"))

    def test_main_and_every_fleet_tag(self):
        self.assertEqual(rc.pinned_versions(self.repo.path), {"0.9.6", "0.9.12", "0.9.14"})

    def test_pins_by_ref_names_each_ref_in_numeric_tag_order(self):
        self.assertEqual(
            list(rc.pins_by_ref(self.repo.path).items()),
            [("main", "0.9.14"), ("fleet-v1", None), ("fleet-v2", "0.9.6"), ("fleet-v10", "0.9.12")],
        )

    def test_tag_pinned_versions_leave_out_main(self):
        self.assertEqual(rc.tag_pinned_versions(self.repo.path), {"0.9.6", "0.9.12"})

    def test_origin_main_wins_over_a_stale_local_main(self):
        older = ts.git(self.repo.path, "rev-parse", "HEAD~1").strip()
        ts.git(self.repo.path, "update-ref", "refs/remotes/origin/main", older)
        self.assertEqual(rc.main_ref(self.repo.path), "refs/remotes/origin/main")
        self.assertEqual(rc.pins_by_ref(self.repo.path)["main"], "0.9.13")

    def test_pins_by_ref_reads_main_at_the_commit_it_is_given(self):
        resolved = self.repo.head()
        self.repo.commit(ts.manifest("0.9.15"))  # main moves on after a caller resolved it
        self.assertEqual(rc.pins_by_ref(self.repo.path)["main"], "0.9.15")
        pins = rc.pins_by_ref(self.repo.path, main_rev=resolved)
        self.assertEqual(pins["main"], "0.9.14")
        self.assertEqual(
            list(pins.items()),
            [("main", "0.9.14"), ("fleet-v1", None), ("fleet-v2", "0.9.6"), ("fleet-v10", "0.9.12")],
        )

    def test_a_commit_that_cannot_be_read_is_a_git_failure(self):
        with self.assertRaises(rc.InfraError) as caught:
            rc.pins_by_ref(self.repo.path, main_rev="0" * 40)
        self.assertEqual(caught.exception.check, "git")

    def test_main_without_the_entry_pins_nothing(self):
        doc = ts.manifest()
        del doc["plugins"][2]
        self.repo.commit(doc)
        self.assertIsNone(rc.pins_by_ref(self.repo.path)["main"])

    def test_an_ambiguous_main_is_refused(self):
        doc = ts.manifest()
        doc["plugins"].append(copy.deepcopy(doc["plugins"][2]))
        self.repo.commit(doc)
        with self.assertRaises(rc.ReleaseCheckError):
            rc.pinned_versions(self.repo.path)

    def test_a_tag_pinning_the_package_twice_pins_nothing(self):
        # Two entries pinning the package is ambiguous, so the tag pins nothing, as a tag
        # whose manifest does not parse does. Its version must not reach the candidate or
        # rollback floors. Main is put back to one entry afterwards: main is read strictly.
        doc = ts.manifest("0.9.20")
        twin = copy.deepcopy(doc["plugins"][2])
        twin["name"] = "ai-tc-canary"
        doc["plugins"].append(twin)
        self.repo.commit(doc)
        self.repo.tag("fleet-v11")
        self.repo.commit(ts.manifest("0.9.14"))
        self.assertIsNone(rc._tag_pin(self.repo.path, "fleet-v11"))
        self.assertEqual(
            list(rc.pins_by_ref(self.repo.path).items()),
            [
                ("main", "0.9.14"),
                ("fleet-v1", None),
                ("fleet-v2", "0.9.6"),
                ("fleet-v10", "0.9.12"),
                ("fleet-v11", None),
            ],
        )
        self.assertNotIn("0.9.20", rc.pinned_versions(self.repo.path))

    def test_a_fleet_tag_nested_too_deeply_to_read_pins_nothing(self):
        # A tag is permanent history, so one tag a parser cannot read must not stop every
        # caller of pins_by_ref (validate, the importer, the audit): it pins nothing, as a tag
        # whose manifest does not parse does, and the others read as before.
        self.repo.commit(files={rc.MANIFEST: NESTED_TOO_DEEP})
        self.repo.tag("fleet-v11")
        self.repo.commit(ts.manifest("0.9.14"))
        self.assertIsNone(rc._tag_pin(self.repo.path, "fleet-v11"))
        self.assertEqual(
            list(rc.pins_by_ref(self.repo.path).items()),
            [
                ("main", "0.9.14"),
                ("fleet-v1", None),
                ("fleet-v2", "0.9.6"),
                ("fleet-v10", "0.9.12"),
                ("fleet-v11", None),
            ],
        )
        self.assertEqual(rc.pinned_versions(self.repo.path), {"0.9.6", "0.9.12", "0.9.14"})

    def test_a_main_manifest_nested_too_deeply_to_read_is_refused(self):
        # Main is read strictly, so this is pins_by_ref's usual refusal for a manifest that
        # does not parse, not an uncaught RecursionError.
        self.repo.commit(files={rc.MANIFEST: NESTED_TOO_DEEP})
        with self.assertRaises(rc.ReleaseCheckError) as caught:
            rc.pins_by_ref(self.repo.path)
        self.assertEqual(caught.exception.check, "manifest")
        self.assertIn("does not parse", caught.exception.detail)

    def test_a_repository_without_main_is_infrastructure(self):
        ts.git(self.repo.path, "branch", "-m", "main", "trunk")
        with self.assertRaises(rc.InfraError):
            rc.pinned_versions(self.repo.path)


def forget_object(repo_path, oid):
    """Remove one loose git object, as a failed fetch or a damaged checkout leaves it missing."""
    loose = os.path.join(repo_path, ".git", "objects", oid[:2], oid[2:])
    os.chmod(loose, 0o644)
    os.remove(loose)


class TestPinnedVersionsReadFailures(unittest.TestCase):
    """A tag that cannot be READ is no verdict. It must never be taken as a tag that pins
    nothing: that would drop a version from the candidate floor and the rollback floor."""

    def ledger(self):
        repo = ts.Repo(self)
        for number, version in enumerate(("0.9.12", "0.9.13", "0.9.14", "0.9.15"), start=1):
            repo.commit(ts.manifest(version))
            repo.tag(f"fleet-v{number}")
        return repo

    def delete_blob(self, repo, tag):
        blob = ts.git(repo.path, "rev-parse", f"refs/tags/{tag}^{{commit}}:{rc.MANIFEST}").strip()
        loose = os.path.join(repo.path, ".git", "objects", blob[:2], blob[2:])
        os.chmod(loose, 0o644)
        os.remove(loose)

    def test_a_tag_whose_manifest_object_is_gone_is_infrastructure(self):
        repo = self.ledger()
        self.assertEqual(rc.pinned_versions(repo.path), {"0.9.12", "0.9.13", "0.9.14", "0.9.15"})
        self.delete_blob(repo, "fleet-v3")
        for call in (rc.pins_by_ref, rc.pinned_versions, rc.tag_pinned_versions):
            with self.subTest(call=call.__name__):
                with self.assertRaises(rc.InfraError) as caught:
                    call(repo.path)
                self.assertEqual(caught.exception.check, "git")

    def test_a_tag_whose_manifest_directory_cannot_be_listed_is_infrastructure(self):
        # The probe that tells an absent manifest from an unreadable one lists the tree
        # first. When the listing itself fails, the file may well be there: the tag must
        # not be taken as one that pins nothing, or its version leaves both floors.
        repo = self.ledger()
        directory = os.path.dirname(rc.MANIFEST)
        forget_object(repo.path, ts.git(repo.path, "rev-parse", f"refs/tags/fleet-v3^{{commit}}:{directory}").strip())
        for call in (rc.pins_by_ref, rc.pinned_versions, rc.tag_pinned_versions):
            with self.subTest(call=call.__name__):
                with self.assertRaises(rc.InfraError) as caught:
                    call(repo.path)
                self.assertEqual(caught.exception.check, "git")

    def test_a_tag_at_a_commit_without_the_manifest_file_pins_nothing(self):
        # tag-release cuts such a tag as "entry removed", and a tag is immutable, so reading
        # it as a failed git read would be a permanent outage. The file is not there: the
        # tag pins nothing, and every other tag keeps its pin.
        repo = self.ledger()
        ts.git(repo.path, "rm", "-q", rc.MANIFEST)
        ts.git(repo.path, "commit", "-q", "-m", "drop the manifest")
        repo.tag("fleet-v5")
        repo.commit(ts.manifest("0.9.15"))  # main holds its manifest again: only the tag lacks one
        pins = rc.pins_by_ref(repo.path)
        self.assertEqual(pins["main"], "0.9.15")
        self.assertIsNone(pins["fleet-v5"])
        self.assertEqual([pins[f"fleet-v{n}"] for n in (1, 2, 3, 4)], ["0.9.12", "0.9.13", "0.9.14", "0.9.15"])
        self.assertEqual(rc.pinned_versions(repo.path), {"0.9.12", "0.9.13", "0.9.14", "0.9.15"})
        self.assertEqual(rc.tag_pinned_versions(repo.path), {"0.9.12", "0.9.13", "0.9.14", "0.9.15"})

    def test_a_manifest_that_does_not_parse_still_pins_nothing(self):
        repo = self.ledger()
        repo.commit(files={rc.MANIFEST: "{ not json"})
        repo.tag("fleet-v5")
        repo.commit(ts.manifest("0.9.15"))
        pins = rc.pins_by_ref(repo.path)
        self.assertIsNone(pins["fleet-v5"])
        self.assertEqual(pins["fleet-v3"], "0.9.14")

    def test_a_checkout_without_any_fleet_tag_is_infrastructure(self):
        repo = ts.Repo(self)
        repo.commit(ts.manifest("0.9.14"))
        for call in (rc.pins_by_ref, rc.pinned_versions, rc.tag_pinned_versions):
            with self.subTest(call=call.__name__):
                with self.assertRaises(rc.InfraError) as caught:
                    call(repo.path)
                self.assertEqual(caught.exception.check, "git")


class TestHttpHeaders(unittest.TestCase):
    def test_a_token_goes_only_to_the_github_api(self):
        self.assertTrue(rc._sends_token_to(f"{rc.AI_TC_API}/compare/a...main"))
        self.assertFalse(rc._sends_token_to(rc.packument_url()))
        self.assertFalse(rc._sends_token_to("https://registry.npmjs.org/api.github.com"))

    def test_github_requests_name_the_api_version(self):
        headers = rc._headers_for(f"{rc.AI_TC_API}/x", {})
        self.assertEqual(headers["X-GitHub-Api-Version"], "2022-11-28")
        self.assertEqual(headers["Accept"], "application/vnd.github+json")

    def test_registry_requests_carry_no_authorization(self):
        headers = rc._headers_for(rc.packument_url(), {"Accept": "application/json"})
        self.assertNotIn("Authorization", headers)
        self.assertEqual(headers["Accept"], "application/json")

    def test_no_token_in_the_environment_means_anonymous(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertNotIn("Authorization", rc._headers_for(f"{rc.AI_TC_API}/x", {}))

    def test_the_packument_url_escapes_the_scope_slash(self):
        self.assertEqual(rc.packument_url(), "https://registry.npmjs.org/@akasecurity%2Fai-tc-claude-code")


class _Response:
    """What urlopen returns: a context manager with a status and a body that may fail."""

    status = 200

    def __init__(self, body=b"", read_error=None):
        self.body = body
        self.read_error = read_error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        if self.read_error is not None:
            raise self.read_error
        return self.body


class _FailingBody(io.BytesIO):
    def __init__(self, error):
        super().__init__(b"")
        self.error = error

    def read(self, *args):
        raise self.error


class _Origin(http.server.BaseHTTPRequestHandler):
    """A loopback server: records each request's headers on its server, and answers 302 to
    the server's redirect_to, or 200 when it has none."""

    def do_GET(self):
        self.server.requests.append(dict(self.headers))
        self.send_response(302 if self.server.redirect_to else 200)
        if self.server.redirect_to:
            self.send_header("Location", self.server.redirect_to)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class TestHttpFetch(unittest.TestCase):
    URL = "https://registry.npmjs.org/x"

    def fetch_with(self, **patch):
        with mock.patch.object(rc._OPENER, "open", **patch):
            return rc.http_fetch(self.URL, {})

    def serve(self, redirect_to=None):
        server = http.server.HTTPServer(("127.0.0.1", 0), _Origin)
        server.requests = []
        server.redirect_to = redirect_to
        thread = threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_a_status_and_body_come_back_as_they_are(self):
        self.assertEqual(self.fetch_with(return_value=_Response(b"ok")), (200, b"ok"))

    def test_a_redirect_comes_back_as_its_status_and_is_not_followed(self):
        # urllib's default handler copies every header onto the follow-up request, the token
        # included, whatever host the redirect names. Here the token is forced on (the first
        # server is not api.github.com) so a followed redirect would deliver it to the second.
        second = self.serve()
        first = self.serve(redirect_to=f"http://localhost:{second.server_port}/")
        environ = {"GITHUB_TOKEN": "dummy-token", "no_proxy": "*", "NO_PROXY": "*"}
        with mock.patch.dict(os.environ, environ):
            with mock.patch.object(rc, "_sends_token_to", return_value=True):
                result = rc.http_fetch(f"http://127.0.0.1:{first.server_port}/", {})
        self.assertEqual(result, (302, b""))
        self.assertEqual([seen.get("Authorization") for seen in first.requests], ["Bearer dummy-token"])
        self.assertEqual(second.requests, [])

    def test_an_http_error_status_is_returned_and_not_raised(self):
        error = rc.urllib.error.HTTPError(self.URL, 503, "unavailable", {}, io.BytesIO(b"later"))
        self.assertEqual(self.fetch_with(side_effect=error), (503, b"later"))

    def test_no_answer_at_all_is_no_verdict(self):
        for label, error in (
            ("an unreachable host", rc.urllib.error.URLError("no route")),
            ("a timeout", TimeoutError("timed out")),
            ("a reset connection", ConnectionResetError("reset")),
        ):
            with self.subTest(label):
                with self.assertRaises(rc.InfraError) as caught:
                    self.fetch_with(side_effect=error)
                self.assertEqual(caught.exception.check, "network")

    def test_a_response_the_http_client_cuts_short_is_no_verdict(self):
        # urllib wraps socket errors in URLError, but not http.client's own, which come out
        # of getresponse() and read(): without a class of their own they would reach the
        # caller as neither a verdict nor an outage. An error status is read in a handler,
        # where a sibling except clause cannot see what that read raises.
        def error_status(error):
            return rc.urllib.error.HTTPError(self.URL, 502, "bad gateway", {}, _FailingBody(error))

        for label, patch in (
            ("a status line that is not HTTP", {"side_effect": http.client.BadStatusLine("")}),
            (
                "a body that stops before its length",
                {"return_value": _Response(read_error=http.client.IncompleteRead(b"par", 9))},
            ),
            (
                "an error status whose body stops early",
                {"side_effect": error_status(http.client.IncompleteRead(b"par", 9))},
            ),
            (
                "an error status whose body cannot be read",
                {"side_effect": error_status(ConnectionResetError("reset"))},
            ),
        ):
            with self.subTest(label):
                with self.assertRaises(rc.InfraError) as caught:
                    self.fetch_with(**patch)
                self.assertEqual(caught.exception.check, "network")
                self.assertIn(self.URL, caught.exception.detail)


class TestNpmCandidates(unittest.TestCase):
    def fetch(self, versions, latest="0.9.14"):
        return ts.FakeFetch(
            {rc.packument_url(): (200, {"versions": versions, "dist-tags": {"latest": latest}})}
        )

    def test_only_exact_versions_above_everything_pinned_ascending(self):
        versions = {v: {} for v in ["0.9.9", "0.9.10", "0.9.14", "0.9.15", "0.10.0-rc1", "0.9.16", "0.10.0"]}
        self.assertEqual(
            rc.npm_candidates({"0.9.6", "0.9.14"}, fetch=self.fetch(versions)),
            ["0.9.15", "0.9.16", "0.10.0"],
        )

    def test_versions_sort_by_number_not_text(self):
        self.assertEqual(
            rc.npm_candidates({"0.9.8"}, fetch=self.fetch({"0.9.10": {}, "0.9.9": {}})), ["0.9.9", "0.9.10"]
        )

    def test_nothing_pinned_yields_every_exact_version(self):
        self.assertEqual(rc.npm_candidates(set(), fetch=self.fetch({"0.9.6": {}, "0.9.0-rc1": {}})), ["0.9.6"])

    def test_nothing_above_the_pin_is_an_empty_list(self):
        self.assertEqual(rc.npm_candidates({"0.9.14"}, fetch=self.fetch({"0.9.13": {}, "0.9.14": {}})), [])

    def test_a_registry_document_that_is_not_a_versions_object_is_no_verdict(self):
        # The registry's packument always holds "versions" as an object keyed by version.
        # The list and string shapes belong to `npm view ... versions --json`, which this
        # module never reads, so they are a wrong answer and not a second accepted format.
        not_json = "answered non-JSON"
        no_object = "no versions object"
        for label, body, expected in (
            ("an array", b"[]", no_object),
            ("a string", b'"0.9.15"', no_object),
            ("null", b"null", no_object),
            ("no versions key", {"dist-tags": {"latest": "0.9.14"}}, no_object),
            ("a null versions", {"versions": None}, no_object),
            ("a versions list", {"versions": ["0.9.15"]}, no_object),
            ("a versions string", {"versions": "0.9.15"}, no_object),
            ("text that is not JSON", b"not json", not_json),
            ("bytes that are not UTF-8", b"\xff", not_json),
            ("a duplicated key", b'{"versions": {"0.9.15": {}}, "versions": {"0.9.16": {}}}', not_json),
            # json.loads raises RecursionError, not ValueError, past the interpreter's depth.
            ("nesting deeper than the parser reads", b"[" * 100_000 + b"]" * 100_000, not_json),
        ):
            with self.subTest(label):
                fetch = ts.FakeFetch({rc.packument_url(): (200, body)})
                with self.assertRaises(rc.InfraError) as caught:
                    rc.npm_candidates({"0.9.14"}, fetch=fetch)
                self.assertEqual(caught.exception.check, "npm")
                self.assertIn(expected, caught.exception.detail)

    def test_npm_latest_is_never_consulted(self):
        self.assertEqual(
            rc.npm_candidates({"0.9.14"}, fetch=self.fetch({"0.9.15": {}}, latest="9.9.9")), ["0.9.15"]
        )

    def test_the_registry_is_read_explicitly(self):
        fetch = self.fetch({"0.9.15": {}})
        rc.npm_candidates({"0.9.14"}, fetch=fetch)
        self.assertEqual(fetch.calls, [(rc.packument_url(), {"Accept": "application/json"})])

    def test_a_4xx_registry_answer_is_no_verdict_even_with_a_packument_body(self):
        # Only a 200 is an answer. A 4xx whose body happens to be a valid packument must not
        # be read: a status check that refused only 5xx would turn it into candidates.
        for status in (403, 404):
            with self.subTest(status=status):
                fetch = ts.FakeFetch({rc.packument_url(): (status, {"versions": {"0.9.15": {}}})})
                with self.assertRaises(rc.InfraError) as caught:
                    rc.npm_candidates({"0.9.14"}, fetch=fetch)
                self.assertEqual(caught.exception.check, "npm")
                self.assertIn(f"answered {status}", caught.exception.detail)

    def test_a_registry_error_is_infrastructure(self):
        with self.assertRaises(rc.InfraError):
            rc.npm_candidates(set(), fetch=ts.FakeFetch({rc.packument_url(): (503, b"")}))


class FakeRun:
    """Stands in for subprocess.run, answering by npm sub-command."""

    def __init__(self, *, install=(0,), audit=(1, "{}"), audits=None, npm_version="11.19.0", hang=None):
        self.install = list(install)
        self.audit = audit
        self.audits = None if audits is None else list(audits)  # (code, stdout) per audit; the last repeats
        self.npm_version = npm_version
        self.hang = hang
        self.calls = []
        self.timeouts = []  # (sub-command, the timeout the call carried), one per call

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs.get("cwd")))
        self.timeouts.append((args[1], kwargs.get("timeout")))
        if args[1] == self.hang:
            raise subprocess.TimeoutExpired(args, kwargs.get("timeout"))
        if args[:2] == ["npm", "init"]:
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == ["npm", "--version"]:
            return subprocess.CompletedProcess(args, 0, self.npm_version + "\n", "")
        if args[:2] == ["npm", "install"]:
            code = self.install.pop(0) if len(self.install) > 1 else self.install[0]
            return subprocess.CompletedProcess(args, code, "", "npm error 404" if code else "")
        if self.audits is not None:
            code, out = self.audits.pop(0) if len(self.audits) > 1 else self.audits[0]
        else:
            code, out = self.audit
        return subprocess.CompletedProcess(args, code, out, "")

    def count(self, command):
        return sum(1 for args, _ in self.calls if args[1] == command)


class FakeClock:
    """A clock that moves only when a test moves it: stands in for time.monotonic."""

    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class ClockedRun(FakeRun):
    """A FakeRun whose every call, a hang included, takes `seconds` of a FakeClock."""

    def __init__(self, clock, seconds, **kwargs):
        super().__init__(**kwargs)
        self.clock = clock
        self.seconds = seconds

    def __call__(self, args, **kwargs):
        try:
            return super().__call__(args, **kwargs)
        finally:
            self.clock.advance(self.seconds)


class TestNpmAuditSignatures(unittest.TestCase):
    def test_installs_exactly_the_version_from_npmjs_without_scripts_in_a_scratch_dir(self):
        run = FakeRun(audit=(1, json.dumps(ts.audit_output("0.9.14"))))
        result = rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None)
        install = next(a for a, _ in run.calls if a[:2] == ["npm", "install"])
        self.assertIn("--ignore-scripts", install)
        self.assertIn("--@akasecurity:registry=https://registry.npmjs.org", install)
        self.assertEqual(install[-1], "@akasecurity/ai-tc-claude-code@0.9.14")
        self.assertEqual(result["verified"][0]["version"], "0.9.14")
        cwds = {cwd for _, cwd in run.calls}
        self.assertEqual(len(cwds), 1)
        self.assertNotEqual(cwds.pop(), os.getcwd())

    def test_the_audit_asks_for_attestations_and_a_fresh_read_of_the_registry(self):
        run = FakeRun(audit=(0, json.dumps(ts.audit_output("0.9.14"))))
        rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None)
        # The last argument names npmjs as the scope's registry, as the install does: the audit
        # otherwise reads its keys, packument and attestations from the caller's npm configuration.
        self.assertEqual(
            run.calls[-1][0],
            ["npm", "audit", "signatures", "--json", "--include-attestations", "--prefer-online",
             "--@akasecurity:registry=https://registry.npmjs.org"],
        )

    def test_every_audit_names_npmjs_as_the_registry_the_way_the_install_does(self):
        unindexed = (1, json.dumps(ts.audit_output("0.9.14", verified=False)))
        run = FakeRun(audits=[unindexed])

        def never(report):
            raise rc._NotIndexedYet("not yet")

        with self.assertRaises(rc._NotIndexedYet):
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None, judge=never)
        install = next(args for args, _ in run.calls if args[1] == "install")
        audits = [args for args, _ in run.calls if args[1] == "audit"]
        flag = "--@akasecurity:registry=https://registry.npmjs.org"
        self.assertIn(flag, install)
        self.assertEqual(len(audits), 5)
        self.assertTrue(all(flag in args for args in audits))

    def test_the_audit_is_the_part_that_is_repeated(self):
        # Registry lag is waited out by auditing again, not by installing again: one scratch
        # directory, one init, one version read and one install serve every audit.
        good = (1, json.dumps(ts.audit_output("0.9.14")))
        unindexed = (1, json.dumps(ts.audit_output("0.9.14", verified=False)))
        calls = []

        def judge(report):
            calls.append(report)
            if len(calls) < 4:
                raise rc._NotIndexedYet("not yet")
            return "judged"

        run, sleeps = FakeRun(audits=[unindexed, unindexed, unindexed, good]), []
        result = rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=sleeps.append, judge=judge)
        self.assertEqual(result, "judged")
        self.assertEqual([run.count(c) for c in ("init", "--version", "install", "audit")], [1, 1, 1, 4])
        self.assertEqual(sleeps, [20, 20, 20])
        self.assertEqual(len({cwd for _, cwd in run.calls}), 1)
        self.assertEqual(calls[-1]["verified"][0]["version"], "0.9.14")

    def test_every_audit_revalidates_npms_cache(self):
        # The registry's packument is cacheable for five minutes, so an audit repeated 20 s later
        # would read the same cached answer. --prefer-online makes each one ask the registry.
        unindexed = (1, json.dumps(ts.audit_output("0.9.14", verified=False)))
        run = FakeRun(audits=[unindexed])

        def never(report):
            raise rc._NotIndexedYet("not yet")

        with self.assertRaises(rc._NotIndexedYet):
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None, judge=never)
        audits = [args for args, _ in run.calls if args[1] == "audit"]
        self.assertEqual(len(audits), 5)
        self.assertTrue(all("--prefer-online" in args for args in audits))

    def test_a_report_that_is_never_indexed_is_given_up_on_after_five_audits(self):
        run, sleeps = FakeRun(audits=[(1, json.dumps(ts.audit_output("0.9.14")))]), []

        def never(report):
            raise rc._NotIndexedYet("not yet")

        with self.assertRaises(rc._NotIndexedYet):
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=sleeps.append, judge=never)
        self.assertEqual((run.count("install"), run.count("audit"), sleeps), (1, 5, [20, 20, 20, 20]))

    def test_nothing_printed_and_not_indexed_yet_share_one_budget_of_five_audits(self):
        nothing = (1, "")
        report = (1, json.dumps(ts.audit_output("0.9.14")))

        def never(report):
            raise rc._NotIndexedYet("not yet")

        for label, audits, expected in (
            ("ends on a report", [nothing, report, nothing, report, report], rc._NotIndexedYet),
            ("ends on nothing", [report, nothing, report, nothing, nothing], rc.InfraError),
        ):
            with self.subTest(label):
                run, sleeps = FakeRun(audits=audits), []
                with self.assertRaises(expected):
                    rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=sleeps.append, judge=never)
                self.assertEqual((run.count("install"), run.count("audit"), sleeps), (1, 5, [20, 20, 20, 20]))

    def test_a_judgement_that_is_not_waiting_for_the_index_is_final(self):
        run, sleeps = FakeRun(audits=[(1, json.dumps(ts.audit_output("0.9.14")))]), []

        def refuse(report):
            raise rc.ReleaseCheckError("provenance", "no")

        with self.assertRaises(rc.ReleaseCheckError):
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=sleeps.append, judge=refuse)
        self.assertEqual((run.count("audit"), sleeps), (1, []))

    def test_verify_release_retries_through_one_install(self):
        good = ts.audit_output("0.9.14")
        run, sleeps = FakeRun(audits=[(1, json.dumps(ts.audit_output("0.9.14", verified=False))), (1, json.dumps(good))]), []

        def audit(package, version, judge):
            return rc.npm_audit_signatures(package, version, run=run, sleep=sleeps.append, judge=judge)

        release = rc.verify_release(
            "0.9.14", fetch=ts.FakeFetch(ts.release_routes("0.9.14")), audit=audit, sleep=sleeps.append
        )
        self.assertEqual(release.version, "0.9.14")
        self.assertEqual((run.count("install"), run.count("audit"), sleeps), (1, 2, [20]))

    def test_the_default_audit_takes_the_judge_verify_release_hands_it(self):
        # Every other test passes its own `audit`, so none of them reaches the function verify_release
        # uses when it is given none. Its keyword-only defaults (the npm runner and the wait) are
        # swapped for fakes, which leaves the call from verify_release to the real function as it is.
        good = ts.audit_output("0.9.14")
        run, sleeps = FakeRun(audits=[(1, json.dumps(ts.audit_output("0.9.14", verified=False))), (1, json.dumps(good))]), []
        with mock.patch.dict(rc.npm_audit_signatures.__kwdefaults__, {"run": run, "sleep": sleeps.append}):
            release = rc.verify_release("0.9.14", fetch=ts.FakeFetch(ts.release_routes("0.9.14")), sleep=sleeps.append)
        self.assertEqual(release.version, "0.9.14")
        self.assertEqual((run.count("install"), run.count("audit"), sleeps), (1, 2, [20]))

    def test_verify_release_refuses_a_release_that_is_never_indexed_after_one_install(self):
        run, sleeps = FakeRun(audits=[(1, json.dumps(ts.audit_output("0.9.14", verified=False)))]), []

        def audit(package, version, judge):
            return rc.npm_audit_signatures(package, version, run=run, sleep=sleeps.append, judge=judge)

        with self.assertRaises(rc.ReleaseCheckError) as caught:
            rc.verify_release("0.9.14", fetch=ts.FakeFetch(ts.release_routes("0.9.14")), audit=audit, sleep=sleeps.append)
        self.assertEqual(caught.exception.check, "provenance")
        self.assertIn("did not come from the release pipeline", caught.exception.detail)
        self.assertEqual((run.count("install"), run.count("audit"), sleeps), (1, 5, [20, 20, 20, 20]))

    def test_every_npm_call_carries_a_timeout(self):
        # install gets the longest: it fetches the tarball and its dependencies.
        run = FakeRun(audit=(1, json.dumps(ts.audit_output("0.9.14"))))
        rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None)
        self.assertEqual(
            run.timeouts, [("init", 120), ("--version", 120), ("install", 300), ("audit", 120)]
        )
        self.assertEqual(len(run.timeouts), len(run.calls))

    def test_a_hung_npm_is_toolchain_and_is_not_retried(self):
        # A hang is not lag: waiting it out again would only push the run toward its job's timeout.
        for command, seconds in (("init", 120), ("--version", 120), ("install", 300), ("audit", 120)):
            with self.subTest(command=command):
                run, sleeps = FakeRun(hang=command, audit=(1, json.dumps(ts.audit_output("0.9.14")))), []
                with self.assertRaises(rc.InfraError) as caught:
                    rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=sleeps.append)
                self.assertEqual(caught.exception.check, "toolchain")
                self.assertIn(f"npm {command} did not finish within {seconds} s", caught.exception.detail)
                self.assertIn("NOT a signature result", caught.exception.detail)
                self.assertEqual(sleeps, [])
                self.assertEqual(sum(1 for args, _ in run.calls if args[1] == command), 1)

    def test_install_is_retried_then_reported_as_toolchain(self):
        sleeps = []
        with self.assertRaises(rc.InfraError) as caught:
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=FakeRun(install=(1,)), sleep=sleeps.append)
        self.assertEqual(caught.exception.check, "toolchain")
        self.assertIn("NOT a signature result", caught.exception.detail)
        self.assertEqual(sleeps, [20, 20, 20, 20])

    def test_a_late_install_success_is_used(self):
        run = FakeRun(install=(1, 1, 0), audit=(0, json.dumps(ts.audit_output("0.9.14"))))
        rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None)
        self.assertEqual(sum(1 for a, _ in run.calls if a[:2] == ["npm", "install"]), 3)

    def test_empty_audit_output_is_toolchain(self):
        with self.assertRaises(rc.InfraError):
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=FakeRun(audit=(1, "  ")), sleep=lambda s: None)

    def test_non_json_audit_output_is_toolchain(self):
        with self.assertRaises(rc.InfraError):
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=FakeRun(audit=(1, "oops")), sleep=lambda s: None)

    def test_audit_output_nested_too_deep_to_parse_is_toolchain(self):
        # json.loads raises RecursionError, not ValueError, past the interpreter's depth.
        deep = "[" * 100_000 + "]" * 100_000
        with self.assertRaises(rc.InfraError) as caught:
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=FakeRun(audit=(1, deep)), sleep=lambda s: None)
        self.assertEqual(caught.exception.check, "toolchain")

    def test_empty_audit_output_is_retried_before_it_is_given_up_on(self):
        sleeps, run = [], FakeRun(audit=(1, ""))
        with self.assertRaises(rc.InfraError) as caught:
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=sleeps.append)
        self.assertEqual(caught.exception.check, "toolchain")
        self.assertEqual(sleeps, [20, 20, 20, 20])
        self.assertEqual((run.count("install"), run.count("audit")), (1, 5))

    def test_a_late_audit_answer_is_used(self):
        answers = ["", "", json.dumps(ts.audit_output("0.9.14"))]
        run = FakeRun()

        def audit_run(args, **kwargs):
            if args[:2] == ["npm", "audit"]:
                return subprocess.CompletedProcess(args, 1, answers.pop(0), "")
            return run(args, **kwargs)

        result = rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=audit_run, sleep=lambda s: None)
        self.assertEqual(result["verified"][0]["version"], "0.9.14")

    def test_npms_own_error_document_is_toolchain_not_a_verdict(self):
        error = json.dumps({"error": {"summary": "found no installed dependencies to audit", "detail": ""}})
        with self.assertRaises(rc.InfraError) as caught:
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=FakeRun(audit=(1, error)), sleep=lambda s: None)
        self.assertEqual(caught.exception.check, "toolchain")
        self.assertIn("NOT a signature result", caught.exception.detail)

    def test_an_error_document_never_reaches_a_provenance_refusal(self):
        # All three lists are present, so the document is shaped like a report and only the
        # "error" key says it is not one. Without `missing`, provenance_verdict refuses the
        # document as toolchain by itself, and this test would pass with the guard deleted.
        error = json.dumps(
            {"error": {"summary": "audit endpoint unavailable"}, "invalid": [], "missing": [], "verified": []}
        )
        with self.assertRaises(rc.InfraError):
            rc.verify_release(
                "0.9.14",
                fetch=ts.FakeFetch(ts.release_routes("0.9.14")),
                audit=lambda package, version, judge: rc.npm_audit_signatures(
                    package, version, run=FakeRun(audit=(1, error)), sleep=lambda s: None, judge=judge
                ),
                sleep=lambda s: None,
            )

    def test_output_that_is_not_a_report_object_is_toolchain(self):
        for text in (
            "[]", "null", '"text"', "7", "{}", '{"verified": []}', '{"invalid": "none"}', '{"invalid": [], "verified": {}}',
            '{"invalid": []}', '{"invalid": [], "missing": []}',
        ):
            with self.subTest(text=text), self.assertRaises(rc.InfraError):
                rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=FakeRun(audit=(1, text)), sleep=lambda s: None)

    def test_a_report_with_nothing_verified_is_still_a_verdict(self):
        # An npm that honours --include-attestations prints the verified list even when it is empty.
        report = rc.npm_audit_signatures(
            rc.PACKAGE, "0.9.14", run=FakeRun(audit=(1, json.dumps({"invalid": [], "missing": [], "verified": []}))),
            sleep=lambda s: None,
        )
        self.assertEqual((report["invalid"], report["verified"]), ([], []))

    def test_a_report_without_a_verified_list_is_toolchain_not_a_missing_attestation(self):
        # No list at all is an npm that ignored the flag, and says nothing about the release.
        sleeps = []
        with self.assertRaises(rc.InfraError) as caught:
            rc.npm_audit_signatures(
                rc.PACKAGE, "0.9.14", run=FakeRun(audit=(1, json.dumps({"invalid": [], "missing": []}))), sleep=sleeps.append
            )
        self.assertEqual(caught.exception.check, "toolchain")
        self.assertIn("NOT a signature result", caught.exception.detail)
        self.assertEqual(sleeps, [], "a report npm cannot have meant is not waited out")

    def test_an_npm_older_than_11_12_is_toolchain(self):
        # --include-attestations first shipped in 11.12.0. An 11.0 to 11.11 npm takes the flag
        # without an error and prints no attestations, so it must be refused as the toolchain.
        for version in ("10.9.2", "9.0.0", "11.0.0", "11.5.1", "11.11.0", "11.11.9"):
            with self.subTest(version=version), self.assertRaises(rc.InfraError) as caught:
                rc.npm_audit_signatures(
                    rc.PACKAGE, "0.9.14", run=FakeRun(npm_version=version, audit=(0, json.dumps(ts.audit_output("0.9.14")))),
                    sleep=lambda s: None,
                )
            self.assertEqual(caught.exception.check, "toolchain")
            self.assertIn("11.12.0", caught.exception.detail)
            self.assertIn("NOT a signature result", caught.exception.detail)

    def test_npm_11_12_and_later_is_accepted(self):
        for version in ("11.12.0", "11.12.1", "11.16.0", "11.19.0", "12.0.0", "11.12.0-pre.1"):
            with self.subTest(version=version):
                run = FakeRun(npm_version=version, audit=(0, json.dumps(ts.audit_output("0.9.14"))))
                report = rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None)
                self.assertEqual(report["verified"][0]["version"], "0.9.14")

    def test_an_unreadable_npm_version_is_toolchain(self):
        # The audit itself would pass, so only the version gate can be what refuses.
        for version in ("banana", "11", "11.12", ""):
            with self.subTest(version=version), self.assertRaises(rc.InfraError) as caught:
                rc.npm_audit_signatures(
                    rc.PACKAGE, "0.9.14", run=FakeRun(npm_version=version, audit=(0, json.dumps(ts.audit_output("0.9.14")))),
                    sleep=lambda s: None,
                )
            self.assertEqual(caught.exception.check, "toolchain")
            self.assertIn("could not read npm's version", caught.exception.detail)

    def test_missing_npm_is_toolchain(self):
        def run(args, **kwargs):
            raise FileNotFoundError("npm")

        with self.assertRaises(rc.InfraError):
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None)


class TestVerifyRelease(unittest.TestCase):
    def verify(self, version="0.9.14", *, routes=None, audits=None, sleeps=None):
        fetch = ts.FakeFetch(routes if routes is not None else ts.release_routes(version))
        recorded = sleeps if sleeps is not None else []
        audit = ts.scripted_audit(self, version, audits if audits is not None else [ts.audit_output(version)], recorded.append)
        return rc.verify_release(version, fetch=fetch, audit=audit, sleep=recorded.append), fetch

    def refused(self, check, **kwargs):
        with self.assertRaises(rc.ReleaseCheckError) as caught:
            self.verify(**kwargs)
        self.assertEqual(caught.exception.check, check)
        self.assertNotIsInstance(caught.exception, rc.InfraError)
        return caught.exception

    def test_a_tag_built_release_on_main_passes(self):
        release, _ = self.verify()
        self.assertEqual(
            release, rc.VerifiedRelease("0.9.14", ts.INTEGRITY, ts.SHASUM, ts.ATTESTED["0.9.14"], ts.RUN_URL)
        )

    def test_the_commit_check_asks_whether_main_is_ahead_of_the_commit(self):
        _, fetch = self.verify()
        self.assertIn(ts.compare_url(ts.ATTESTED["0.9.14"]), fetch.urls())

    def test_the_comparison_is_made_against_the_resolved_head_of_main_never_the_name(self):
        # A tag named main in ai-tc could make the short name ambiguous, so the branch is read
        # by its fully qualified ref and the comparison names the sha that read returned.
        other = "d" * 40
        _, fetch = self.verify(routes=ts.release_routes("0.9.14", main_sha=other))
        commit = ts.ATTESTED["0.9.14"]
        urls = fetch.urls()
        self.assertEqual(
            [u for u in urls if u.startswith(f"{rc.AI_TC_API}/")],
            [ts.main_ref_url(), f"{rc.AI_TC_API}/compare/{commit}...{other}?per_page=1"],
        )
        self.assertFalse([u for u in urls if "...main" in u])

    def test_a_failed_main_ref_read_is_no_verdict(self):
        for status, body in ((404, {"message": "Not Found"}), (403, b""), (502, b"")):
            with self.subTest(status=status):
                routes = ts.release_routes("0.9.14")
                routes[ts.main_ref_url()] = (status, body)
                with self.assertRaises(rc.InfraError) as caught:
                    self.verify(routes=routes)
                self.assertEqual(caught.exception.check, "commit-on-main")

    def test_a_malformed_main_ref_is_no_verdict(self):
        good = ts.main_ref_body()
        for label, body in (
            ("not json", b"<html>"),
            ("a list", [good]),
            ("no object", {"ref": "refs/heads/main"}),
            ("object not a mapping", {"ref": "refs/heads/main", "object": "abc"}),
            ("no sha", {"ref": "refs/heads/main", "object": {}}),
            ("short sha", {"ref": "refs/heads/main", "object": {"sha": "abc123"}}),
            ("uppercase sha", {"ref": "refs/heads/main", "object": {"sha": "E" * 40}}),
            ("sha not a string", {"ref": "refs/heads/main", "object": {"sha": 7}}),
            ("another ref", {**good, "ref": "refs/tags/main"}),
            ("a duplicated key", b'{"ref": "refs/heads/main", "ref": "refs/heads/main", "object": {"sha": "' + b"e" * 40 + b'"}}'),
            ("nested too deeply", b"[" * 100000 + b"]" * 100000),
        ):
            with self.subTest(label):
                routes = ts.release_routes("0.9.14")
                routes[ts.main_ref_url()] = (200, body)
                with self.assertRaises(rc.InfraError) as caught:
                    self.verify(routes=routes)
                self.assertEqual(caught.exception.check, "commit-on-main")

    def test_a_compare_answer_that_is_not_a_json_object_is_no_verdict(self):
        # A 200 whose body is not the comparison says nothing about the commit, so it is neither a
        # refusal nor a crash.
        for label, body in (
            ("not json", b"<html>"),
            ("empty", b""),
            ("a list", b"[]"),
            ("a string", b'"ahead"'),
            ("null", b"null"),
            ("a duplicated key", b'{"status": "behind", "status": "ahead"}'),
            ("nested too deeply", b"[" * 100000 + b"]" * 100000),
        ):
            with self.subTest(label):
                routes = ts.release_routes("0.9.14")
                routes[ts.compare_url(ts.ATTESTED["0.9.14"])] = (200, body)
                with self.assertRaises(rc.InfraError) as caught:
                    self.verify(routes=routes)
                self.assertEqual(caught.exception.check, "commit-on-main")
                self.assertIn("compare", caught.exception.detail)

    def test_identical_to_main_passes(self):
        self.verify(routes=ts.release_routes("0.9.14", compare="identical"))

    def test_behind_main_is_refused(self):
        # Built on main's tip and never merged: the attacker's case.
        self.refused("commit-on-main", routes=ts.release_routes("0.9.14", compare="behind"))

    def test_diverged_is_refused(self):
        self.refused("commit-on-main", routes=ts.release_routes("0.9.14", compare="diverged"))

    def test_a_422_and_an_object_with_no_known_status_are_verdicts(self):
        # What commit_on_ai_tc_main's docstring says: GitHub cannot compare the two (404 or
        # 422), or it answered a JSON object whose status is neither ahead nor identical.
        # Only a body that is not that object, or another HTTP status, is no verdict.
        for label, answer in (
            ("a 422", (422, {"message": "No common ancestor"})),
            ("an empty object", (200, {})),
            ("a status of another kind", (200, {"status": "later"})),
            ("a status that is not a string", (200, {"status": 7})),
        ):
            with self.subTest(label):
                routes = ts.release_routes("0.9.14")
                routes[ts.compare_url(ts.ATTESTED["0.9.14"])] = answer
                self.refused("commit-on-main", routes=routes)

    def test_an_unknown_commit_is_refused(self):
        routes = ts.release_routes("0.9.14")
        routes[ts.compare_url(ts.ATTESTED["0.9.14"])] = (404, {"message": "Not Found"})
        self.refused("commit-on-main", routes=routes)

    def test_a_github_outage_is_no_verdict(self):
        routes = ts.release_routes("0.9.14")
        routes[ts.compare_url(ts.ATTESTED["0.9.14"])] = (502, b"")
        with self.assertRaises(rc.InfraError):
            self.verify(routes=routes)

    def test_a_non_exact_version_is_refused_before_any_request(self):
        fetch = ts.FakeFetch()
        with self.assertRaises(rc.ReleaseCheckError) as caught:
            rc.verify_release("0.9.15-rc1", fetch=fetch, audit=lambda p, v, judge: {}, sleep=lambda s: None)
        self.assertEqual((caught.exception.check, fetch.calls), ("version", []))

    def test_registry_lag_is_retried(self):
        routes = ts.release_routes("0.9.14")
        url = ts.dist_url("0.9.14")
        routes[url] = [(404, b'"version not found"'), (404, b'"version not found"'), routes[url]]
        sleeps = []
        self.verify(routes=routes, sleeps=sleeps)
        self.assertEqual(sleeps, [20, 20])

    def test_a_version_npm_never_serves_is_refused(self):
        routes = ts.release_routes("0.9.14")
        routes[ts.dist_url("0.9.14")] = (404, b'"version not found"')
        sleeps = []
        self.refused("dist", routes=routes, sleeps=sleeps)
        self.assertEqual(sleeps, [20, 20, 20, 20])

    def test_an_integrity_that_is_not_one_sha512_is_refused(self):
        self.refused("dist", routes=ts.release_routes("0.9.14", integrity="sha1-abc"))

    def test_an_unindexed_attestation_is_retried(self):
        sleeps = []
        self.verify(audits=[ts.audit_output("0.9.14", verified=False), ts.audit_output("0.9.14")], sleeps=sleeps)
        self.assertEqual(sleeps, [20])

    def test_no_attestation_after_five_tries_is_refused(self):
        sleeps = []
        error = self.refused("provenance", audits=[ts.audit_output("0.9.14", verified=False)], sleeps=sleeps)
        self.assertIn("no VERIFIED attestation", error.detail)
        self.assertEqual(sleeps, [20, 20, 20, 20])

    def test_npm_reporting_invalid_is_refused(self):
        self.refused("provenance", audits=[ts.audit_output("0.9.14", invalid=[{"code": "EINTEGRITYSIGNATURE"}])])

    def test_an_off_tag_branch_publish_is_refused_without_crying_theft(self):
        # The certificate and the statement both say the workflow ran from a branch.
        ref = "refs/heads/release/0.9.x"
        uri = f"{rc.PROV_REPO}/{ts.WORKFLOW}@{ref}"
        stmt = ts.statement("0.9.14", ref=ref)
        cert = ts.signing_cert("0.9.14", san=uri, build_signer=uri, build_config=uri, ref=ref, trigger="workflow_dispatch")
        error = self.refused("provenance", audits=[ts.audit_output("0.9.14", stmt, cert=cert)])
        self.assertIn("not a stolen npm credential", error.detail)

    def test_another_repository_is_refused(self):
        other = "https://github.com/someone/ai-tc"
        uri = f"{other}/{ts.WORKFLOW}@refs/tags/plugin-claude-v0.9.14"
        stmt = ts.statement("0.9.14", repository=other)
        cert = ts.signing_cert("0.9.14", san=uri, build_signer=uri, build_config=uri, repository=other)
        error = self.refused("provenance", audits=[ts.audit_output("0.9.14", stmt, cert=cert)])
        self.assertIn("anyone can publish with provenance", error.detail)

    def test_an_unhashable_subject_digest_still_gets_the_identity_refusal(self):
        # A statement is the publisher's JSON, and npm checks only its first subject. A list or
        # an object as a later subject's digest used to raise TypeError before the certificate's
        # identity was compared, so a foreign signer got a crash instead of the refusal that
        # says anyone can publish with provenance.
        other = "https://github.com/someone/ai-tc"
        uri = f"{other}/{ts.WORKFLOW}@refs/tags/plugin-claude-v0.9.14"
        for label, digest in (("a list", []), ("an object", {})):
            with self.subTest(label):
                foreign = ts.statement("0.9.14", repository=other)
                foreign["subject"].append({"name": "extra", "digest": {"sha512": digest}})
                cert = ts.signing_cert("0.9.14", san=uri, build_signer=uri, build_config=uri, repository=other)
                error = self.refused("provenance", audits=[ts.audit_output("0.9.14", foreign, cert=cert)])
                self.assertIn("anyone can publish with provenance", error.detail)
                # The genuine signer with the same extra subject still passes: the tarball's
                # digest is in the first subject.
                genuine = ts.statement("0.9.14")
                genuine["subject"].append({"name": "extra", "digest": {"sha512": digest}})
                release, _ = self.verify(audits=[ts.audit_output("0.9.14", genuine)])
                self.assertEqual(release.version, "0.9.14")

    def test_another_workflow_is_refused(self):
        path = ".github/workflows/other.yml"
        uri = f"{rc.PROV_REPO}/{path}@refs/tags/plugin-claude-v0.9.14"
        stmt = ts.statement("0.9.14", path=path)
        cert = ts.signing_cert("0.9.14", san=uri, build_signer=uri, build_config=uri)
        self.refused("provenance", audits=[ts.audit_output("0.9.14", stmt, cert=cert)])

    def test_a_self_hosted_builder_is_refused(self):
        stmt = ts.statement("0.9.14", builder="https://github.com/actions/runner/self-hosted")
        cert = ts.signing_cert("0.9.14", runner="self-hosted")
        error = self.refused("provenance", audits=[ts.audit_output("0.9.14", stmt, cert=cert)])
        self.assertIn("github-hosted", error.detail)

    def test_an_attestation_for_different_bytes_is_refused(self):
        stmt = ts.statement("0.9.14", sha512="00" * 64)
        error = self.refused("provenance", audits=[ts.audit_output("0.9.14", stmt)])
        self.assertIn("different tarball", error.detail)

    def test_a_statement_without_the_tag_dependency_is_refused(self):
        stmt = ts.statement("0.9.14", dependency_uri=f"git+{rc.PROV_REPO}@refs/heads/main")
        self.refused("attested-commit", audits=[ts.audit_output("0.9.14", stmt)])

    def test_a_short_commit_is_refused(self):
        stmt = ts.statement("0.9.14", commit="a75532b9")
        self.refused("attested-commit", audits=[ts.audit_output("0.9.14", stmt)])

    def test_a_foreign_run_url_is_refused(self):
        stmt = ts.statement("0.9.14", run_url="https://example.com/actions/runs/1")
        self.refused("run-url", audits=[ts.audit_output("0.9.14", stmt)])


SQL_GENERATED = (
    "ALTER TABLE `events` ADD `elapsed_ms` integer GENERATED ALWAYS AS "
    "(json_extract(attributes, '$.elapsed_ms')) VIRTUAL;"
)
SQL_DEFAULTED = "ALTER TABLE `widgets` ADD `approved` integer DEFAULT 0 NOT NULL;"
SQL_DROP_INDEX = """DROP INDEX IF EXISTS `idx_widgets_key`;--> statement-breakpoint
CREATE INDEX `idx_widgets_key_created` ON `widgets` (`key`,`created_at`);"""
SQL_COMMENTED = """CREATE INDEX `idx_events_ended` ON `events` (`ended_at`) WHERE ended_at IS NOT NULL;--> statement-breakpoint
-- An expression index, written by hand: the generator cannot emit an
-- expression that contains a comma.
CREATE INDEX `idx_events_run` ON `events` (`session_id`, json_extract(`attributes`, '$.run_key')) WHERE `kind` = 'call';
"""
SQL_NULLABLE = "ALTER TABLE `widgets` ADD `provider_id` text;"
SQL_REBUILD = """PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_widgets` (`id` text PRIMARY KEY NOT NULL, `mode` text NOT NULL);--> statement-breakpoint
INSERT INTO `__new_widgets`("id", "mode") SELECT "id", "mode" FROM `widgets`;--> statement-breakpoint
DROP TABLE `widgets`;--> statement-breakpoint
ALTER TABLE `__new_widgets` RENAME TO `widgets`;--> statement-breakpoint
PRAGMA foreign_keys=ON;"""


class TestTimeBudget(unittest.TestCase):
    """One budget bounds a whole run: the per-call bounds and the retries alone add up to about
    50 minutes for one version, more than the jobs that run the checks are allowed."""

    URL = "https://registry.npmjs.org/x"

    def budget(self, seconds):
        clock = FakeClock()
        rc.start_budget(seconds, clock=clock)
        self.addCleanup(rc.clear_budget)
        return clock

    def sleeping(self, clock):
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            clock.advance(seconds)

        sleep.taken = sleeps
        return sleep

    def request_timeout(self):
        with mock.patch.object(rc._OPENER, "open", return_value=_Response(b"ok")) as opener:
            rc.http_fetch(self.URL, {})
        return opener.call_args.kwargs["timeout"]

    def test_without_a_budget_every_call_keeps_its_own_bound(self):
        self.assertIsNone(rc.time_left())
        self.assertEqual(rc._time_for(300, "npm install"), 300)
        self.assertEqual(self.request_timeout(), 60)
        sleeps = []
        rc._wait(sleeps.append, "the next install")
        self.assertEqual(sleeps, [20])

    def test_the_budget_counts_down_on_its_clock_and_can_be_cleared(self):
        clock = self.budget(100)
        self.assertEqual(rc.time_left(), 100)
        clock.advance(30)
        self.assertEqual(rc.time_left(), 70)
        clock.advance(80)
        self.assertEqual(rc.time_left(), -10)
        rc.clear_budget()
        self.assertIsNone(rc.time_left())

    def test_the_budget_runs_on_the_monotonic_clock_unless_given_another(self):
        rc.start_budget(100)
        self.addCleanup(rc.clear_budget)
        self.assertTrue(99 < rc.time_left() <= 100)

    def test_every_budget_ends_before_the_job_that_runs_it(self):
        # validate and the importer's verify job are allowed 30 minutes, staleness 45 (for every
        # candidate it verifies). The script's own "no verdict" must come first.
        self.assertLess(rc.BUDGET_JOB, 30 * 60)
        self.assertLess(rc.BUDGET_STALENESS, 45 * 60)
        self.assertEqual(rc.BUDGET_CLI, 20 * 60)

    def test_a_request_keeps_its_own_bound_while_the_budget_is_longer(self):
        self.budget(500)
        self.assertEqual(self.request_timeout(), 60)

    def test_a_request_is_clipped_to_what_remains(self):
        clock = self.budget(100)
        clock.advance(88)
        self.assertEqual(self.request_timeout(), 12)

    def test_no_request_is_started_once_the_budget_is_used_up(self):
        clock = self.budget(100)
        for step in (100, 30):  # left 0, then -30
            clock.advance(step)
            with self.subTest(left=rc.time_left()):
                with mock.patch.object(rc._OPENER, "open") as opener:
                    with self.assertRaises(rc.InfraError) as caught:
                        rc.http_fetch(self.URL, {})
                self.assertEqual(caught.exception.check, "deadline")
                self.assertIn(self.URL, caught.exception.detail)
                opener.assert_not_called()

    def test_a_request_that_fails_as_the_budget_ends_is_the_deadline_not_the_network(self):
        clock = self.budget(100)

        def cut_off(request, timeout):
            clock.advance(timeout)
            raise TimeoutError("timed out")

        clock.advance(88)
        with mock.patch.object(rc._OPENER, "open", side_effect=cut_off):
            with self.assertRaises(rc.InfraError) as caught:
                rc.http_fetch(self.URL, {})
        self.assertEqual(caught.exception.check, "deadline")

    def test_a_request_that_fails_with_time_left_is_still_the_network(self):
        self.budget(100)
        with mock.patch.object(rc._OPENER, "open", side_effect=TimeoutError("timed out")):
            with self.assertRaises(rc.InfraError) as caught:
                rc.http_fetch(self.URL, {})
        self.assertEqual(caught.exception.check, "network")

    def test_an_npm_call_is_clipped_to_what_remains(self):
        clock = self.budget(500)
        clock.advance(380)
        run = FakeRun()
        rc._npm(run, ["install"], "work")
        self.assertEqual(run.timeouts, [("install", 120)])

    def test_no_npm_call_is_started_once_the_budget_is_used_up(self):
        clock = self.budget(60)
        clock.advance(60)
        run = FakeRun()
        with self.assertRaises(rc.InfraError) as caught:
            rc._npm(run, ["audit"], "work")
        self.assertEqual(caught.exception.check, "deadline")
        self.assertIn("npm audit", caught.exception.detail)
        self.assertEqual(run.calls, [])

    def test_an_npm_call_cut_off_by_the_budget_is_the_deadline_not_a_hung_npm(self):
        clock = self.budget(100)
        with self.assertRaises(rc.InfraError) as caught:
            rc._npm(ClockedRun(clock, 100, hang="install"), ["install"], "work")
        self.assertEqual(caught.exception.check, "deadline")
        self.assertIn("NOT a failed check", caught.exception.detail)

    def test_an_npm_call_that_hangs_with_time_left_is_still_toolchain(self):
        self.budget(1000)
        with self.assertRaises(rc.InfraError) as caught:
            rc._npm(FakeRun(hang="install"), ["install"], "work")
        self.assertEqual(caught.exception.check, "toolchain")
        self.assertIn("npm install did not finish within 300 s", caught.exception.detail)

    def test_a_wait_that_would_use_up_the_budget_is_not_taken(self):
        # With 20 s left or less the attempt after the wait could not start.
        for left in (20, 5, -3):
            with self.subTest(left=left):
                sleep = self.sleeping(self.budget(left))
                with self.assertRaises(rc.InfraError) as caught:
                    rc._wait(sleep, "the next audit")
                self.assertEqual(caught.exception.check, "deadline")
                self.assertIn("the next audit", caught.exception.detail)
                self.assertEqual(sleep.taken, [])
        sleep = self.sleeping(self.budget(21))
        rc._wait(sleep, "the next audit")
        self.assertEqual(sleep.taken, [20])

    def test_registry_reads_stop_when_the_next_attempt_could_not_start(self):
        clock = self.budget(150)
        sleep, reads = self.sleeping(clock), []

        def slow_registry(url, headers):
            reads.append(url)
            clock.advance(40)
            return 503, b""

        with self.assertRaises(rc.InfraError) as caught:
            rc.registry_dist("0.9.14", fetch=slow_registry, sleep=sleep)
        self.assertEqual(caught.exception.check, "deadline")
        self.assertEqual((len(reads), sleep.taken), (3, [20, 20]))

    def test_audits_stop_when_the_next_one_could_not_start(self):
        clock = self.budget(100)
        sleep, audits = self.sleeping(clock), []

        def slow_audit():
            audits.append(clock.now)
            clock.advance(45)
            return {"invalid": [], "verified": []}

        def never(report):
            raise rc._NotIndexedYet("not yet")

        with self.assertRaises(rc.InfraError) as caught:
            rc._audit_until_judged(slow_audit, never, sleep)
        self.assertEqual(caught.exception.check, "deadline")
        self.assertEqual((len(audits), sleep.taken), (2, [20]))

    def test_verify_release_ends_as_no_verdict_inside_the_budget(self):
        # Every npm call takes 300 s of a 20-minute budget: init and the version read use 600,
        # the first install 300, and the second install is cut to the 280 s that remain. It
        # fails like the first, and the wait before a third is not taken: nothing could follow it.
        clock = self.budget(1200)
        sleep = self.sleeping(clock)
        run = ClockedRun(clock, 300, install=(1,))

        def audit(package, version, judge):
            return rc.npm_audit_signatures(package, version, run=run, sleep=sleep, judge=judge)

        with self.assertRaises(rc.InfraError) as caught:
            rc.verify_release("0.9.14", fetch=ts.FakeFetch(ts.release_routes("0.9.14")), audit=audit, sleep=sleep)
        self.assertEqual(caught.exception.check, "deadline")
        self.assertEqual(
            run.timeouts, [("init", 120), ("--version", 120), ("install", 300), ("install", 280)]
        )
        self.assertEqual(sleep.taken, [20])
        self.assertEqual(clock.now, 1000 + 1220)


class TestMigrationKind(unittest.TestCase):
    def test_generated_and_nullable_columns_are_additive(self):
        self.assertEqual(rc.migration_kind(SQL_GENERATED), "additive")
        self.assertEqual(rc.migration_kind(SQL_NULLABLE), "additive")

    def test_a_defaulted_not_null_column_is_additive(self):
        self.assertEqual(rc.migration_kind(SQL_DEFAULTED), "additive")

    def test_indexes_and_comments_are_additive(self):
        self.assertEqual(rc.migration_kind(SQL_COMMENTED), "additive")

    def test_a_new_table_is_additive(self):
        self.assertEqual(rc.migration_kind("CREATE TABLE `gadgets` (`id` integer PRIMARY KEY);"), "additive")

    def test_dropping_an_index_is_not(self):
        self.assertEqual(rc.migration_kind(SQL_DROP_INDEX), "non-additive: a drop (drop index)")

    def test_not_null_without_a_default_is_not(self):
        self.assertEqual(
            rc.migration_kind("ALTER TABLE `widgets` ADD `c` text NOT NULL;"),
            "non-additive: a NOT NULL column without a default",
        )

    def test_not_null_is_read_after_the_column_name_and_as_words(self):
        no_default = "non-additive: a NOT NULL column without a default"
        cases = {
            "a name that ends in default": "ALTER TABLE `widgets` ADD `is_default` integer NOT NULL;",
            "a quoted name that holds the word": "ALTER TABLE `widgets` ADD `x default` integer NOT NULL;",
            "a double-quoted name that holds the word": 'ALTER TABLE `widgets` ADD "x default" integer NOT NULL;',
            "a bracketed name that holds the word": "ALTER TABLE `widgets` ADD [x default] integer NOT NULL;",
            "an unquoted name, COLUMN spelled out": "ALTER TABLE widgets ADD COLUMN x integer NOT NULL;",
            "an unquoted name with a dollar before the word": "ALTER TABLE widgets ADD x$default integer NOT NULL;",
            "the word in a string of a check": "ALTER TABLE `widgets` ADD `x` text NOT NULL CHECK (`x` <> 'DEFAULT');",
            "the word as a quoted name in the definition": "ALTER TABLE `widgets` ADD `x` integer NOT NULL REFERENCES `default`(`id`);",
            "a longer word that starts with it": "ALTER TABLE `widgets` ADD `x` integer NOT NULL REFERENCES defaults(id);",
        }
        for name, sql in cases.items():
            with self.subTest(name):
                self.assertEqual(rc.migration_kind(sql), no_default)

    def test_a_default_or_a_generated_expression_after_the_name_still_allows_not_null(self):
        cases = [
            "ALTER TABLE `widgets` ADD `x` integer NOT NULL DEFAULT 0;",
            "ALTER TABLE `widgets` ADD `x default` integer DEFAULT 0 NOT NULL;",
            "ALTER TABLE `widgets` ADD `x` text NOT NULL DEFAULT 'a';",
            "ALTER TABLE `widgets` ADD `x` integer NOT NULL GENERATED ALWAYS AS (1) VIRTUAL;",
            "ALTER TABLE `widgets` ADD `x` text;",
            # The words are in a quoted name, not in the column's constraints.
            "ALTER TABLE `widgets` ADD `x` text COLLATE `not null`;",
        ]
        for sql in cases:
            with self.subTest(sql):
                self.assertEqual(rc.migration_kind(sql), "additive")

    def test_a_table_name_holding_add_does_not_hide_a_drop_or_rename(self):
        # The table is read as one name, quoted or not, so the words ADD, DROP and RENAME inside
        # a quoted name start no clause. Read as a run of non-space characters, ` ADD ` inside the
        # name matched and the real DROP or RENAME landed in the column's definition.
        names = {
            "backticks": "`t ADD c`",
            "double quotes": '"t ADD c"',
            "double quotes with a doubled quote inside": '"t"" ADD c"',
            "backticks with a doubled backtick inside": "`t`` ADD c`",
            "brackets": "[t ADD c]",
            "a schema in front": "`main`.`t ADD c`",
        }
        statements = [
            ("a dropped column", "ALTER TABLE {t} DROP COLUMN `x`;"),
            ("a rename", "ALTER TABLE {t} RENAME TO `u`;"),
            ("a rename", "ALTER TABLE {t} RENAME COLUMN `x` TO `y`;"),
        ]
        for name, table in names.items():
            for reason, sql in statements:
                with self.subTest(name, statement=sql):
                    self.assertEqual(rc.migration_kind(sql.format(t=table)), f"non-additive: {reason}")

    def test_an_added_column_in_a_table_with_an_odd_name_is_still_additive(self):
        for table in ("`t ADD c`", '"t"" ADD c"', "[t ADD c]", "main.widgets", '"main"."widgets"', "`t DROP x`"):
            with self.subTest(table):
                self.assertEqual(rc.migration_kind(f"ALTER TABLE {table} ADD `x` text;"), "additive")
                self.assertEqual(rc.migration_kind(f"ALTER TABLE {table} ADD COLUMN x integer DEFAULT 0 NOT NULL;"), "additive")

    def test_a_name_that_cannot_be_read_as_one_is_not_additive(self):
        # Fail closed: a table name the reader does not recognise is an unrecognised statement.
        for sql in ("ALTER TABLE a.b.c ADD x text;", "ALTER TABLE ADD x text;", "ALTER TABLE `t` `u` ADD x text;"):
            with self.subTest(sql):
                self.assertTrue(rc.migration_kind(sql).startswith("non-additive"), rc.migration_kind(sql))

    def test_an_added_column_with_check_or_references_is_not_additive(self):
        # A CHECK is a new constraint an older build's inserts can fail; a REFERENCES adds a
        # foreign key an older build's delete on the parent can fail once a newer build fills it in.
        check = "non-additive: a CHECK constraint an older build's writes can fail"
        reference = "non-additive: a foreign key an older build's deletes can fail"
        cases = {
            "a check on another column": ("ALTER TABLE `widgets` ADD `c` integer CHECK (`d` > 0);", check),
            "a check on the column itself": ("ALTER TABLE `widgets` ADD `c` integer CHECK (`c` > 0);", check),
            "a named check": ("ALTER TABLE `widgets` ADD `c` integer DEFAULT 0 CONSTRAINT `c_ok` CHECK (`c` >= 0);", check),
            "a check, unquoted": ("ALTER TABLE widgets ADD COLUMN c integer CHECK(c > 0);", check),
            "a check that mentions NOT NULL, with a default": (
                "ALTER TABLE `widgets` ADD `c` integer DEFAULT 0 CHECK (`c` IS NOT NULL);",
                check,
            ),
            "a reference": ("ALTER TABLE `widgets` ADD `c` integer REFERENCES `gadgets`(`id`);", reference),
            "a reference, unquoted": ("ALTER TABLE widgets ADD c integer REFERENCES gadgets(id) ON DELETE CASCADE;", reference),
            "a reference in a double-quoted table": ('ALTER TABLE "t ADD c" ADD `c` integer REFERENCES `g`(`id`);', reference),
        }
        for name, (sql, kind) in cases.items():
            with self.subTest(name):
                self.assertEqual(rc.migration_kind(sql), kind)

    def test_the_words_check_and_references_in_a_name_or_a_string_decide_nothing(self):
        cases = [
            "ALTER TABLE `widgets` ADD `check` integer;",
            "ALTER TABLE `widgets` ADD `references` integer;",
            "ALTER TABLE widgets ADD check_count integer;",
            "ALTER TABLE widgets ADD references_total integer;",
            "ALTER TABLE `widgets` ADD `c` text DEFAULT 'CHECK (1) REFERENCES x';",
            "ALTER TABLE `widgets` ADD `c` text COLLATE `references`;",
        ]
        for sql in cases:
            with self.subTest(sql):
                self.assertEqual(rc.migration_kind(sql), "additive")

    def test_a_table_rebuild_is_not(self):
        self.assertEqual(rc.migration_kind(SQL_REBUILD), "non-additive: a table rebuild (drizzle's __new_ copy)")

    def test_every_other_change_is_not(self):
        cases = {
            "ALTER TABLE `widgets` RENAME COLUMN `a` TO `b`;": "a rename",
            "ALTER TABLE `widgets` DROP COLUMN `a`;": "a dropped column",
            "DROP TABLE `widgets`;": "a drop (drop table)",
            "CREATE VIEW `widgets` AS SELECT 1;": "a view",
            "CREATE TRIGGER `w` AFTER INSERT ON `widgets` BEGIN SELECT 1; END;": "a trigger",
            "CREATE UNIQUE INDEX `u` ON `widgets` (`a`);": "a UNIQUE index",
            "UPDATE `widgets` SET `c` = 1;": "an unrecognised statement",
        }
        for sql, reason in cases.items():
            with self.subTest(sql):
                self.assertTrue(rc.migration_kind(sql).startswith(f"non-additive: {reason}"), rc.migration_kind(sql))

    def test_an_empty_file_is_not_additive(self):
        self.assertEqual(rc.migration_kind("-- nothing\n"), "non-additive: no statements")

    def test_dashes_inside_a_string_do_not_hide_the_rest_of_the_line(self):
        sql = "CREATE TABLE `t` (`a` text DEFAULT '--');DROP TABLE `users`;"
        self.assertEqual(rc.migration_kind(sql), "non-additive: a drop (drop table)")

    def test_an_apostrophe_in_a_block_comment_does_not_open_a_string(self):
        # A lexer that misses /* */ reads the apostrophe as the start of a string that
        # runs to the next quote and blanks the DROP in between.
        sql = "/* don't */ DROP TABLE `users`; CREATE TABLE `a` (`b` text DEFAULT 'x');"
        self.assertEqual(rc.migration_kind(sql), "non-additive: a drop (drop table)")

    def test_a_line_comment_ends_at_its_line_so_the_next_line_still_counts(self):
        # SQLite ends a -- comment at the newline. A lexer that let it run on to the end of
        # the chunk would drop every statement after it, and read this file as additive.
        drop = "non-additive: a drop (drop table)"
        cases = {
            "after a statement": "CREATE TABLE `a` (`x` integer); -- note\nDROP TABLE `users`;",
            "before the first statement": "-- note\nDROP TABLE `users`;",
            "between two statements": "CREATE TABLE `a` (`x` integer);\n-- note\nDROP TABLE `users`;\nCREATE TABLE `b` (`y` integer);",
            "one comment line after another": "-- one\n-- two\nDROP TABLE `users`;",
            "inside a statement": "CREATE TABLE `a` (`x` integer -- note\n); DROP TABLE `users`;",
        }
        for name, sql in cases.items():
            with self.subTest(name):
                self.assertEqual(rc.migration_kind(sql), drop)
        # The comment does end at the end of the file when no newline follows it.
        self.assertEqual(rc.migration_kind("CREATE TABLE `a` (`x` integer); -- DROP TABLE `users`;"), "additive")

    def test_a_statement_breakpoint_ends_a_statement_with_no_semicolon(self):
        sql = "CREATE TABLE `a` (`x` integer)\n--> statement-breakpoint\nDROP TABLE `users`;"
        self.assertEqual(rc.migration_kind(sql), "non-additive: a drop (drop table)")

    def test_ai_tc_splits_on_the_breakpoint_wherever_it_stands_so_the_rest_of_the_line_counts(self):
        # ai-tc runs the text after each "-->\s*statement-breakpoint" as its own chunk, even
        # when it follows a statement on the same line or sits inside a comment.
        drop = "non-additive: a drop (drop table)"
        cases = {
            "after a statement on the same line": "CREATE TABLE `a` (`x` integer);--> statement-breakpoint DROP TABLE `users`;",
            "inside a line comment": "CREATE TABLE `a` (`x` integer); -- why --> statement-breakpoint DROP TABLE `users`;",
            "with a newline between the words": "CREATE TABLE `a` (`x` integer)-->\nstatement-breakpoint DROP TABLE `users`;",
            "with no space at all": "CREATE TABLE `a` (`x` integer)-->statement-breakpoint DROP TABLE `users`;",
            # JavaScript's \s counts U+FEFF as white space and Python's does not.
            "split by a byte-order mark": f"CREATE TABLE `a` (`x` integer);-->{chr(0xFEFF)}statement-breakpoint DROP TABLE `users`;",
        }
        for name, sql in cases.items():
            with self.subTest(name):
                self.assertEqual(rc.migration_kind(sql), drop)

    def test_a_breakpoint_inside_a_comment_cannot_hide_the_statement_after_it(self):
        # The chunk before the breakpoint ends inside a block comment, which is refused.
        sql = "CREATE TABLE `a` (`x` integer); /* --> statement-breakpoint DROP TABLE `users`; -- */"
        self.assertTrue(rc.migration_kind(sql).startswith("non-additive"), rc.migration_kind(sql))

    def test_a_semicolon_inside_a_string_does_not_end_the_statement(self):
        self.assertEqual(rc.migration_kind("CREATE TABLE `t` (`a` text DEFAULT ';DROP TABLE x');"), "additive")

    def test_a_doubled_quote_is_an_escape_not_the_end_of_the_literal(self):
        self.assertEqual(rc.migration_kind("CREATE TABLE `t` (`a` text DEFAULT 'it''s; DROP TABLE x');"), "additive")
        self.assertEqual(rc.migration_kind('CREATE TABLE "t""x;y" ("a" text);'), "additive")
        self.assertEqual(rc.migration_kind("CREATE TABLE `t``x;y` (`a` text);"), "additive")

    def test_quoted_names_keep_their_words_so_a_rebuild_is_still_seen(self):
        self.assertEqual(
            rc.migration_kind("CREATE TABLE `__new_widgets` (`id` text);"),
            "non-additive: a table rebuild (drizzle's __new_ copy)",
        )
        self.assertEqual(
            rc.migration_kind("CREATE TABLE [__new_widgets] (id text);"),
            "non-additive: a table rebuild (drizzle's __new_ copy)",
        )

    def test_words_inside_a_string_or_a_comment_decide_nothing(self):
        self.assertEqual(rc.migration_kind("CREATE TABLE `t` (`a` text DEFAULT 'DROP TABLE __new_x');"), "additive")
        self.assertEqual(rc.migration_kind("CREATE TABLE `t` (`a` text); /* DROP TABLE `users`; */ -- DROP TABLE `x`;"), "additive")

    def test_only_the_foreign_keys_pragma_is_additive(self):
        pragma = "non-additive: a PRAGMA other than foreign_keys=ON/OFF"
        cases = {
            "PRAGMA foreign_keys=OFF;": "additive",
            "PRAGMA foreign_keys=ON;": "additive",
            "pragma foreign_keys = off;": "additive",
            "PRAGMA foreign_keys  =  On ;": "additive",
            "PRAGMA user_version=9;": pragma,
            "PRAGMA writable_schema=1;": pragma,
            "PRAGMA journal_mode=DELETE;": pragma,
            "PRAGMA foreign_keys;": pragma,
            "PRAGMA foreign_keys=1;": pragma,
            "PRAGMA main.foreign_keys=OFF;": pragma,
            "PRAGMA foreign_keys=OFF AND 1;": pragma,
        }
        for sql, kind in cases.items():
            with self.subTest(sql):
                self.assertEqual(rc.migration_kind(sql), kind)

    def test_a_quote_or_comment_that_never_closes_is_not_additive(self):
        unterminated = "non-additive: an unterminated quoted string or comment"
        cases = {
            "string": "CREATE TABLE `t` (`a` text DEFAULT 'x);",
            "backtick name": "CREATE TABLE `t (`a` text);",
            "double-quoted name": 'CREATE TABLE "t (a text);',
            "bracketed name": "CREATE TABLE [t (a text);",
            "block comment": "CREATE TABLE `t` (`a` text); /* DROP TABLE `users`;",
        }
        for name, sql in cases.items():
            with self.subTest(name):
                self.assertEqual(rc.migration_kind(sql), unterminated)


JOURNAL = f"{rc.MIGRATIONS_DIR}/meta/_journal.json"
FROM, TO = ts.ATTESTED["0.9.13"], ts.ATTESTED["0.9.14"]
BASE_TAGS = ("0000_initial", "0034_migration")


def journal(*tags):
    return {"version": "7", "dialect": "sqlite", "entries": [{"idx": i, "tag": t} for i, t in enumerate(tags)]}


def blob(tag, variant=""):
    """A stable fake git blob sha for one migration file."""
    return hashlib.sha1(f"{tag}{variant}".encode()).hexdigest()


def directory(tags, edited=()):
    """What the Contents API answers for the migrations directory: the meta folder, then
    one file per tag, each with its git blob sha. A tag in `edited` has a different one."""
    files = [
        {
            "name": f"{tag}.sql",
            "path": f"{rc.MIGRATIONS_DIR}/{tag}.sql",
            "sha": blob(tag, "edited" if tag in edited else ""),
            "type": "file",
        }
        for tag in tags
    ]
    return [{"name": "meta", "path": f"{rc.MIGRATIONS_DIR}/meta", "sha": blob("meta"), "type": "dir"}, *files]


STORE_CODE = "packages/persistence/src/migrations.ts"
TRIGGER_CODE = "packages/persistence/src/sync-failure.ts"


def store_directory(*, changed=(), omit=()):
    """What the Contents API answers for ai-tc's persistence source: the two store-code files, spelled
    out here so the test does not read the names from the code it tests, and a neighbour that is not
    one, each with a git blob sha. A name in `changed` has a different
    sha; a name in `omit` is not there."""
    return [
        {
            "name": name,
            "path": f"{rc.STORE_CODE_DIR}/{name}",
            "sha": blob(name, "changed" if name in changed else ""),
            "type": "file",
        }
        for name in ("database.ts", "migrations.ts", "sync-failure.ts")
        if name not in omit
    ]


class TestClassifyMigrations(unittest.TestCase):
    def fetch(self, from_tags, to_tags, sql, *, edited=(), store_changed=(), routes=None):
        """Journals, listings and added files for a pair of releases. `edited` tags carry a
        different blob sha at TO, and so do the `store_changed` files of the store code; the
        store code is otherwise the same at both. `routes` replaces any of the answers."""
        answers = {
            ts.contents_url(JOURNAL, FROM): (200, journal(*from_tags)),
            ts.contents_url(JOURNAL, TO): (200, journal(*to_tags)),
            ts.contents_url(rc.MIGRATIONS_DIR, FROM): (200, directory(from_tags)),
            ts.contents_url(rc.MIGRATIONS_DIR, TO): (200, directory(to_tags, edited)),
            ts.contents_url(rc.STORE_CODE_DIR, FROM): (200, store_directory()),
            ts.contents_url(rc.STORE_CODE_DIR, TO): (200, store_directory(changed=store_changed)),
        }
        for tag, text in sql.items():
            answers[ts.contents_url(f"{rc.MIGRATIONS_DIR}/{tag}.sql", TO)] = (200, text.encode())
        answers.update(routes or {})
        return ts.FakeFetch(answers)

    def test_no_new_migration_is_additive(self):
        result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS, {}))
        self.assertEqual((result.classification, result.migrations), ("additive", []))

    def test_every_migration_counts_until_downgrades_are_measured(self):
        tag = "0035_migration"
        result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS + (tag,), {tag: SQL_NULLABLE}))
        self.assertEqual((result.classification, result.migrations), ("not-rollback-safe", [tag]))
        self.assertEqual(result.kinds, {tag: "additive"})

    def test_once_measured_only_non_additive_kinds_count(self):
        additive, dropping = "0035_migration", "0036_migration"
        with mock.patch.object(rc, "EVERY_MIGRATION_COUNTS", False):
            first = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS + (additive,), {additive: SQL_NULLABLE}))
            second = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS + (dropping,), {dropping: SQL_DROP_INDEX}))
        self.assertEqual((first.classification, second.classification), ("additive", "not-rollback-safe"))

    def test_file_reads_use_the_raw_media_type_and_listings_use_json(self):
        tag = "0035_migration"
        fetch = self.fetch(BASE_TAGS, BASE_TAGS + (tag,), {tag: SQL_NULLABLE})
        rc.classify_migrations(FROM, TO, fetch=fetch)
        directories = (rc.MIGRATIONS_DIR, rc.STORE_CODE_DIR)
        listings = [(url, h) for url, h in fetch.calls if url.split("?")[0].endswith(tuple(f"/contents/{d}" for d in directories))]
        files = [(url, h) for url, h in fetch.calls if (url, h) not in listings]
        # One listing of each directory per attested commit, however many migrations the journals hold.
        self.assertEqual(
            sorted(url for url, _ in listings),
            sorted(ts.contents_url(d, c) for d in directories for c in (FROM, TO)),
        )
        self.assertTrue(all(h.get("Accept") == "application/vnd.github+json" for _, h in listings))
        self.assertEqual(len(files), 3)  # the two journals and the one added file
        self.assertTrue(all(h.get("Accept") == "application/vnd.github.raw+json" for _, h in files))

    def test_an_unreadable_journal_counts_as_not_rollback_safe(self):
        fetch = ts.FakeFetch({ts.contents_url(JOURNAL, TO): (200, journal(*BASE_TAGS))})
        result = rc.classify_migrations(FROM, TO, fetch=fetch)
        self.assertEqual((result.classification, result.migrations), ("not-rollback-safe", []))
        self.assertIn("cannot be read", result.note)

    def test_an_unreadable_migration_file_is_not_additive(self):
        tag = "0036_migration"
        with mock.patch.object(rc, "EVERY_MIGRATION_COUNTS", False):
            result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS + (tag,), {}))
        self.assertEqual(result.classification, "not-rollback-safe")
        self.assertIn("cannot be read", result.kinds[tag])

    def test_a_migration_edited_in_place_is_not_rollback_safe(self):
        # A store that already applied the tag never re-runs an edit, so a fresh store and
        # an old one diverge: the release is not safe to roll back across, whatever the edit.
        for counts in (True, False):
            with self.subTest(every_migration_counts=counts), mock.patch.object(rc, "EVERY_MIGRATION_COUNTS", counts):
                result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS, {}, edited=("0000_initial",)))
                self.assertEqual((result.classification, result.migrations), ("not-rollback-safe", ["0000_initial"]))
                self.assertTrue(result.kinds["0000_initial"].startswith("non-additive: modified in place"), result.kinds)
                self.assertNotIn("0034_migration", result.kinds)

    def test_an_edited_migration_is_listed_after_the_added_and_removed_ones(self):
        added, removed = "0035_migration", "0033_migration"
        result = rc.classify_migrations(
            FROM,
            TO,
            fetch=self.fetch(BASE_TAGS + (removed,), BASE_TAGS + (added,), {added: SQL_NULLABLE}, edited=("0000_initial",)),
        )
        self.assertEqual(result.migrations, [added, removed, "0000_initial"])
        self.assertEqual(result.kinds[added], "additive")

    def test_a_store_change_in_code_with_no_migration_is_not_rollback_safe(self):
        # ai-tc changes the store in code as well as through the journal. A release whose only
        # store change is there has no new tag, and counts whatever the flag says.
        for counts in (True, False):
            with self.subTest(every_migration_counts=counts), mock.patch.object(rc, "EVERY_MIGRATION_COUNTS", counts):
                fetch = self.fetch(BASE_TAGS, BASE_TAGS, {}, store_changed=("migrations.ts",))
                result = rc.classify_migrations(FROM, TO, fetch=fetch)
                self.assertEqual((result.classification, result.migrations), ("not-rollback-safe", []))
                self.assertEqual(result.kinds, {STORE_CODE: rc.STORE_CODE_CHANGED})
                self.assertIn("store code", result.note)

    def test_store_code_is_recorded_in_kinds_and_never_in_migrations(self):
        # The journal list stays a list of journal tags, so what is written to the safety file
        # is the same with or without a code change beside a migration.
        tag = "0035_migration"
        for counts in (True, False):
            with self.subTest(every_migration_counts=counts), mock.patch.object(rc, "EVERY_MIGRATION_COUNTS", counts):
                fetch = self.fetch(BASE_TAGS, BASE_TAGS + (tag,), {tag: SQL_NULLABLE}, store_changed=("migrations.ts",))
                result = rc.classify_migrations(FROM, TO, fetch=fetch)
                self.assertEqual((result.classification, result.migrations), ("not-rollback-safe", [tag]))
                self.assertEqual(result.kinds, {tag: "additive", STORE_CODE: rc.STORE_CODE_CHANGED})

    def test_a_change_to_the_trigger_condition_counts(self):
        # sync-failure.ts holds the condition the trigger in migrations.ts is built from.
        result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS, {}, store_changed=("sync-failure.ts",)))
        self.assertEqual((result.classification, result.migrations), ("not-rollback-safe", []))
        self.assertEqual(result.kinds, {TRIGGER_CODE: rc.STORE_CODE_CHANGED})

    def test_a_store_code_file_that_appears_or_vanishes_counts(self):
        # sync-failure.ts first shipped in a release of its own; a file that is in only one of
        # the two commits is a change. One that is in neither is not a change.
        cases = {
            "appears": (store_directory(omit=("sync-failure.ts",)), store_directory(), True),
            "vanishes": (store_directory(), store_directory(omit=("sync-failure.ts",)), True),
            "was never there": (store_directory(omit=("sync-failure.ts",)), store_directory(omit=("sync-failure.ts",)), False),
        }
        for name, (earlier, later, counts) in cases.items():
            with self.subTest(name):
                routes = {ts.contents_url(rc.STORE_CODE_DIR, FROM): (200, earlier), ts.contents_url(rc.STORE_CODE_DIR, TO): (200, later)}
                result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS, {}, routes=routes))
                self.assertEqual(result.classification, "not-rollback-safe" if counts else "additive")
                self.assertEqual(result.kinds, {TRIGGER_CODE: rc.STORE_CODE_CHANGED} if counts else {})

    def test_store_code_that_moved_or_vanished_counts(self):
        # If ai-tc moves migrations.ts, nothing here can say what the store does at open.
        gone = (404, {"message": "Not Found"})
        cases = {
            "the file is missing from the later listing": (ts.contents_url(rc.STORE_CODE_DIR, TO), (200, store_directory(omit=("migrations.ts",)))),
            "the later commit has no such directory": (ts.contents_url(rc.STORE_CODE_DIR, TO), gone),
            "the file is a directory at the later commit": (
                ts.contents_url(rc.STORE_CODE_DIR, TO),
                (200, [dict(e, type="dir") if e["name"] == "migrations.ts" else e for e in store_directory()]),
            ),
        }
        for name, (url, answer) in cases.items():
            for counts in (True, False):
                with self.subTest(name, every_migration_counts=counts), mock.patch.object(rc, "EVERY_MIGRATION_COUNTS", counts):
                    result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS, {}, routes={url: answer}))
                    self.assertEqual((result.classification, result.migrations), ("not-rollback-safe", []))
                    self.assertEqual(result.kinds[STORE_CODE], rc.STORE_CODE_MISSING)
        # No such directory at the earlier commit: what the store did then is unknown too.
        routes = {ts.contents_url(rc.STORE_CODE_DIR, FROM): gone}
        result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS, {}, routes=routes))
        self.assertEqual((result.classification, result.migrations), ("not-rollback-safe", []))
        self.assertEqual(result.kinds[STORE_CODE], rc.STORE_CODE_CHANGED)

    def test_unchanged_store_code_keeps_a_release_with_no_migration_additive(self):
        # The 0.9.12 -> 0.9.13 shape: other files in the same directory changed with no store
        # change, so only the named files are compared, not the directory.
        result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS, {}, store_changed=("database.ts",)))
        self.assertEqual((result.classification, result.migrations, result.kinds), ("additive", [], {}))

    def test_a_store_code_listing_outage_is_no_verdict(self):
        good = store_directory()
        junk = lambda value: [dict(e, sha=value) if e["name"] == "migrations.ts" else e for e in good]
        crowd = [{"name": f"x{i}.ts", "path": f"{rc.STORE_CODE_DIR}/x{i}.ts", "sha": blob(f"x{i}"), "type": "file"} for i in range(1000)]
        cases = {
            "a 403": (403, b""),
            "a 500": (500, b""),
            "a 502": (502, b""),
            "not JSON": (200, b"not json"),
            "a single file, not a directory": (200, {"name": "migrations.ts", "type": "file", "sha": blob("x")}),
            "null": (200, b"null"),
            "an entry that is not an object": (200, [*good, "x.ts"]),
            "a listing at the API's cap": (200, good + crowd[: 1000 - len(good)]),
            "a sha that is not 40 hex": (200, junk("not-a-sha")),
            "a sha that is not a string": (200, junk(7)),
        }
        for name, answer in cases.items():
            for commit in (FROM, TO):
                with self.subTest(name, commit=commit[:8]):
                    fetch = self.fetch(BASE_TAGS, BASE_TAGS, {}, routes={ts.contents_url(rc.STORE_CODE_DIR, commit): answer})
                    with self.assertRaises(rc.InfraError) as caught:
                        rc.classify_migrations(FROM, TO, fetch=fetch)
                    self.assertEqual(caught.exception.check, "classify")

    def test_a_shipped_migration_the_listing_does_not_hold_is_not_additive(self):
        # The journal names it but the directory has no such file (or the directory cannot
        # be listed at all): unreadable, which counts as not rollback-safe. Not an outage.
        without = lambda tags: (200, [e for e in directory(tags) if e["name"] != "0000_initial.sql"])
        cases = {
            "missing at the earlier commit": ({ts.contents_url(rc.MIGRATIONS_DIR, FROM): without(BASE_TAGS)}, ["0000_initial"]),
            "missing at the later commit": ({ts.contents_url(rc.MIGRATIONS_DIR, TO): without(BASE_TAGS)}, ["0000_initial"]),
            "no directory at the earlier commit": ({ts.contents_url(rc.MIGRATIONS_DIR, FROM): (404, {"message": "Not Found"})}, list(BASE_TAGS)),
            "no directory at the later commit": ({ts.contents_url(rc.MIGRATIONS_DIR, TO): (404, {"message": "Not Found"})}, list(BASE_TAGS)),
        }
        for name, (routes, unreadable) in cases.items():
            for counts in (True, False):
                with self.subTest(name, every_migration_counts=counts), mock.patch.object(rc, "EVERY_MIGRATION_COUNTS", counts):
                    result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS, {}, routes=routes))
                    self.assertEqual((result.classification, result.migrations), ("not-rollback-safe", unreadable))
                    for tag in unreadable:
                        self.assertEqual(result.kinds[tag], "non-additive: the migration file cannot be read")

    def test_a_listing_error_is_no_verdict(self):
        for commit in (FROM, TO):
            for status in (403, 500, 502):
                with self.subTest(commit=commit[:8], status=status):
                    fetch = self.fetch(BASE_TAGS, BASE_TAGS, {}, routes={ts.contents_url(rc.MIGRATIONS_DIR, commit): (status, b"")})
                    with self.assertRaises(rc.InfraError) as caught:
                        rc.classify_migrations(FROM, TO, fetch=fetch)
                    self.assertEqual(caught.exception.check, "classify")

    def test_a_truncated_listing_is_no_verdict(self):
        # The Contents API lists at most 1000 entries of a directory and does not say it stopped.
        crowd = [{"name": f"x{i}.txt", "path": f"{rc.MIGRATIONS_DIR}/x{i}.txt", "sha": blob(f"x{i}"), "type": "file"} for i in range(1000)]
        for size, raises in ((1000, True), (999, False)):
            with self.subTest(entries=size):
                routes = {ts.contents_url(rc.MIGRATIONS_DIR, TO): (200, directory(BASE_TAGS) + crowd[: size - len(directory(BASE_TAGS))])}
                fetch = self.fetch(BASE_TAGS, BASE_TAGS, {}, routes=routes)
                if raises:
                    with self.assertRaises(rc.InfraError):
                        rc.classify_migrations(FROM, TO, fetch=fetch)
                else:
                    self.assertEqual(rc.classify_migrations(FROM, TO, fetch=fetch).classification, "additive")

    def test_a_listing_that_is_not_a_directory_listing_is_no_verdict(self):
        good = directory(BASE_TAGS)
        with_sha = lambda value: [dict(e, sha=value) if e["name"] == "0034_migration.sql" else e for e in good]
        cases = {
            "not JSON": (200, b"not json"),
            "a single file, not a directory": (200, {"name": "0000_initial.sql", "type": "file", "sha": blob("x")}),
            "null": (200, b"null"),
            "an entry that is not an object": (200, [*good, "0035_migration.sql"]),
            "a sha that is not 40 hex": (200, with_sha("not-a-sha")),
            "a sha that is not a string": (200, with_sha(7)),
            "an entry without a sha": (200, [{k: v for k, v in e.items() if k != "sha"} if e["name"] == "0034_migration.sql" else e for e in good]),
            "a duplicated key": (200, b'[{"name": "a", "name": "b"}]'),
        }
        for name, answer in cases.items():
            for commit in (FROM, TO):
                with self.subTest(name, commit=commit[:8]):
                    fetch = self.fetch(BASE_TAGS, BASE_TAGS, {}, routes={ts.contents_url(rc.MIGRATIONS_DIR, commit): answer})
                    with self.assertRaises(rc.InfraError):
                        rc.classify_migrations(FROM, TO, fetch=fetch)

    def test_a_tag_dropped_from_the_journal_is_not_rollback_safe(self):
        tag = "0035_migration"
        with mock.patch.object(rc, "EVERY_MIGRATION_COUNTS", False):
            result = rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS + (tag,), BASE_TAGS, {}))
        self.assertEqual((result.classification, result.migrations), ("not-rollback-safe", [tag]))

    def test_a_github_error_is_no_verdict(self):
        fetch = ts.FakeFetch({ts.contents_url(JOURNAL, FROM): (502, b"")})
        with self.assertRaises(rc.InfraError):
            rc.classify_migrations(FROM, TO, fetch=fetch)

    def test_only_full_commit_ids_are_accepted(self):
        fetch = ts.FakeFetch()
        with self.assertRaises(rc.ReleaseCheckError):
            rc.classify_migrations("a75532b9", TO, fetch=fetch)
        self.assertEqual(fetch.calls, [])

    def test_a_malformed_journal_is_a_verdict_not_a_crash(self):
        # The journal at an attested commit never changes, so a retry cannot help: refuse it.
        cases = {
            "not JSON": b"not json",
            "a list, not an object": b"[]",
            "null": b"null",
            "entries that is not a list": b'{"entries": "0000_initial"}',
            "an entry that is not an object": b'{"entries": [1]}',
            "an entry whose tag is not a string": b'{"entries": [{"tag": 5}]}',
            "a duplicated key": b'{"entries": [], "entries": []}',
            "nested too deep to parse": b"[" * 100000 + b"]" * 100000,
            "not UTF-8": b"\xff\xfe{}",
        }
        for name, answer in cases.items():
            for commit in (FROM, TO):
                with self.subTest(name, commit=commit[:8]):
                    fetch = self.fetch(BASE_TAGS, BASE_TAGS, {}, routes={ts.contents_url(JOURNAL, commit): (200, answer)})
                    with self.assertRaises(rc.ReleaseCheckError) as caught:
                        rc.classify_migrations(FROM, TO, fetch=fetch)
                    self.assertEqual(caught.exception.check, "classify")
                    self.assertIn(commit, caught.exception.detail)

    def test_a_migration_file_that_is_not_utf8_is_a_verdict_not_a_crash(self):
        tag = "0035_migration"
        fetch = self.fetch(
            BASE_TAGS,
            BASE_TAGS + (tag,),
            {},
            routes={ts.contents_url(f"{rc.MIGRATIONS_DIR}/{tag}.sql", TO): (200, b"CREATE TABLE \xff\xfe;")},
        )
        with self.assertRaises(rc.ReleaseCheckError) as caught:
            rc.classify_migrations(FROM, TO, fetch=fetch)
        self.assertEqual(caught.exception.check, "classify")
        self.assertIn(f"{tag}.sql", caught.exception.detail)

    def test_a_journal_tag_that_is_not_a_migration_name_is_refused(self):
        with self.assertRaises(rc.ReleaseCheckError):
            rc.classify_migrations(FROM, TO, fetch=self.fetch(BASE_TAGS, BASE_TAGS + ("../../x",), {}))


def fake_verify(version):
    return rc.VerifiedRelease(version, ts.INTEGRITY, ts.SHASUM, ts.ATTESTED[version], ts.RUN_URL)


class TestSafetyEntry(unittest.TestCase):
    def test_computed_from_the_highest_pinned_version_below(self):
        calls = []

        def classify(start, end):
            calls.append((start, end))
            return rc.Classification("not-rollback-safe", ["0029_migration"])

        entry = rc.safety_entry("0.9.12", {"0.9.9", "0.9.10", "0.9.14"}, verify=fake_verify, classify=classify)
        self.assertEqual(calls, [(ts.ATTESTED["0.9.10"], ts.ATTESTED["0.9.12"])])
        self.assertEqual(list(entry), ["classification", "from", "to", "migrations"])
        self.assertEqual(
            entry,
            {
                "classification": "not-rollback-safe",
                "from": ts.ATTESTED["0.9.10"],
                "to": ts.ATTESTED["0.9.12"],
                "migrations": ["0029_migration"],
            },
        )

    def test_nothing_pinned_below_is_refused(self):
        with self.assertRaises(rc.ReleaseCheckError):
            rc.safety_entry("0.9.8", {"0.9.9"}, verify=fake_verify, classify=lambda a, b: None)


class TestRollbackFloor(unittest.TestCase):
    SAFETY = {"versions": copy.deepcopy(ts.SEED)}

    def test_the_seed_refuses_a_rollback_from_0_9_14_to_0_9_13(self):
        self.assertEqual(rc.rollback_floor(self.SAFETY, "0.9.13", "0.9.14", pinned=set()), "0.9.14")

    def test_the_lowest_flagged_version_in_range_is_the_floor(self):
        self.assertEqual(rc.rollback_floor(self.SAFETY, "0.9.8", "0.9.14", pinned=set()), "0.9.9")

    def test_additive_versions_set_no_floor(self):
        self.assertIsNone(rc.rollback_floor({"versions": {"0.9.13": dict(ts.SEED["0.9.13"])}}, "0.9.12", "0.9.13", pinned=set()))

    def test_the_target_itself_is_never_the_floor(self):
        self.assertIsNone(rc.rollback_floor({"versions": {"0.9.12": dict(ts.SEED["0.9.12"])}}, "0.9.12", "0.9.13", pinned=set()))

    def test_a_flag_above_the_highest_pinned_version_is_ignored(self):
        self.assertIsNone(rc.rollback_floor({"versions": {"0.9.15": dict(ts.SEED["0.9.14"])}}, "0.9.13", "0.9.14", pinned=set()))

    def test_a_malformed_or_missing_entry_counts_as_flagged(self):
        self.assertEqual(rc.rollback_floor({"versions": {"0.9.14": "additive"}}, "0.9.13", "0.9.14", pinned=set()), "0.9.14")
        # A pinned version with no entry at all (a break-glass pin, a restore) is flagged too.
        additive = {"versions": {"0.9.13": dict(ts.SEED["0.9.13"])}}
        pinned = {"0.9.12", "0.9.13", "0.9.14"}
        self.assertEqual(rc.rollback_floor(additive, "0.9.12", "0.9.14", pinned=pinned), "0.9.14")
        self.assertIsNone(rc.rollback_floor(additive, "0.9.12", "0.9.13", pinned=pinned))

    def test_the_pinned_set_must_be_named(self):
        # With no pinned set a version missing from the file sets no floor, which is a weaker
        # floor than the same call with the set. A caller has to say which set it means.
        with self.assertRaises(TypeError):
            rc.rollback_floor({"versions": {}}, "0.9.13", "0.9.14")
        with self.assertRaises(TypeError):
            rc.rollback_floor({"versions": {}}, "0.9.13", "0.9.14", {"0.9.14"})
        self.assertEqual(rc.rollback_floor({"versions": {}}, "0.9.13", "0.9.14", pinned={"0.9.14"}), "0.9.14")
        self.assertIsNone(rc.rollback_floor({"versions": {}}, "0.9.13", "0.9.14", pinned=set()))

    def test_a_malformed_file_is_refused(self):
        with self.assertRaises(rc.ReleaseCheckError):
            rc.rollback_floor({"0.9.14": {}}, "0.9.13", "0.9.14", pinned=set())

    def test_only_a_well_formed_additive_entry_is_trusted(self):
        # A version is safe to roll back across only on an entry that safety_problems accepts
        # and that says "additive". One malformed entry flags its own version; it does not
        # refuse the whole file, which would block every rollback (the incident path).
        good = dict(ts.SEED["0.9.14"], classification="additive", migrations=[])
        malformed = {
            "only the classification": {"classification": "additive"},
            "an extra key": {**good, "note": 1},
            "keys out of order": {key: good[key] for key in ("from", "classification", "to", "migrations")},
            "a commit that is not 40 hex": {**good, "from": "abc"},
            "a migration that is not a tag": {**good, "migrations": ["../x"]},
            "migrations that is not a list": {**good, "migrations": "0035_migration"},
        }
        for name, entry in malformed.items():
            with self.subTest(name):
                self.assertNotEqual(rc.safety_problems({"versions": {"0.9.14": entry}}), [])
                self.assertEqual(rc.rollback_floor({"versions": {"0.9.14": entry}}, "0.9.13", "0.9.14", pinned=set()), "0.9.14")
        self.assertEqual(rc.safety_problems({"versions": {"0.9.14": good}}), [])
        self.assertIsNone(rc.rollback_floor({"versions": {"0.9.14": good}}, "0.9.13", "0.9.14", pinned=set()))

    def test_a_malformed_entry_flags_only_its_own_version(self):
        versions = {"0.9.13": dict(ts.SEED["0.9.13"]), "0.9.14": {"classification": "additive"}}
        self.assertIsNone(rc.rollback_floor({"versions": versions}, "0.9.12", "0.9.13", pinned=set()))
        self.assertEqual(rc.rollback_floor({"versions": versions}, "0.9.12", "0.9.14", pinned=set()), "0.9.14")


class TestSafetyProblems(unittest.TestCase):
    def test_the_seed_is_well_formed(self):
        self.assertEqual(rc.safety_problems({"versions": ts.SEED}), [])

    def test_each_problem_names_its_version_and_field(self):
        good = dict(ts.SEED["0.9.14"])
        self.assertEqual(
            rc.safety_problems({"versions": {"0.9": good}}),
            ["rollback-safety.json '0.9': not an exact x.y.z"],
        )
        self.assertEqual(
            rc.safety_problems({"versions": {"0.9.14": {**good, "classification": "safe", "from": "abc"}}}),
            [
                "rollback-safety.json '0.9.14': classification must be additive or not-rollback-safe",
                "rollback-safety.json '0.9.14': from must be a 40-hex commit id",
            ],
        )
        # Every entry is read, not just the first one with a problem.
        self.assertEqual(
            rc.safety_problems({"versions": {"0.9": good, "0.9.14": good, "0.9.15": {}}}),
            [
                "rollback-safety.json '0.9': not an exact x.y.z",
                f"rollback-safety.json '0.9.15': keys must be exactly {rc.SAFETY_KEYS}, in that order",
            ],
        )

    def test_each_malformation_is_named(self):
        good = dict(ts.SEED["0.9.14"])
        cases = {
            "shape": {"versions": []},
            "extra top-level key": {"versions": {}, "notes": "x"},
            "version": {"versions": {"0.9": good}},
            "key order": {"versions": {"0.9.14": {k: good[k] for k in ("from", "classification", "to", "migrations")}}},
            "classification": {"versions": {"0.9.14": {**good, "classification": "safe"}}},
            "commit": {"versions": {"0.9.14": {**good, "from": "abc"}}},
            "migration": {"versions": {"0.9.14": {**good, "migrations": ["../x"]}}},
        }
        for name, doc in cases.items():
            with self.subTest(name):
                self.assertNotEqual(rc.safety_problems(doc), [])


class TestDiffMode(unittest.TestCase):
    def removed(self):
        doc = ts.manifest()
        del doc["plugins"][2]
        return doc

    def test_identical_is_none(self):
        self.assertEqual(rc.diff_mode(ts.manifest(), ts.manifest()), "none")

    def test_other_entries_and_top_level_edits_alone_are_none(self):
        head = ts.manifest()
        head["plugins"][0]["description"] = "new words"
        head["metadata"]["version"] = "0.2.0"
        self.assertEqual(rc.diff_mode(ts.manifest(), head), "none")

    def test_reordered_plugins_are_none(self):
        head = ts.manifest()
        head["plugins"].reverse()
        self.assertEqual(rc.diff_mode(ts.manifest(), head), "none")

    def test_up_with_its_integrity_is_advance(self):
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), ts.manifest("0.9.15", integrity=ts.OTHER_INTEGRITY)), "advance")

    def test_down_is_rollback(self):
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), ts.manifest("0.9.13", integrity=ts.OTHER_INTEGRITY)), "rollback")

    def test_a_base_without_metadata_still_advances(self):
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14", integrity=None), ts.manifest("0.9.15")), "advance")

    def test_an_advance_that_also_touches_another_entry_is_human(self):
        head = ts.manifest("0.9.15")
        head["plugins"][0]["description"] = "new words"
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), head), "human")

    def test_an_advance_that_changes_a_top_level_key_is_human(self):
        head = ts.manifest("0.9.15")
        head["metadata"]["version"] = "0.2.0"
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), head), "human")

    def test_an_advance_that_changes_the_registry_is_human(self):
        head = ts.manifest("0.9.15")
        ts.ai_tc(head)["source"]["registry"] = "https://npm.pkg.github.com"
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), head), "human")

    def test_an_advance_that_adds_a_key_is_human(self):
        head = ts.manifest("0.9.15")
        ts.ai_tc(head)["hooks"] = "./hooks/extra.json"
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), head), "human")

    def test_a_version_move_without_integrity_is_human(self):
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), ts.manifest("0.9.15", integrity=None)), "human")

    def test_extra_metadata_is_human(self):
        head = ts.manifest("0.9.15")
        ts.ai_tc(head)["metadata"]["note"] = "x"
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), head), "human")

    def test_a_new_integrity_at_the_same_version_is_human(self):
        self.assertEqual(rc.diff_mode(ts.manifest("0.9.14"), ts.manifest("0.9.14", integrity=ts.OTHER_INTEGRITY)), "human")

    def test_a_type_change_in_the_ai_tc_entry_is_human(self):
        # Python's == says True == 1 == 1.0; JSON, and so the rest of the manifest, tells them
        # apart. The real entry has no boolean or number today, so this needs a reviewed edit
        # first, but then the comparison must still be exact.
        def with_strict(version, value, integrity=ts.INTEGRITY):
            doc = ts.manifest(version, integrity=integrity)
            ts.ai_tc(doc)["strict"] = value
            return doc

        cases = {
            "true to 1, same version": (with_strict("0.9.14", True), with_strict("0.9.14", 1)),
            "true to 1, with an advance": (with_strict("0.9.14", True), with_strict("0.9.15", 1, ts.OTHER_INTEGRITY)),
            "1 to 1.0, with an advance": (with_strict("0.9.14", 1), with_strict("0.9.15", 1.0, ts.OTHER_INTEGRITY)),
            "false to 0, with an advance": (with_strict("0.9.14", False), with_strict("0.9.15", 0, ts.OTHER_INTEGRITY)),
        }
        for name, (base, head) in cases.items():
            with self.subTest(name):
                self.assertEqual(rc.diff_mode(base, head), "human")
        # The same value, spelled the same, is still none or advance.
        self.assertEqual(rc.diff_mode(with_strict("0.9.14", True), with_strict("0.9.14", True)), "none")
        self.assertEqual(rc.diff_mode(with_strict("0.9.14", 1.0), with_strict("0.9.15", 1.0, ts.OTHER_INTEGRITY)), "advance")

    def test_a_description_edit_is_human(self):
        self.assertEqual(rc.diff_mode(ts.manifest(), ts.manifest(description="Better words.")), "human")

    def test_removing_only_the_entry_is_remove(self):
        self.assertEqual(rc.diff_mode(ts.manifest(), self.removed()), "remove")

    def test_removing_the_entry_and_editing_another_is_human(self):
        head = self.removed()
        head["plugins"][0]["description"] = "new words"
        self.assertEqual(rc.diff_mode(ts.manifest(), head), "human")

    def test_the_fixed_restore_shape_is_restore(self):
        self.assertEqual(rc.diff_mode(self.removed(), ts.manifest("0.9.14")), "restore")

    def test_a_restore_without_the_registry_is_human(self):
        self.assertEqual(rc.diff_mode(self.removed(), ts.manifest("0.9.14", registry=False)), "human")

    def test_a_restore_with_a_description_that_is_not_a_non_empty_string_is_human(self):
        for bad in (None, 123, "", "   ", ["x"]):
            with self.subTest(description=bad):
                head = ts.manifest("0.9.14")
                ts.ai_tc(head)["description"] = bad
                self.assertEqual(rc.diff_mode(self.removed(), head), "human")

    def test_description_ok_wants_a_string_with_a_visible_character(self):
        entry = {}
        self.assertFalse(rc.description_ok(entry))
        self.assertFalse(rc.description_ok(None))
        self.assertFalse(rc.description_ok("a string, not an entry"))
        for bad in (None, 1, 1.5, True, "", " \t\n", [], ["x"], {}):
            with self.subTest(description=bad):
                self.assertFalse(rc.description_ok({"description": bad}))
        for good in ("x", " x ", "Clearer words."):
            with self.subTest(description=good):
                self.assertTrue(rc.description_ok({"description": good}))

    def test_description_ok_docstring_gives_the_reason_that_is_true(self):
        doc = " ".join((rc.description_ok.__doc__ or "").split())
        self.assertIn("The marketplace requires that.", doc)
        self.assertIn("Claude Code itself refuses only a null or non-string description", doc)
        self.assertIn("accepts an empty or blank one or none", doc)
        self.assertNotIn("anything else", doc)

    def test_a_restore_with_an_extra_key_is_human(self):
        head = ts.manifest("0.9.14")
        ts.ai_tc(head)["strict"] = False
        self.assertEqual(rc.diff_mode(self.removed(), head), "human")

    def test_nothing_before_or_after_is_none(self):
        self.assertEqual(rc.diff_mode(self.removed(), self.removed()), "none")

    def test_an_ambiguous_head_is_refused(self):
        head = ts.manifest("0.9.15")
        head["plugins"].append(copy.deepcopy(head["plugins"][2]))
        with self.assertRaises(rc.ReleaseCheckError):
            rc.diff_mode(ts.manifest(), head)


BOT = "aka-marketplace-bot[bot]"


class TestParseTagMessage(unittest.TestCase):
    def test_subject_and_fields(self):
        fields = rc.parse_tag_message("fleet-v9: ai-tc 0.9.15\n\nversion: 0.9.15\npr: #14\ndrill: true\n")
        self.assertEqual(fields["subject"], "fleet-v9: ai-tc 0.9.15")
        self.assertEqual((fields["version"], fields["pr"], fields["drill"]), ("0.9.15", "#14", "true"))

    def test_the_first_value_wins(self):
        self.assertEqual(rc.parse_tag_message("s\nversion: 1\nversion: 2")["version"], "1")


class TestAuditTags(unittest.TestCase):
    def setUp(self):
        self.repo = ts.Repo(self)
        for number, version in ((1, "0.9.6"), (2, "0.9.8"), (3, "0.9.9")):
            self.repo.commit(ts.manifest(version), message=f"pin {version}")
            self.repo.tag(f"fleet-v{number}", f"fleet-v{number}: a message cut by hand")
        self.scratch = ts.Repo(self)  # lists live outside the audited repository
        self.frozen = self.scratch.write("frozen.json", rc.dump_json(rc.snapshot_tags(self.repo.path)))
        self.fetch = ts.FakeFetch()
        patcher = mock.patch.object(rc, "BOT_LOGIN", BOT)
        patcher.start()
        self.addCleanup(patcher.stop)

    def audit(self, **kwargs):
        return rc.audit_tags(self.repo.path, self.frozen, fetch=self.fetch, check_rulesets=False, **kwargs)

    def cut(self, version, number, **kwargs):
        commit = self.repo.commit(ts.manifest(version), message=f"pin {version}")
        self.tag_at(commit, version, number, **kwargs)
        return commit

    def tag_at(self, commit, version, number, *, pr=12, author=BOT, merged=True, merge_commit=None, subject=None, recorded=None):
        recorded = recorded or version
        lines = [
            subject or f"fleet-v{number}: ai-tc {recorded}",
            "",
            f"version: {recorded}",
            f"integrity: {ts.INTEGRITY}",
            f"pr: {pr}",
            "approver: venuverse",
            "store-migration: additive",
        ]
        self.repo.tag(f"fleet-v{number}", "\n".join(lines), rev=commit)
        self.fetch.routes[f"{rc.MARKETPLACE_API}/pulls/{pr}"] = (
            200,
            {
                "number": pr,
                "user": {"login": author},
                "merged_at": "2026-10-01T00:00:00Z" if merged else None,
                "merge_commit_sha": merge_commit or commit,
            },
        )

    def test_untouched_frozen_tags_pass(self):
        self.assertEqual(self.audit(), [])

    def test_the_snapshot_has_the_frozen_list_shape(self):
        rows = rc.snapshot_tags(self.repo.path)
        self.assertEqual([r["tag"] for r in rows], ["fleet-v1", "fleet-v2", "fleet-v3"])
        self.assertTrue(all(set(r) == {"tag", "object", "commit"} and r["object"] != r["commit"] for r in rows))

    def test_a_moved_frozen_tag_is_caught(self):
        ts.git(self.repo.path, "tag", "-f", "-a", "fleet-v2", "-m", "moved", "HEAD")
        self.assertTrue(any("fleet-v2 changed since the frozen list" in p for p in self.audit()))

    def test_a_deleted_frozen_tag_is_caught(self):
        ts.git(self.repo.path, "tag", "-d", "fleet-v3")
        self.assertTrue(any("fleet-v3 is in the frozen list but no longer exists" in p for p in self.audit()))

    def test_any_other_tag_is_caught(self):
        self.repo.tag("main", "a shadow of the branch")
        self.assertTrue(any("tag 'main' exists" in p for p in self.audit()))

    def test_a_lightweight_fleet_tag_is_caught(self):
        self.repo.commit(ts.manifest("0.9.10"))
        self.repo.tag("fleet-v4", lightweight=True)
        self.assertTrue(any("fleet-v4 is a lightweight tag" in p for p in self.audit()))

    def test_a_gap_in_numbering_is_caught(self):
        self.cut("0.9.10", 5)
        self.assertTrue(any("not contiguous" in p for p in self.audit()))

    def test_a_bot_tag_at_its_merge_commit_passes(self):
        self.cut("0.9.10", 4)
        self.assertEqual(self.audit(), [])

    def test_a_removal_is_recorded_as_entry_removed(self):
        doc = ts.manifest()
        del doc["plugins"][2]
        self.tag_at(self.repo.commit(doc), "entry removed", 4)
        self.assertEqual(self.audit(), [])

    def drop_the_manifest(self):
        ts.git(self.repo.path, "rm", "-q", rc.MANIFEST)
        ts.git(self.repo.path, "commit", "-q", "-m", "drop the manifest")
        return self.repo.head()

    def test_a_tag_at_a_commit_without_the_manifest_records_entry_removed(self):
        # tag-release cuts a tag at a commit that holds no manifest as "entry removed", so the
        # audit reads that commit the same way. It is not a failure of git.
        self.tag_at(self.drop_the_manifest(), "entry removed", 4)
        self.assertEqual(self.audit(), [])

    def test_a_tag_at_a_commit_without_the_manifest_must_still_record_entry_removed(self):
        self.tag_at(self.drop_the_manifest(), "0.9.10", 4)
        self.assertEqual(
            self.audit(),
            ["fleet-v4 records version '0.9.10', but the manifest at its commit pins 'entry removed'"],
        )

    def test_a_new_tag_whose_manifest_is_nested_too_deeply_is_a_problem_not_a_crash(self):
        # Tags never change, so a tag whose manifest crashed the audit would crash every later
        # audit. It reads as an unreadable manifest, which cannot match the version the tag records.
        commit = self.repo.commit(files={rc.MANIFEST: NESTED_TOO_DEEP}, message="a manifest nested too deeply")
        self.tag_at(commit, "0.9.10", 4)
        self.assertEqual(
            self.audit(),
            [
                "fleet-v4 records version '0.9.10', but the manifest at its commit pins "
                "'an unreadable manifest (the document is too deeply nested to read)'"
            ],
        )

    def test_a_manifest_object_git_cannot_read_is_no_verdict_not_drift(self):
        # The tree lists the file and the blob is gone: git failed, which says nothing about the tag.
        commit = self.cut("0.9.10", 4)
        blob = ts.git(self.repo.path, "rev-parse", f"{commit}:{rc.MANIFEST}").strip()
        loose = os.path.join(self.repo.path, ".git", "objects", blob[:2], blob[2:])
        os.chmod(loose, 0o644)
        os.remove(loose)
        with self.assertRaises(rc.InfraError) as caught:
            self.audit()
        self.assertEqual(caught.exception.check, "git")

    def test_a_manifest_directory_git_cannot_list_is_no_verdict_not_drift(self):
        # The same failure one step earlier: the listing that looks for the file fails, so
        # nothing is known about the manifest, and reading it as "entry removed" would call
        # the tag's honest record drift.
        commit = self.cut("0.9.10", 4)
        forget_object(self.repo.path, ts.git(self.repo.path, "rev-parse", f"{commit}:{os.path.dirname(rc.MANIFEST)}").strip())
        with self.assertRaises(rc.InfraError) as caught:
            self.audit()
        self.assertEqual(caught.exception.check, "git")

    def test_a_tag_that_misstates_the_version_is_caught(self):
        self.cut("0.9.10", 4, recorded="0.9.11")
        self.assertTrue(any("records version '0.9.11'" in p for p in self.audit()))

    def test_a_malformed_subject_is_caught(self):
        self.cut("0.9.10", 4, subject="fleet-v4 ai-tc 0.9.10")
        self.assertTrue(any("subject" in p for p in self.audit()))

    def test_a_tag_off_main_is_caught(self):
        ts.git(self.repo.path, "checkout", "-q", "-b", "side")
        commit = self.repo.commit(ts.manifest("0.9.10"))
        ts.git(self.repo.path, "checkout", "-q", "main")
        self.tag_at(commit, "0.9.10", 4)
        self.assertTrue(any("not on main's first-parent history" in p for p in self.audit()))

    def test_a_tag_earlier_than_its_predecessor_is_caught(self):
        self.cut("0.9.10", 4)
        fleet_v3_commit = ts.git(self.repo.path, "rev-parse", "fleet-v3^{commit}").strip()
        self.tag_at(fleet_v3_commit, "0.9.9", 5, pr=13)
        self.assertTrue(any("fleet-v5's commit is not later on main than fleet-v4's" in p for p in self.audit()))

    def test_a_human_pr_is_caught(self):
        self.cut("0.9.10", 4, author="venuverse")
        self.assertTrue(any("not the bot App" in p for p in self.audit()))

    def test_an_unmerged_pr_is_caught(self):
        self.cut("0.9.10", 4, merged=False)
        self.assertTrue(any("is not merged" in p for p in self.audit()))

    def test_a_different_merge_commit_is_caught(self):
        self.cut("0.9.10", 4, merge_commit="d" * 40)
        self.assertTrue(any("is not merged with" in p for p in self.audit()))

    def pull_answer(self, answer, number=12):
        self.fetch.routes[f"{rc.MARKETPLACE_API}/pulls/{number}"] = answer

    def test_a_tag_naming_a_pull_request_that_does_not_exist_is_caught(self):
        self.cut("0.9.10", 4)
        self.pull_answer((404, {"message": "Not Found"}))
        self.assertEqual(self.audit(), ["fleet-v4 names PR #12, which does not exist"])

    def test_a_pull_request_read_that_fails_is_no_verdict_not_drift(self):
        self.cut("0.9.10", 4)
        for status in (401, 403, 429, 500, 502):
            with self.subTest(status=status):
                self.pull_answer((status, {"message": "no"}))
                with self.assertRaises(rc.InfraError) as caught:
                    self.audit()
                self.assertEqual(caught.exception.check, "api")
                self.assertIn(str(status), caught.exception.detail)

    def test_a_pull_request_answer_that_is_not_a_json_object_is_no_verdict(self):
        self.cut("0.9.10", 4)
        for label, answer in (
            ("not JSON", (200, b"<html>")),
            ("a list", (200, [])),
            ("a string", (200, b'"merged"')),
            ("null", (200, b"null")),
            ("a duplicated key", (200, b'{"merged_at": null, "merged_at": "2026-10-01T00:00:00Z"}')),
            ("nested too deeply", (200, b"[" * 100000 + b"]" * 100000)),
        ):
            with self.subTest(answer=label):
                self.pull_answer(answer)
                with self.assertRaises(rc.InfraError) as caught:
                    self.audit()
                self.assertEqual(caught.exception.check, "api")

    def test_a_pull_request_whose_author_is_not_an_object_is_not_the_bot(self):
        commit = self.cut("0.9.10", 4)
        self.pull_answer((200, {"user": "the-bot", "merged_at": "2026-10-01T00:00:00Z", "merge_commit_sha": commit}))
        self.assertTrue(any("was opened by None, not the bot App" in p for p in self.audit()))

    def test_no_bot_identity_confirms_no_new_tag(self):
        self.cut("0.9.10", 4)
        with mock.patch.object(rc, "BOT_LOGIN", None):
            self.assertTrue(any("no bot identity is configured" in p for p in self.audit()))

    def test_a_break_glass_tag_clears_once_the_frozen_list_names_it(self):
        self.cut("0.9.10", 4, author="venuverse")
        self.scratch.write("frozen.json", rc.dump_json(rc.snapshot_tags(self.repo.path)))
        self.assertEqual(self.audit(), [])

    def test_an_unreadable_frozen_list_is_a_problem(self):
        self.frozen = os.path.join(self.scratch.path, "absent.json")
        self.assertTrue(any("unreadable" in p for p in self.audit()))

    def test_the_rulesets_are_audited_when_asked(self):
        self.fetch.routes.update(ruleset_routes())
        self.assertEqual(rc.audit_tags(self.repo.path, self.frozen, fetch=self.fetch), [])


# Only this repository's own rulesets: includes_parents=false leaves out the organisation's and the enterprise's.
RULESET_LISTING = f"{rc.MARKETPLACE_API}/rulesets?targets=branch,tag&includes_parents=false&per_page=100"


def ruleset_routes(overrides=None, missing=()):
    listing, routes = [], {}
    for number, (name, (target, types)) in enumerate(rc.EXPECTED_RULESETS.items(), start=1):
        if name in missing:
            continue
        listing.append({"id": number, "name": name, "target": target, "enforcement": "active"})
        rules = [{"type": t} for t in sorted(types)]
        if name == "main":
            rules = [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {
                    "type": "pull_request",
                    "parameters": {
                        "required_approving_review_count": 1,
                        "require_code_owner_review": True,
                        "dismiss_stale_reviews_on_push": True,
                        "require_last_push_approval": True,
                        "required_review_thread_resolution": False,
                        "allowed_merge_methods": ["squash"],
                    },
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": False,
                        "required_status_checks": [{"context": "validate", "integration_id": 15368}],
                    },
                },
            ]
        includes, exclude = rc.EXPECTED_REF_PATTERNS[name]
        body = {
            "id": number,
            "name": name,
            "target": target,
            "enforcement": "active",
            "conditions": {"ref_name": {"include": list(includes[0]), "exclude": list(exclude)}},
            "rules": rules,
        }
        body.update((overrides or {}).get(name, {}))
        routes[f"{rc.MARKETPLACE_API}/rulesets/{number}"] = (200, body)
    routes[RULESET_LISTING] = (200, listing)
    return routes


class TestAuditRulesets(unittest.TestCase):
    def test_the_seven_rulesets_as_specified_pass(self):
        self.assertEqual(rc.audit_rulesets(fetch=ts.FakeFetch(ruleset_routes())), [])
        # The include list is compared as a set: GitHub may return the globs in either order.
        globs = {"include": ["refs/tags/**/*", "refs/tags/*"], "exclude": ["refs/tags/fleet-v*"]}
        routes = ruleset_routes({"tags-locked": {"conditions": {"ref_name": globs}}})
        self.assertEqual(rc.audit_rulesets(fetch=ts.FakeFetch(routes)), [])

    def test_tags_locked_on_all_is_caught(self):
        # ~ALL would cover every tag on a tag ruleset too (GitHub's own tag recipes use it), but
        # tags-locked must list the two explicit globs, so what it covers is spelled out and
        # audited exactly. The audit reports the difference; it does not claim ~ALL locks nothing.
        on_all = {"include": ["~ALL"], "exclude": ["refs/tags/fleet-v*"]}
        routes = ruleset_routes({"tags-locked": {"conditions": {"ref_name": on_all}}})
        self.assertEqual(
            rc.audit_rulesets(fetch=ts.FakeFetch(routes)),
            ["ruleset 'tags-locked' covers include ['~ALL'] exclude ['refs/tags/fleet-v*'], "
             "not include ['refs/tags/*', 'refs/tags/**/*'] exclude ['refs/tags/fleet-v*']"],
        )

    def test_a_missing_ruleset_is_caught(self):
        problems = rc.audit_rulesets(fetch=ts.FakeFetch(ruleset_routes(missing=("x4-tags",))))
        self.assertEqual(problems, ["ruleset 'x4-tags' does not exist"])

    def test_a_duplicated_ruleset_name_is_flagged(self):
        # Two rulesets named "main" cannot both be the one audited, and the last must not win
        # silently: an inherited or stray ruleset of the same name would hide the real one.
        routes = ruleset_routes()
        listing = routes[RULESET_LISTING][1]
        # The stray one comes first: neither copy is audited, so it is never fetched.
        routes[RULESET_LISTING] = (200, [{"id": 99, "name": "main"}] + listing)
        fetch = ts.FakeFetch(routes)
        self.assertEqual(rc.audit_rulesets(fetch=fetch), ["ruleset 'main': expected exactly one, found 2"])
        self.assertNotIn(f"{rc.MARKETPLACE_API}/rulesets/99", fetch.urls())
        self.assertNotIn(f"{rc.MARKETPLACE_API}/rulesets/1", fetch.urls())

    def test_every_duplicated_name_is_flagged_once_and_the_others_are_still_audited(self):
        routes = ruleset_routes({"bot-branches": {"enforcement": "disabled"}})
        listing = routes[RULESET_LISTING][1]
        extra = [{"id": 90 + n, "name": name} for n, name in enumerate(("x4-tags", "x4-tags", "tags-locked"))]
        routes[RULESET_LISTING] = (200, listing + extra)
        self.assertEqual(
            rc.audit_rulesets(fetch=ts.FakeFetch(routes)),
            [
                "ruleset 'tags-locked': expected exactly one, found 2",
                "ruleset 'bot-branches' is 'disabled', not active",
                "ruleset 'x4-tags': expected exactly one, found 3",
            ],
        )

    def test_only_the_repositorys_own_rulesets_are_listed(self):
        fetch = ts.FakeFetch(ruleset_routes())
        rc.audit_rulesets(fetch=fetch)
        self.assertIn("includes_parents=false", fetch.urls()[0])
        self.assertIn("per_page=100", fetch.urls()[0])

    def test_a_disabled_ruleset_is_caught(self):
        problems = rc.audit_rulesets(fetch=ts.FakeFetch(ruleset_routes({"fleet-tags-immutable": {"enforcement": "disabled"}})))
        self.assertEqual(problems, ["ruleset 'fleet-tags-immutable' is 'disabled', not active"])

    def test_a_missing_rule_is_caught(self):
        problems = rc.audit_rulesets(fetch=ts.FakeFetch(ruleset_routes({"bot-branches": {"rules": [{"type": "creation"}]}})))
        self.assertEqual(problems, ["ruleset 'bot-branches' lacks rules: deletion, update"])

    def test_a_wrong_target_or_ref_pattern_is_caught(self):
        problems = rc.audit_rulesets(fetch=ts.FakeFetch(ruleset_routes({"tags-locked": {"target": "branch"}})))
        self.assertEqual(problems, ["ruleset 'tags-locked' targets 'branch', not 'tag'"])
        retargeted = {"main": {"conditions": {"ref_name": {"include": ["refs/heads/trunk"], "exclude": []}}}}
        problems = rc.audit_rulesets(fetch=ts.FakeFetch(ruleset_routes(retargeted)))
        self.assertEqual(
            problems,
            ["ruleset 'main' covers include ['refs/heads/trunk'] exclude [], not include ['refs/heads/main'] exclude []"],
        )
        # A probe pattern left in fleet-tags-immutable after the probe is caught too.
        probe = {"include": ["refs/tags/fleet-v*", "refs/tags/ruleset-probe-*"], "exclude": []}
        problems = rc.audit_rulesets(fetch=ts.FakeFetch(ruleset_routes({"fleet-tags-immutable": {"conditions": {"ref_name": probe}}})))
        self.assertEqual(len(problems), 1)
        self.assertTrue(problems[0].startswith("ruleset 'fleet-tags-immutable' covers include ['refs/tags/fleet-v*', 'refs/tags/ruleset-probe-*']"))

    def test_main_must_be_squash_only_and_require_validate_from_actions(self):
        routes = ruleset_routes()
        main = json.loads(json.dumps(routes[f"{rc.MARKETPLACE_API}/rulesets/1"][1]))
        main["rules"][2]["parameters"]["allowed_merge_methods"] = ["merge", "squash"]
        main["rules"][3]["parameters"]["required_status_checks"] = [{"context": "validate"}]
        routes[f"{rc.MARKETPLACE_API}/rulesets/1"] = (200, main)
        self.assertEqual(
            rc.audit_rulesets(fetch=ts.FakeFetch(routes)),
            [
                "ruleset 'main': allowed_merge_methods is ['merge', 'squash'], not ['squash']",
                "ruleset 'main' does not require the validate check from the GitHub Actions app",
            ],
        )

    LISTING = RULESET_LISTING

    def no_verdict(self, routes):
        with self.assertRaises(rc.InfraError) as caught:
            rc.audit_rulesets(fetch=ts.FakeFetch(routes))
        self.assertEqual(caught.exception.check, "api")
        return caught.exception

    def test_a_listing_that_fails_is_no_verdict_not_drift(self):
        # A 403 or a 502 says nothing about the rulesets, so it must not read as "every ruleset is missing".
        for status in (401, 403, 404, 429, 500, 502):
            with self.subTest(status=status):
                error = self.no_verdict({self.LISTING: (status, b"")})
                self.assertIn(str(status), error.detail)

    def test_a_listing_that_is_not_a_json_list_is_no_verdict(self):
        # Iterating a JSON object visits its keys, so every ruleset used to read as missing.
        for label, answer in (
            ("an object", (200, {})),
            ("an object with a message", (200, {"message": "Server Error"})),
            ("not JSON", (200, b"<html>")),
            ("null", (200, b"null")),
            ("a duplicated key", (200, b'[{"name": "main", "name": "other"}]')),
            ("nested too deeply", (200, b"[" * 100000 + b"]" * 100000)),
            ("entries that are not objects", (200, ["main", 3])),
        ):
            with self.subTest(listing=label):
                self.no_verdict(ruleset_routes() | {self.LISTING: answer})

    def test_a_ruleset_read_that_fails_is_no_verdict_not_drift(self):
        for status in (403, 404, 500, 502):
            with self.subTest(status=status):
                routes = ruleset_routes()
                routes[f"{rc.MARKETPLACE_API}/rulesets/3"] = (status, b"")
                error = self.no_verdict(routes)
                self.assertIn(str(status), error.detail)

    def test_a_ruleset_answer_that_is_not_a_json_object_is_no_verdict(self):
        for label, answer in (("a list", (200, [])), ("not JSON", (200, b"<html>")), ("null", (200, b"null"))):
            with self.subTest(ruleset=label):
                self.no_verdict(ruleset_routes() | {f"{rc.MARKETPLACE_API}/rulesets/3": answer})


def cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = rc.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestCli(unittest.TestCase):
    def repo(self):
        repo = ts.Repo(self)
        repo.commit(ts.manifest("0.9.13"))
        repo.tag("fleet-v1")
        repo.commit(ts.manifest("0.9.14"))
        return repo

    def test_verify_version_prints_the_verified_release(self):
        with mock.patch.object(rc, "verify_release", return_value=fake_verify("0.9.14")):
            code, out, _ = cli("verify-version", "0.9.14")
        self.assertEqual((code, json.loads(out)["git_commit"]), (0, ts.ATTESTED["0.9.14"]))

    def test_a_failed_check_exits_1_and_names_the_check(self):
        with mock.patch.object(rc, "verify_release", side_effect=rc.ReleaseCheckError("commit-on-main", "behind")):
            code, out, err = cli("verify-version", "0.9.15")
        self.assertEqual((code, json.loads(out)["error"]["check"]), (1, "commit-on-main"))
        self.assertIn("::error::commit-on-main: behind", err)

    def test_no_verdict_exits_2(self):
        with mock.patch.object(rc, "verify_release", side_effect=rc.InfraError("network", "down")):
            code, out, _ = cli("verify-version", "0.9.15")
        self.assertEqual((code, json.loads(out)["error"]["check"]), (2, "network"))

    def test_usage_errors_exit_2(self):
        self.assertEqual(cli("no-such-command")[0], 2)
        self.assertEqual(cli("floor")[0], 2)

    def test_a_malformed_version_argument_is_a_usage_error_not_a_verdict(self):
        # Only a verdict exits 1. These used to reach the check, which refused the text as a
        # failed check named "version", so a caller read a typo as a release that failed.
        repo = self.repo()
        safety = repo.write("safety.json", rc.dump_json({"versions": ts.SEED}))
        for verb in (
            ["verify-version"],
            ["safety-entry", "--repo", repo.path],
            ["floor", "--repo", repo.path, "--safety", safety],
        ):
            for bad in ("0.9.x", "0.9", "v0.9.14", "0.9.09", "0.9.14-rc.1", ""):
                with self.subTest(verb=verb[0], version=bad):
                    argv = [verb[0], bad, *verb[1:]]
                    code, out, err = cli(*argv)
                    self.assertEqual((code, out), (2, ""))
                    self.assertIn("is not an exact x.y.z", err)

    def test_a_well_formed_version_argument_still_reaches_its_check(self):
        repo = self.repo()
        safety = repo.write("safety.json", rc.dump_json({"versions": ts.SEED}))
        with mock.patch.object(rc, "verify_release", return_value=fake_verify("0.9.14")) as verify:
            self.assertEqual(cli("verify-version", "0.9.14")[0], 0)
        verify.assert_called_once_with("0.9.14")
        self.assertEqual(cli("floor", "0.9.13", "--repo", repo.path, "--safety", safety)[0], 1)

    def test_a_malformed_commit_id_is_a_usage_error_not_a_verdict(self):
        good = "a" * 40
        for argv in (
            ("abc", "def"),
            (good, "b" * 39),
            ("b" * 41, good),
            (good.upper(), good),
            (good, "g" * 40),
            ("", good),
        ):
            with self.subTest(argv=argv):
                code, out, err = cli("classify", *argv)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("is not a 40-hex commit id", err)

    def elsewhere(self):
        """Run from a directory that holds none of the repository's files."""
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        previous = os.getcwd()
        os.chdir(holder.name)
        self.addCleanup(os.chdir, previous)
        return holder.name

    def test_the_audit_reads_the_frozen_list_from_the_repo_it_was_pointed_at(self):
        # The default used to be relative to the current directory, so `--repo ./clone` run from
        # anywhere else reported the list as unreadable, which reads as tag drift (exit 1).
        repo = self.repo()
        repo.write(rc.FROZEN_TAGS_FILE, rc.dump_json(rc.snapshot_tags(repo.path)))
        self.elsewhere()
        code, out, _ = cli("audit-tags", "--repo", repo.path, "--no-rulesets")
        self.assertEqual((code, json.loads(out)), (0, {"problems": []}))

    def test_floor_reads_the_safety_file_from_the_repo_it_was_pointed_at(self):
        repo = self.repo()
        repo.write(rc.SAFETY_FILE, rc.dump_json({"versions": ts.SEED}))
        self.elsewhere()
        code, out, _ = cli("floor", "0.9.13", "--repo", repo.path)
        self.assertEqual(code, 1, out)
        result = json.loads(out)
        self.assertEqual((result["floor"], result["highest_pinned"]), ("0.9.14", "0.9.14"))

    def test_a_path_given_on_the_command_line_is_used_as_given(self):
        repo = self.repo()
        frozen = repo.write("elsewhere/frozen.json", rc.dump_json(rc.snapshot_tags(repo.path)))
        repo.tag("stray")
        code, out, _ = cli("audit-tags", "--repo", repo.path, "--frozen", frozen, "--no-rulesets")
        self.assertEqual((code, json.loads(out)["problems"]), (1, ["tag 'stray' exists: no tag other than fleet-v<N> may exist"]))

    def test_an_unexpected_error_exits_2_as_internal(self):
        # Only a verdict exits 1. A bug in this tool, or a document shaped in a way it did
        # not expect, reaches no verdict, so a caller that fails on any non-zero status
        # never reads a traceback (exit 1) as "the release failed its checks".
        before, after = "a" * 40, "b" * 40
        for error in (AttributeError("'list' object has no attribute 'get'"), TypeError("not subscriptable"), KeyError("status")):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(rc, "classify_migrations", side_effect=error):
                    code, out, err = cli("classify", before, after)
                self.assertEqual(code, 2)
                document = json.loads(out)["error"]
                self.assertEqual(document["check"], "internal")
                self.assertIn(type(error).__name__, document["detail"])
                self.assertIn("::error::internal: " + type(error).__name__, err)

    def test_a_stray_value_error_is_an_internal_error_not_a_usage_error(self):
        # `usage` names a mistake in what the caller typed. A ValueError that no check turned
        # into a verdict or an outage is none of that: it is this tool meeting something it did
        # not expect, so it reaches no verdict (exit 2) and says so.
        stray = (
            ValueError("not a number"),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
        )
        for error in stray:
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(rc, "classify_migrations", side_effect=error):
                    code, out, err = cli("classify", "a" * 40, "b" * 40)
                self.assertEqual(code, 2)
                document = json.loads(out)["error"]
                self.assertEqual(document["check"], "internal")
                self.assertIn(type(error).__name__, document["detail"])
                self.assertIn("::error::internal: " + type(error).__name__, err)

    def test_a_file_the_command_line_names_but_cannot_be_read_is_a_usage_error(self):
        # The one failure `usage` still names: a path the caller gave that does not open.
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        code, out, _ = cli("diff-mode", os.path.join(holder.name, "base.json"), os.path.join(holder.name, "head.json"))
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["error"]["check"], "usage")

    def test_an_interrupt_is_not_reported_as_an_internal_error(self):
        for error in (KeyboardInterrupt(), SystemExit(3)):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(rc, "classify_migrations", side_effect=error):
                    with self.assertRaises(type(error)):
                        cli("classify", "a" * 40, "b" * 40)

    def test_the_command_runs_inside_a_twenty_minute_budget(self):
        seen = []

        def command(args):
            seen.append(rc.time_left())
            return 0

        with mock.patch.object(rc, "_command", command):
            self.assertEqual(cli("diff-mode", "base.json", "head.json")[0], 0)
        self.assertEqual(len(seen), 1)
        self.assertIsNotNone(seen[0], "no budget was running while the command ran")
        self.assertTrue(rc.BUDGET_CLI - 60 < seen[0] <= rc.BUDGET_CLI)

    def test_the_budget_ends_with_the_command_however_it_ends(self):
        for error in (
            rc.InfraError("network", "down"),
            rc.ReleaseCheckError("version", "no"),
            OSError("gone"),
            KeyError("status"),
            KeyboardInterrupt(),
        ):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(rc, "_command", side_effect=error):
                    try:
                        cli("diff-mode", "base.json", "head.json")
                    except KeyboardInterrupt:
                        pass
                self.assertIsNone(rc.time_left())

    def test_candidates(self):
        repo = self.repo()
        with mock.patch.object(rc, "npm_candidates", return_value=["0.9.15"]) as candidates:
            code, out, _ = cli("candidates", "--repo", repo.path)
        candidates.assert_called_once_with({"0.9.13", "0.9.14"})
        self.assertEqual((code, json.loads(out)), (0, {"pinned": ["0.9.13", "0.9.14"], "candidates": ["0.9.15"]}))

    def test_a_fleet_tag_nested_too_deeply_to_read_does_not_stop_candidates(self):
        # The importer asks for candidates on every run, so one tag the parser cannot read
        # must leave that tag pinning nothing and everything else as it was, not end the run.
        repo = self.repo()
        repo.commit(files={rc.MANIFEST: NESTED_TOO_DEEP})
        repo.tag("fleet-v2")
        repo.commit(ts.manifest("0.9.14"))
        with mock.patch.object(rc, "npm_candidates", return_value=["0.9.15"]) as candidates:
            code, out, _ = cli("candidates", "--repo", repo.path)
        candidates.assert_called_once_with({"0.9.13", "0.9.14"})
        self.assertEqual((code, json.loads(out)), (0, {"pinned": ["0.9.13", "0.9.14"], "candidates": ["0.9.15"]}))

    def test_classify_prints_a_rollback_safety_entry(self):
        tag = "0035_migration"
        result = rc.Classification("not-rollback-safe", [tag], {tag: "additive"})
        with mock.patch.object(rc, "classify_migrations", return_value=result):
            code, out, err = cli("classify", ts.ATTESTED["0.9.13"], ts.ATTESTED["0.9.14"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), ts.SEED["0.9.14"])
        self.assertIn(f"{tag}: additive", err)

    def test_safety_entry(self):
        repo = self.repo()
        with mock.patch.object(rc, "safety_entry", return_value=ts.SEED["0.9.14"]) as entry:
            code, out, _ = cli("safety-entry", "0.9.14", "--repo", repo.path)
        entry.assert_called_once_with("0.9.14", {"0.9.13", "0.9.14"})
        self.assertEqual((code, json.loads(out)), (0, {"version": "0.9.14", "entry": ts.SEED["0.9.14"]}))

    def test_floor_exits_1_when_the_target_crosses_it(self):
        repo = self.repo()
        safety = repo.write("safety.json", rc.dump_json({"versions": ts.SEED}))
        code, out, _ = cli("floor", "0.9.13", "--repo", repo.path, "--safety", safety)
        result = json.loads(out)
        self.assertEqual((code, result["floor"], result["highest_pinned"]), (1, "0.9.14", "0.9.14"))
        self.assertEqual(result["error"]["check"], "floor")

    def test_floor_exits_0_when_nothing_is_crossed(self):
        repo = self.repo()
        additive = {"0.9.14": {**ts.SEED["0.9.14"], "classification": "additive"}}
        safety = repo.write("safety.json", rc.dump_json({"versions": additive}))
        code, out, _ = cli("floor", "0.9.13", "--repo", repo.path, "--safety", safety)
        self.assertEqual((code, json.loads(out)), (0, {"target": "0.9.13", "highest_pinned": "0.9.14", "floor": None}))

    def test_diff_mode(self):
        repo = ts.Repo(self)
        base = repo.write("base.json", rc.dump_json(ts.manifest("0.9.14")))
        head = repo.write("head.json", rc.dump_json(ts.manifest("0.9.15", integrity=ts.OTHER_INTEGRITY)))
        code, out, _ = cli("diff-mode", base, head)
        self.assertEqual((code, json.loads(out)), (0, {"mode": "advance"}))

    def test_diff_mode_on_an_ambiguous_manifest_exits_1(self):
        repo = ts.Repo(self)
        doc = ts.manifest()
        doc["plugins"].append(copy.deepcopy(doc["plugins"][2]))
        base = repo.write("base.json", rc.dump_json(ts.manifest()))
        head = repo.write("head.json", rc.dump_json(doc))
        self.assertEqual(cli("diff-mode", base, head)[0], 1)

    def test_diff_mode_on_a_duplicate_key_exits_1(self):
        repo = ts.Repo(self)
        base = repo.write("base.json", rc.dump_json(ts.manifest()))
        head = repo.write("head.json", '{"name": "a", "name": "b", "plugins": []}')
        self.assertEqual(cli("diff-mode", base, head)[0], 1)

    def test_audit_tags_exits_1_with_problems(self):
        repo = self.repo()
        frozen = repo.write("frozen.json", rc.dump_json(rc.snapshot_tags(repo.path)))
        repo.tag("stray")
        code, out, _ = cli("audit-tags", "--repo", repo.path, "--frozen", frozen, "--no-rulesets")
        self.assertEqual((code, json.loads(out)["problems"]), (1, ["tag 'stray' exists: no tag other than fleet-v<N> may exist"]))

    def test_the_audit_has_no_previous_run_option(self):
        # Comparing against the last run's snapshot is tag_audit.py's job. Here a missing
        # file used to be skipped without a word, so an audit given one checked nothing.
        repo = self.repo()
        frozen = repo.write("frozen.json", rc.dump_json(rc.snapshot_tags(repo.path)))
        code, out, err = cli("audit-tags", "--repo", repo.path, "--frozen", frozen, "--previous", "missing.json", "--no-rulesets")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("--previous", err)
        with self.assertRaises(TypeError):
            rc.audit_tags(repo.path, frozen, previous_path="missing.json", check_rulesets=False)

    def test_snapshot_tags(self):
        repo = self.repo()
        code, out, _ = cli("snapshot-tags", "--repo", repo.path)
        self.assertEqual((code, [r["tag"] for r in json.loads(out)]), (0, ["fleet-v1"]))

    def numeric_order_repo(self):
        repo = ts.Repo(self)
        repo.commit(ts.manifest("0.9.9"))
        repo.tag("fleet-v1")
        repo.commit(ts.manifest("0.9.10"))
        repo.tag("fleet-v2")
        repo.commit(ts.manifest("0.9.14"))
        return repo

    def test_versions_are_ordered_numerically_wherever_the_cli_lists_or_picks_one(self):
        repo = self.numeric_order_repo()
        with mock.patch.object(rc, "npm_candidates", return_value=[]):
            code, out, _ = cli("candidates", "--repo", repo.path)
        self.assertEqual((code, json.loads(out)["pinned"]), (0, ["0.9.9", "0.9.10", "0.9.14"]))
        # Its own classifications: 0.9.14 is stated here, so a change to the seeded
        # classification of any version cannot move this test's expected floor.
        versions = {
            version: {**ts.SEED[version], "classification": classification}
            for version, classification in (
                ("0.9.9", "additive"),
                ("0.9.10", "additive"),
                ("0.9.14", "not-rollback-safe"),
            )
        }
        safety = repo.write("safety.json", rc.dump_json({"versions": versions}))
        code, out, _ = cli("floor", "0.9.10", "--repo", repo.path, "--safety", safety)
        result = json.loads(out)
        self.assertEqual((code, result["highest_pinned"], result["floor"]), (1, "0.9.14", "0.9.14"))

    def test_the_highest_pin_is_the_numerically_highest_when_text_order_would_pick_another(self):
        repo = ts.Repo(self)
        repo.commit(ts.manifest("0.9.9"))
        repo.tag("fleet-v1")
        repo.commit(ts.manifest("0.9.10"))
        safety = repo.write("safety.json", rc.dump_json({"versions": ts.SEED}))
        code, out, _ = cli("floor", "0.9.9", "--repo", repo.path, "--safety", safety)
        result = json.loads(out)
        self.assertEqual((code, result["highest_pinned"], result["floor"]), (1, "0.9.10", "0.9.10"))
