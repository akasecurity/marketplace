"""Unit tests for release_checks.py. Standard library only and no outside network: every fetch,
npm run and sleep is injected. live_release_checks.py holds the three live checks."""

from __future__ import annotations

import contextlib
import copy
import http.client
import http.server
import io
import json
import os
import subprocess
import sys
import threading
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
        with mock.patch.object(rc, "_read_manifest", side_effect=rc.InfraError("git", "show failed")):
            with self.assertRaises(rc.InfraError):
                rc._tag_pin("unused", "fleet-v1")
        for verdict in (rc.ReleaseCheckError("manifest", "no plugins list"), ValueError("does not parse")):
            with self.subTest(verdict=repr(verdict)):
                with mock.patch.object(rc, "_read_manifest", side_effect=verdict):
                    self.assertIsNone(rc._tag_pin("unused", "fleet-v1"))


class TestRunningTheFile(unittest.TestCase):
    def test_running_the_file_is_a_usage_error_until_the_command_line_exists(self):
        # The docstring defines exit 0 as "the check passes", so a file that prints nothing
        # and exits 0 would be read as a pass by `release_checks.py verify X && proceed`.
        # The in-process tests cannot see this: they never run the file as a program.
        result = subprocess.run(
            [sys.executable, rc.__file__, "verify", "0.9.16"], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("nothing was checked", result.stderr)


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

    def test_a_repository_without_main_is_infrastructure(self):
        ts.git(self.repo.path, "branch", "-m", "main", "trunk")
        with self.assertRaises(rc.InfraError):
            rc.pinned_versions(self.repo.path)


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

    def test_a_registry_error_is_infrastructure(self):
        with self.assertRaises(rc.InfraError):
            rc.npm_candidates(set(), fetch=ts.FakeFetch({rc.packument_url(): (503, b"")}))
