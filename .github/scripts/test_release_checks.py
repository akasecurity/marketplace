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

    def __init__(self, *, install=(0,), audit=(1, "{}")):
        self.install = list(install)
        self.audit = audit
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), kwargs.get("cwd")))
        if args[:2] == ["npm", "init"]:
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == ["npm", "install"]:
            code = self.install.pop(0) if len(self.install) > 1 else self.install[0]
            return subprocess.CompletedProcess(args, code, "", "npm error 404" if code else "")
        code, out = self.audit
        return subprocess.CompletedProcess(args, code, out, "")


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

    def test_the_audit_asks_for_attestations(self):
        run = FakeRun(audit=(0, json.dumps(ts.audit_output("0.9.14"))))
        rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None)
        self.assertEqual(run.calls[-1][0], ["npm", "audit", "signatures", "--json", "--include-attestations"])

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

    def test_missing_npm_is_toolchain(self):
        def run(args, **kwargs):
            raise FileNotFoundError("npm")

        with self.assertRaises(rc.InfraError):
            rc.npm_audit_signatures(rc.PACKAGE, "0.9.14", run=run, sleep=lambda s: None)


class TestVerifyRelease(unittest.TestCase):
    def verify(self, version="0.9.14", *, routes=None, audits=None, sleeps=None):
        fetch = ts.FakeFetch(routes if routes is not None else ts.release_routes(version))
        queue = list(audits if audits is not None else [ts.audit_output(version)])

        def audit(package, v):
            self.assertEqual((package, v), (rc.PACKAGE, version))
            return queue.pop(0) if len(queue) > 1 else queue[0]

        recorded = sleeps if sleeps is not None else []
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
        self.assertIn(f"{rc.AI_TC_API}/compare/{ts.ATTESTED['0.9.14']}...main?per_page=1", fetch.urls())

    def test_identical_to_main_passes(self):
        self.verify(routes=ts.release_routes("0.9.14", compare="identical"))

    def test_behind_main_is_refused(self):
        # Built on main's tip and never merged: the attacker's case.
        self.refused("commit-on-main", routes=ts.release_routes("0.9.14", compare="behind"))

    def test_diverged_is_refused(self):
        self.refused("commit-on-main", routes=ts.release_routes("0.9.14", compare="diverged"))

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
            rc.verify_release("0.9.15-rc1", fetch=fetch, audit=lambda p, v: {}, sleep=lambda s: None)
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

    def test_an_off_tag_branch_publish_does_not_rule_out_a_stolen_github_credential(self):
        # The certificate and the statement both say the workflow ran from a branch.
        ref = "refs/heads/release/0.9.x"
        uri = f"{rc.PROV_REPO}/{ts.WORKFLOW}@{ref}"
        stmt = ts.statement("0.9.14", ref=ref)
        cert = ts.signing_cert("0.9.14", san=uri, build_signer=uri, build_config=uri, ref=ref, trigger="workflow_dispatch")
        error = self.refused("provenance", audits=[ts.audit_output("0.9.14", stmt, cert=cert)])
        ts.assert_off_tag_text_is_truthful(self, error.detail)

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
