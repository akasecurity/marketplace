"""Tests for ghapi.py: headers, bodies, statuses, pagination and GraphQL errors."""
import json
import secrets
import unittest

from ghapi import GitHub, GitHubError


class Transport:
    """Answers queued (status, body) pairs and records every call."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, method, url, headers, data):
        self.calls.append((method, url, headers, data))
        status, body = self.answers.pop(0)
        return status, b"" if body is None else json.dumps(body).encode()


class TestGitHub(unittest.TestCase):
    def test_request_sends_the_api_headers_and_a_json_body(self):
        transport = Transport((201, {"number": 3}))
        gh = GitHub("", "akasecurity/marketplace", transport)
        self.assertEqual(gh.post(gh.repo_path("pulls"), {"title": "t"}), {"number": 3})
        method, url, headers, data = transport.calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://api.github.com/repos/akasecurity/marketplace/pulls")
        self.assertEqual(headers["Accept"], "application/vnd.github+json")
        self.assertEqual(headers["X-GitHub-Api-Version"], "2022-11-28")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(json.loads(data), {"title": "t"})

    def test_the_credential_is_sent_as_a_bearer_header_only_when_set(self):
        transport = Transport((200, []), (200, []))
        value = secrets.token_hex(8)  # generated per run, so the source holds no credential-shaped literal
        GitHub(value, "o/r", transport).get("repos/o/r/tags")
        GitHub("", "o/r", transport).get("repos/o/r/tags")
        self.assertEqual(transport.calls[0][2]["Authorization"], "Bearer " + value)
        self.assertNotIn("Authorization", transport.calls[1][2])

    def test_query_parameters_are_encoded(self):
        transport = Transport((200, []))
        GitHub("", "o/r", transport).get("repos/o/r/pulls", params={"state": "open", "base": "main"})
        self.assertEqual(transport.calls[0][1], "https://api.github.com/repos/o/r/pulls?state=open&base=main")

    def test_an_unaccepted_status_raises_with_the_status(self):
        gh = GitHub("", "o/r", Transport((404, {"message": "Not Found"})))
        with self.assertRaises(GitHubError) as caught:
            gh.get("repos/o/r/git/ref/heads/nope")
        self.assertEqual(caught.exception.status, 404)
        self.assertIn("Not Found", str(caught.exception))

    def test_an_empty_body_is_none(self):
        self.assertIsNone(GitHub("", "o/r", Transport((204, None))).delete("repos/o/r/git/refs/heads/x"))

    def test_paginate_walks_pages_until_a_short_one(self):
        transport = Transport((200, [{"n": i} for i in range(100)]), (200, [{"n": 100}]))
        items = list(GitHub("", "o/r", transport).paginate("repos/o/r/pulls", {"state": "closed"}))
        self.assertEqual(len(items), 101)
        self.assertIn("state=closed&per_page=100&page=1", transport.calls[0][1])
        self.assertIn("page=2", transport.calls[1][1])

    def test_paginate_reads_the_list_inside_an_envelope(self):
        transport = Transport((200, {"total_count": 1, "workflow_runs": [{"id": 9}]}))
        self.assertEqual(list(GitHub("", "o/r", transport).paginate("repos/o/r/actions/runs")), [{"id": 9}])

    def test_graphql_returns_data_and_raises_on_errors(self):
        ok = GitHub("", "o/r", Transport((200, {"data": {"x": 1}})))
        self.assertEqual(ok.graphql("query { x }", {}), {"x": 1})
        failing = GitHub("", "o/r", Transport((200, {"errors": [{"message": "nope"}]})))
        with self.assertRaisesRegex(GitHubError, "nope"):
            failing.graphql("mutation { y }", {})


if __name__ == "__main__":
    unittest.main()
