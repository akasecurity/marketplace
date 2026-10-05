"""A small GitHub REST and GraphQL client for the marketplace's workflow scripts.

Stdlib only. Every call goes through one transport function, which the tests
replace, so no test touches the network.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterator

API = "https://api.github.com"
Transport = Callable[[str, str, "dict[str, str]", "bytes | None"], "tuple[int, bytes]"]


class GitHubError(Exception):
    """A call answered with a status its caller does not accept."""

    def __init__(self, status: int, method: str, path: str, body: str) -> None:
        super().__init__(f"{method} {path} -> HTTP {status}: {body[:500]}")
        self.status = status
        self.method = method
        self.path = path
        self.body = body


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Follows no redirect, so a 30x comes back as its own status. urllib's default handler
    copies the request's headers onto the follow-up request, Authorization included, even
    when it goes to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def urllib_transport(method: str, url: str, headers: dict[str, str], data: bytes | None) -> tuple[int, bytes]:
    """One request; a status other than 2xx comes back as itself, and so does a redirect, which is
    never followed: the bot's token must not reach a host the API named in a Location header."""
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with _OPENER.open(request, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


class GitHub:
    """REST and GraphQL calls against api.github.com for one repository ("owner/name")."""

    def __init__(self, auth, repo, transport: Transport | None = None) -> None:
        self.auth = auth or ""
        self.repo = repo
        self.transport = transport or urllib_transport

    def repo_path(self, suffix: str) -> str:
        return f"repos/{self.repo}/{suffix.lstrip('/')}"

    def request(self, method: str, path: str, *, body: Any = None, params: dict | None = None,
                ok: tuple[int, ...] = (200, 201, 204)) -> Any:
        url = f"{API}/{path.lstrip('/')}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "akasecurity-marketplace-workflows",
        }
        if self.auth:
            headers["Authorization"] = "Bearer " + self.auth
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        status, raw = self.transport(method, url, headers, data)
        if status not in ok:
            raise GitHubError(status, method, path, raw.decode("utf-8", "replace"))
        return json.loads(raw) if raw.strip() else None

    def get(self, path: str, params: dict | None = None, ok: tuple[int, ...] = (200,)) -> Any:
        return self.request("GET", path, params=params, ok=ok)

    def post(self, path: str, body: Any, ok: tuple[int, ...] = (200, 201)) -> Any:
        return self.request("POST", path, body=body, ok=ok)

    def patch(self, path: str, body: Any) -> Any:
        return self.request("PATCH", path, body=body, ok=(200,))

    def delete(self, path: str, ok: tuple[int, ...] = (204,)) -> Any:
        return self.request("DELETE", path, ok=ok)

    def paginate(self, path: str, params: dict | None = None) -> Iterator[Any]:
        """Every item of a list endpoint, 100 per page, until a short page."""
        page = 1
        while True:
            answer = self.get(path, params={**(params or {}), "per_page": 100, "page": page})
            if isinstance(answer, dict):  # an envelope such as {"total_count": n, "workflow_runs": [...]}
                answer = next((value for value in answer.values() if isinstance(value, list)), [])
            yield from answer
            if len(answer) < 100:
                return
            page += 1

    def graphql(self, query: str, variables: dict) -> dict:
        answer = self.request("POST", "graphql", body={"query": query, "variables": variables}, ok=(200,))
        if answer.get("errors"):
            raise GitHubError(200, "POST", "graphql", json.dumps(answer["errors"]))
        return answer["data"]
