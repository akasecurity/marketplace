"""Read-only git queries over the workflow's checkout.

Output is read as bytes and decoded as UTF-8 by hand: text mode would
translate line endings, and the manifest's byte-stability proof must see the
file exactly as committed. The fleet-v tag rows are release_checks'
snapshot_tags, the read tag-audit's frozen list and ledger checks use.
"""
from __future__ import annotations

import subprocess

import release_checks


class GitError(Exception):
    """A git command failed."""


class Git:
    def __init__(self, repo_dir: str) -> None:
        self.repo_dir = repo_dir

    def _run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        proc = subprocess.run(["git", "-C", self.repo_dir, *args], capture_output=True)
        if check and proc.returncode != 0:
            raise GitError(f"git {' '.join(args)} failed: {proc.stderr.decode('utf-8', 'replace').strip()}")
        return proc

    def run(self, *args: str) -> str:
        return self._run(*args).stdout.decode("utf-8")

    def rev_parse(self, rev: str) -> str:
        return self.run("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").strip()

    def show(self, rev: str, path: str) -> str | None:
        """The file at `path` in commit `rev`, or None when that commit has no such file."""
        commit = self.rev_parse(rev)
        if self._run("cat-file", "-e", f"{commit}:{path}", check=False).returncode != 0:
            return None
        return self.run("show", f"{commit}:{path}")

    def fleet_tags(self) -> list[dict]:
        """Every fleet-v<N> tag as {tag, object, commit, n}, N ascending: release_checks.snapshot_tags'
        rows (object is the tag object, commit the peeled commit) with the number added."""
        try:
            rows = release_checks.snapshot_tags(self.repo_dir)
        except release_checks.InfraError as error:
            raise GitError(str(error)) from error
        return [{**row, "n": int(release_checks.FLEET_TAG.fullmatch(row["tag"]).group(1))} for row in rows]

    def tag_names(self) -> list[str]:
        return [line for line in self.run("for-each-ref", "--format=%(refname:strip=2)", "refs/tags").splitlines() if line]

    def tag_message(self, tag: str) -> str:
        return self.run("for-each-ref", "--format=%(contents)", f"refs/tags/{tag}")

    def first_parent_after(self, base: str, tip: str) -> list[str]:
        """Commits on tip's first-parent chain that base does not reach, oldest first."""
        return [line for line in self.run("rev-list", "--first-parent", "--reverse", f"{base}..{tip}").splitlines() if line]

    def first_parent(self, sha: str) -> str | None:
        parts = self.run("rev-list", "--parents", "-n", "1", sha).split()
        return parts[1] if len(parts) > 1 else None

    def commits_between(self, before: str, after: str) -> list[str]:
        """Every commit `after` reaches and `before` does not, oldest first."""
        return [line for line in self.run("rev-list", "--reverse", f"{before}..{after}").splitlines() if line]

    def commit_time(self, sha: str) -> int:
        return int(self.run("show", "-s", "--format=%ct", sha).strip())

    def ls_remote(self, remote: str = "origin") -> list[str]:
        return [line.split("\t", 1)[1] for line in self.run("ls-remote", remote).splitlines() if "\t" in line]
