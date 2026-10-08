"""Tests for gitrepo.py against a scratch repository (no network)."""
import os
import tempfile
import unittest

import _testsupport as ts
from gitrepo import Git, GitError


class Scratch(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.env = ts.git_env("test", "test@example.invalid")
        self.sh("init", "-q", "-b", "main")
        self.git = Git(self.dir)

    def sh(self, *args, when="2026-09-01T00:00:00+00:00"):
        env = dict(self.env, GIT_AUTHOR_DATE=when, GIT_COMMITTER_DATE=when)
        return ts.git(self.dir, *args, env=env).strip()

    def commit(self, path, text, when="2026-09-01T00:00:00+00:00"):
        full = os.path.join(self.dir, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        self.sh("add", path)
        self.sh("commit", "-q", "-m", f"set {path}", when=when)
        return self.sh("rev-parse", "HEAD")


class TestGit(Scratch):
    def test_fleet_tags_are_in_numeric_order_with_peeled_commits(self):
        first = self.commit("a.txt", "1\n")
        second = self.commit("a.txt", "2\n")
        self.sh("tag", "-a", "fleet-v10", "-m", "ten", second)
        self.sh("tag", "-a", "fleet-v2", "-m", "two", first)
        self.sh("tag", "fleet-v3", second)  # lightweight
        self.sh("tag", "-a", "other", "-m", "x", first)
        tags = self.git.fleet_tags()
        self.assertEqual([t["tag"] for t in tags], ["fleet-v2", "fleet-v3", "fleet-v10"])
        self.assertEqual([t["n"] for t in tags], [2, 3, 10])
        self.assertEqual(tags[0]["commit"], first)
        self.assertNotEqual(tags[0]["object"], first)  # an annotated tag has its own object
        self.assertEqual((tags[1]["object"], tags[1]["commit"]), (second, second))
        self.assertEqual(sorted(self.git.tag_names()), ["fleet-v10", "fleet-v2", "fleet-v3", "other"])
        self.assertEqual(self.git.tag_message("fleet-v10").strip(), "ten")

    def test_show_returns_exact_bytes_none_when_absent_and_raises_on_a_bad_revision(self):
        sha = self.commit("dir/m.json", "{\r\n}\n")
        self.assertEqual(self.git.show(sha, "dir/m.json"), "{\r\n}\n")
        self.assertEqual(self.git.show("main", "dir/m.json"), "{\r\n}\n")
        self.assertIsNone(self.git.show(sha, "dir/absent.json"))
        with self.assertRaises(GitError):
            self.git.show("0" * 40, "dir/m.json")

    def test_a_committed_file_whose_object_is_missing_raises_instead_of_reading_as_absent(self):
        sha = self.commit("dir/m.json", "{}\n")
        blob = self.sh("rev-parse", f"{sha}:dir/m.json")
        loose = os.path.join(self.dir, ".git", "objects", blob[:2], blob[2:])
        os.chmod(loose, 0o644)
        os.remove(loose)
        with self.assertRaises(GitError):
            self.git.show(sha, "dir/m.json")
        self.assertIsNone(self.git.show(sha, "dir/absent.json"))

    def test_a_path_under_a_missing_tree_object_raises(self):
        sha = self.commit("dir/m.json", "{}\n")
        tree = self.sh("rev-parse", f"{sha}:dir")
        loose = os.path.join(self.dir, ".git", "objects", tree[:2], tree[2:])
        os.chmod(loose, 0o644)
        os.remove(loose)
        with self.assertRaises(GitError):
            self.git.show(sha, "dir/m.json")

    def test_entry_mode_names_what_git_records_at_a_path_and_none_when_there_is_nothing(self):
        plain = self.commit("dir/m.json", "{}\n")
        self.assertEqual(self.git.entry_mode(plain, "dir/m.json"), "100644")
        self.assertEqual(self.git.entry_mode("main", "dir/m.json"), "100644")
        self.assertEqual(self.git.entry_mode(plain, "dir"), "040000")
        self.assertIsNone(self.git.entry_mode(plain, "dir/absent.json"))
        self.assertIsNone(self.git.entry_mode(plain, "dir/m.json/inside"))
        self.sh("update-index", "--chmod=+x", "dir/m.json")
        self.sh("commit", "-q", "-m", "executable")
        self.assertEqual(self.git.entry_mode("main", "dir/m.json"), "100755")
        os.symlink("m.json", os.path.join(self.dir, "dir", "link"))
        self.sh("add", "dir/link")
        self.sh("update-index", "--add", "--cacheinfo", f"160000,{'a' * 40},dir/sub")
        self.sh("commit", "-q", "-m", "a symbolic link and a submodule")
        self.assertEqual(self.git.entry_mode("main", "dir/link"), "120000")
        self.assertEqual(self.git.entry_mode("main", "dir/sub"), "160000")
        with self.assertRaises(GitError):
            self.git.entry_mode("0" * 40, "dir/m.json")

    def test_first_parent_history_skips_the_merged_side_branch(self):
        base = self.commit("a.txt", "base\n")
        self.sh("switch", "-q", "-c", "side")
        self.commit("b.txt", "side\n")
        self.sh("switch", "-q", "main")
        second = self.commit("a.txt", "two\n")
        self.sh("merge", "-q", "--no-ff", "-m", "merge side", "side")
        merge = self.sh("rev-parse", "HEAD")
        self.assertEqual(self.git.first_parent_after(base, "main"), [second, merge])
        self.assertEqual(self.git.first_parent(merge), second)
        self.assertIsNone(self.git.first_parent(base))
        self.assertEqual(self.git.rev_parse("main"), merge)

    def test_merge_base_is_the_last_common_commit_and_none_without_one(self):
        base = self.commit("a.txt", "base\n")
        self.sh("switch", "-q", "-c", "side")
        side = self.commit("b.txt", "side\n")
        self.sh("switch", "-q", "main")
        main = self.commit("a.txt", "two\n")
        self.assertEqual(self.git.merge_base(side, main), base)
        self.assertEqual(self.git.merge_base(base, main), base)  # an ancestor is its own base with its descendant
        self.sh("switch", "-q", "--orphan", "other")
        other = self.commit("c.txt", "unrelated\n")
        self.assertIsNone(self.git.merge_base(other, main))
        with self.assertRaises(GitError):
            self.git.merge_base("0" * 40, main)

    def test_main_is_the_branch_when_a_tag_is_named_main(self):
        first = self.commit("a.txt", "1\n")
        second = self.commit("a.txt", "2\n")
        self.sh("tag", "main", first)
        # The hazard: git resolves a bare name to the tag before the branch.
        self.assertEqual(self.git.rev_parse("main"), first)
        self.assertEqual(self.git.main(), "refs/heads/main")
        self.assertEqual(self.git.rev_parse(self.git.main()), second)
        # With origin's main fetched, that is the one read, whatever the local branch has since moved to.
        self.commit("a.txt", "3\n")
        self.sh("update-ref", "refs/remotes/origin/main", second)
        self.assertEqual(self.git.main(), "refs/remotes/origin/main")
        self.assertEqual(self.git.rev_parse(self.git.main()), second)

    def test_commit_time_and_ls_remote(self):
        sha = self.commit("a.txt", "1\n", when="2026-09-02T03:04:05+00:00")
        self.sh("tag", "-a", "fleet-v1", "-m", "one", sha)
        self.assertEqual(self.git.commit_time(sha), 1788318245)
        refs = self.git.ls_remote(self.dir)
        self.assertIn("refs/heads/main", refs)
        self.assertIn("refs/tags/fleet-v1", refs)
        self.assertIn("refs/tags/fleet-v1^{}", refs)


if __name__ == "__main__":
    unittest.main()
