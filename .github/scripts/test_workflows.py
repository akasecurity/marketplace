"""Structural guards on the workflow files: what may hold secrets, and what runs where.

The files are read as text (the stdlib has no YAML parser). These pin the
security-relevant shape; they do not replace reading a workflow in review.
"""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest

WORKFLOWS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "workflows")


def read(name: str) -> str:
    with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as handle:
        return handle.read()


def header(text: str) -> str:
    return text.split("\njobs:\n", 1)[0]


def jobs(text: str) -> dict[str, str]:
    """Each job's block, keyed by job id (the two-space-indented keys under `jobs:`)."""
    parts = re.split(r"(?m)^  ([A-Za-z0-9_-]+):[ \t]*$", text.split("\njobs:\n", 1)[1])
    return {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}


class WorkflowCase(unittest.TestCase):
    name = ""

    def setUp(self):
        self.text = read(self.name)
        self.head = header(self.text)
        self.jobs = jobs(self.text)

    def assert_common_shape(self):
        self.assertIn("\npermissions: {}\n", self.head)
        self.assertEqual(self.text.count("persist-credentials: false"), self.text.count("uses: actions/checkout@"))
        self.assertNotIn("secrets.GITHUB_TOKEN", self.text)
        self.assertNotIn("--force", self.text)
        for job, block in self.jobs.items():
            self.assertIn("    permissions:\n", block, f"job {job} declares its permissions")


class ImporterWorkflow(WorkflowCase):
    name = "import-plugin-release.yml"

    def test_common_shape(self):
        self.assert_common_shape()

    def test_triggers_are_the_schedule_and_a_dispatch_only(self):
        self.assertIn('    - cron: "*/15 * * * *"', self.head)
        self.assertIn("  workflow_dispatch:", self.head)
        self.assertNotIn("repository_dispatch", self.text)

    def test_dispatch_inputs_match_the_contract(self):
        self.assertRegex(self.head, r"(?s)\n      mode:\n.*?type: choice\n\s+options: \[forward, rollback, remove, restore\]\n\s+default: forward\n")
        self.assertRegex(self.head, r"(?s)\n      target:\n.*?type: string\n")
        self.assertRegex(self.head, r"(?s)\n      reimport:\n.*?type: boolean\n")
        self.assertRegex(self.head, r"(?s)\n      below_floor:\n.*?type: boolean\n")

    def test_each_mode_queues_in_its_own_concurrency_group(self):
        self.assertIn("  group: ${{ github.event_name == 'schedule' && 'import-forward' || "
                      "format('import-{0}', inputs.mode) }}\n", self.head)
        self.assertIn("  cancel-in-progress: false\n", self.head)

    def test_verify_holds_no_secret_and_only_open_pr_enters_the_environment(self):
        self.assertEqual(list(self.jobs), ["verify", "open-pr"])
        self.assertNotIn("secrets.", self.jobs["verify"])
        self.assertNotIn("environment:", self.jobs["verify"])
        self.assertIn("    environment: marketplace-bot\n", self.jobs["open-pr"])
        self.assertIn("    if: needs.verify.outputs.proceed == 'true'\n", self.jobs["open-pr"])

    def test_the_workflow_token_never_writes(self):
        self.assertNotRegex(self.text, r"(?m)^\s+(contents|pull-requests|issues): write")


class TagAuditWorkflow(WorkflowCase):
    name = "tag-audit.yml"

    def test_common_shape(self):
        self.assert_common_shape()

    def test_triggers(self):
        self.assertIn('    - cron: "23 5 * * *"', self.head)
        self.assertIn('    tags: ["**"]', self.head)
        self.assertIn("\n  delete:\n", self.head)
        self.assertIn("\n  workflow_dispatch:\n", self.head)
        self.assertIn("  group: tag-audit\n", self.head)

    def test_no_secret_and_no_environment(self):
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("environment:", self.text)

    def test_only_file_issues_can_write_issues(self):
        self.assertEqual(list(self.jobs), ["audit", "file-issues"])
        self.assertNotIn("issues: write", self.jobs["audit"])
        self.assertIn("      issues: write\n", self.jobs["file-issues"])
        self.assertIn("    if: always()\n", self.jobs["file-issues"])

    def step(self, needle: str) -> str:
        """The audit job's step whose text holds needle."""
        steps = [block for block in re.split(r"(?m)^      - ", self.jobs["audit"]) if needle in block]
        self.assertEqual(len(steps), 1, needle)
        return steps[0]

    def test_the_snapshot_is_kept_only_from_a_green_audit(self):
        upload = self.step("uses: actions/upload-artifact@")
        self.assertIn("        if: steps.check.outputs.red == 'false'\n", upload)
        self.assertIn("name: fleet-tags-snapshot", upload)
        self.assertIn("retention-days: 90", upload)
        self.assertIn("# Kept only from a green audit", self.jobs["audit"])
        self.assertRegex(self.jobs["audit"], r"It lasts 90\s+# days")

    def test_the_baseline_comes_only_from_a_green_run_on_main(self):
        fetch = self.step("name: fetch the snapshot the last green run kept")
        listing = re.search(r"(?s)gh run list.*?--jq", fetch).group(0)
        for flag in ("--workflow tag-audit.yml", "--branch main", "--status success", "--limit 1"):
            self.assertIn(flag, listing)

    def test_a_failed_download_is_not_read_as_an_expired_snapshot(self):
        fetch = self.step("name: fetch the snapshot the last green run kept")
        self.assertNotIn("elif !", fetch)
        self.assertNotRegex(fetch, r"(?m)^\s*(if|elif) ! gh ")
        self.assertNotIn("|| true", fetch)
        self.assertIn("actions/runs/$run_id/artifacts", fetch)

    def fetch_script(self) -> str:
        fetch = self.step("name: fetch the snapshot the last green run kept")
        body = fetch.split("run: |\n", 1)[1]
        return textwrap.dedent(body.split("\n      - ", 1)[0])

    def run_fetch(self, *, runs: str = "[]", artifacts: str = "{}", list_fails=False, api_fails=False,
                  download_fails=False):
        """Run the fetch step's script against a stand-in for gh, which answers as the real one would."""
        if shutil.which("jq") is None:
            self.skipTest("jq is not installed")
        with tempfile.TemporaryDirectory() as root:
            stub = os.path.join(root, "bin", "gh")
            os.makedirs(os.path.dirname(stub))
            with open(stub, "w", encoding="utf-8") as handle:
                handle.write(textwrap.dedent("""\
                    #!/usr/bin/env python3
                    import os, subprocess, sys
                    args = sys.argv[1:]
                    with open(os.environ["GH_LOG"], "a") as log:
                        log.write(" ".join(args) + "\\n")
                    def filtered(document):
                        expression = args[args.index("--jq") + 1]
                        out = subprocess.run(["jq", "-r", expression], input=document, text=True, capture_output=True)
                        sys.stderr.write(out.stderr)
                        sys.stdout.write(out.stdout)
                        sys.exit(out.returncode)
                    if args[:2] == ["run", "list"]:
                        sys.exit(1) if os.environ.get("LIST_FAILS") else filtered(os.environ["RUNS"])
                    if args[0] == "api":
                        sys.exit(1) if os.environ.get("API_FAILS") else filtered(os.environ["ARTIFACTS"])
                    if args[:2] == ["run", "download"]:
                        sys.exit(1) if os.environ.get("DOWNLOAD_FAILS") else sys.exit(0)
                    sys.exit(2)
                    """))
            os.chmod(stub, os.stat(stub).st_mode | stat.S_IXUSR)
            log = os.path.join(root, "gh.log")
            env = {"PATH": os.path.dirname(stub) + os.pathsep + os.environ["PATH"], "GH_LOG": log,
                   "GITHUB_REPOSITORY": "akasecurity/marketplace", "RUNS": runs, "ARTIFACTS": artifacts,
                   **({"LIST_FAILS": "1"} if list_fails else {}), **({"API_FAILS": "1"} if api_fails else {}),
                   **({"DOWNLOAD_FAILS": "1"} if download_fails else {})}
            work = os.path.join(root, "work")
            os.makedirs(work)
            done = subprocess.run(["bash", "-c", self.fetch_script()], cwd=work, env=env, text=True,
                                  capture_output=True)
            calls = []
            if os.path.exists(log):
                with open(log, encoding="utf-8") as handle:
                    calls = handle.read().splitlines()
            return done, calls

    def test_the_fetch_step_downloads_the_last_green_runs_snapshot(self):
        done, calls = self.run_fetch(runs='[{"databaseId": 77}]',
                                     artifacts='{"artifacts": [{"name": "fleet-tags-snapshot", "expired": false}]}')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(calls[-1], "run download 77 --repo akasecurity/marketplace --name fleet-tags-snapshot --dir previous")

    def test_the_fetch_step_with_no_earlier_green_run_compares_against_the_frozen_list_only(self):
        done, calls = self.run_fetch()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("::notice::no earlier green tag-audit run", done.stdout)
        self.assertEqual(len(calls), 1)

    def test_the_fetch_step_takes_the_notice_path_only_for_an_expired_snapshot(self):
        done, calls = self.run_fetch(runs='[{"databaseId": 77}]',
                                     artifacts='{"artifacts": [{"name": "fleet-tags-snapshot", "expired": true}]}')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("::notice::run 77 kept a snapshot that has expired", done.stdout)
        self.assertFalse([call for call in calls if call.startswith("run download")])

    def test_the_fetch_step_fails_on_every_other_failure(self):
        listed = dict(runs='[{"databaseId": 77}]',
                      artifacts='{"artifacts": [{"name": "fleet-tags-snapshot", "expired": false}]}')
        cases = {
            "the run listing fails": dict(runs='[{"databaseId": 77}]', list_fails=True),
            "the artifact listing fails": dict(listed, api_fails=True),
            "the green run lists no snapshot": dict(runs='[{"databaseId": 77}]', artifacts='{"artifacts": []}'),
            "another artifact only": dict(runs='[{"databaseId": 77}]',
                                          artifacts='{"artifacts": [{"name": "other", "expired": false}]}'),
            "the download fails": dict(listed, download_fails=True),
        }
        for label, kwargs in cases.items():
            with self.subTest(label):
                done, _ = self.run_fetch(**kwargs)
                self.assertNotEqual(done.returncode, 0, done.stdout)
                self.assertNotIn("expired", done.stdout)


if __name__ == "__main__":
    unittest.main()
