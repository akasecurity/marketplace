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

import release_checks

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

    # The first Node 24 release that bundles an npm of release_checks.MIN_NPM or later: v24.15.0 ships
    # npm 11.12.1 (nodejs.org/dist/index.json), and every later 24.x ships a newer one.
    FIRST_NODE_WITH_MIN_NPM = (24, 15, 0)

    def test_node_is_installed_at_a_release_that_ships_the_npm_the_gate_accepts(self):
        # setup-node uses a cached Node that satisfies the spec before it downloads one, so a bare "24"
        # can resolve to an older cached 24.x whose npm the release checks refuse, red, on every run.
        # Only an exact version, or a range that starts at one, cannot.
        specs = re.findall(r'uses: actions/setup-node@[0-9a-f]{40}.*\n\s+with:\n\s+node-version: "([^"]+)"', self.text)
        self.assertEqual(len(specs), 1, "the importer installs Node exactly once, with a quoted node-version")
        match = re.fullmatch(r"(?:>=)?(\d+)\.(\d+)\.(\d+)(?: <\d+)?", specs[0])
        self.assertIsNotNone(match, f"node-version {specs[0]!r} can resolve to a cached Node with an older npm")
        self.assertGreaterEqual(tuple(int(part) for part in match.groups()), self.FIRST_NODE_WITH_MIN_NPM)

    def test_the_node_release_was_chosen_for_the_gates_npm_floor(self):
        self.assertEqual(release_checks.MIN_NPM, (11, 12, 0))

    def test_the_workflow_names_the_npm_it_needs_rather_than_just_a_major(self):
        self.assertIn("npm 11.12", self.text)
        self.assertNotIn("npm 11 (node 24)", self.text.lower())


RUN_77 = '[{"databaseId": 77, "event": "schedule"}]'
READY = '{"artifacts": [{"name": "fleet-tags-snapshot", "expired": false}]}'


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
        self.assertRegex(self.jobs["audit"], r"It lasts 90(?:\s+#)?\s+days")

    def test_the_baseline_comes_only_from_a_green_run_on_main(self):
        fetch = self.step("name: fetch the snapshot the last green run kept")
        listing = re.search(r"(?s)gh run list.*?--jq", fetch).group(0)
        for flag in ("--workflow tag-audit.yml", "--branch main", "--status success", "--limit 100",
                     "--json databaseId,event"):
            self.assertIn(flag, listing)
        # A fork's pull request from its own main also reports the branch main, so the event decides.
        self.assertIn('.event == "schedule" or .event == "workflow_dispatch" or .event == "delete"', fetch)
        self.assertNotIn("pull_request", fetch)

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
        done, calls = self.run_fetch(runs=RUN_77,
                                     artifacts='{"artifacts": [{"name": "fleet-tags-snapshot", "expired": false}]}')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(calls[-1], "run download 77 --repo akasecurity/marketplace --name fleet-tags-snapshot --dir previous")

    def test_the_fetch_step_never_takes_a_pull_request_run_as_the_baseline(self):
        # A fork's pull request from its own main lists as a green run on the branch main; only the
        # older scheduled run may supply the baseline.
        runs = ('[{"databaseId": 99, "event": "pull_request"}, {"databaseId": 88, "event": "pull_request_target"},'
                ' {"databaseId": 77, "event": "schedule"}]')
        done, calls = self.run_fetch(runs=runs, artifacts=READY)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(calls[-1], "run download 77 --repo akasecurity/marketplace --name fleet-tags-snapshot --dir previous")
        self.assertFalse([call for call in calls if " 99 " in f" {call} " or " 88 " in f" {call} "])

    def test_the_fetch_step_with_only_pull_request_runs_has_no_baseline(self):
        done, calls = self.run_fetch(runs='[{"databaseId": 99, "event": "pull_request"}]', artifacts=READY)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("::notice::no earlier green tag-audit run", done.stdout)
        # The listing's jq filter spans two lines, so the log holds it as two; nothing else was called.
        self.assertTrue(calls[0].startswith("run list "))
        self.assertFalse([call for call in calls if call.startswith(("api ", "run download"))])

    def test_the_fetch_step_takes_a_manual_or_deletion_run_as_the_baseline(self):
        for event in ("workflow_dispatch", "delete"):
            with self.subTest(event):
                done, calls = self.run_fetch(runs='[{"databaseId": 55, "event": "%s"}]' % event, artifacts=READY)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertTrue(calls[-1].startswith("run download 55 "))

    def test_the_fetch_step_with_no_earlier_green_run_requires_the_frozen_list_to_cover_every_tag(self):
        done, calls = self.run_fetch()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("::notice::no earlier green tag-audit run", done.stdout)
        self.assertIn("the frozen list has to record every fleet-v tag", done.stdout)
        # The listing's jq filter spans two lines, so the log holds it as two; nothing else was called.
        self.assertTrue(calls[0].startswith("run list "))
        self.assertFalse([call for call in calls if call.startswith(("api ", "run download"))])

    def test_the_fetch_step_takes_the_notice_path_only_for_an_expired_snapshot(self):
        done, calls = self.run_fetch(runs=RUN_77,
                                     artifacts='{"artifacts": [{"name": "fleet-tags-snapshot", "expired": true}]}')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("::notice::run 77 kept a snapshot that has expired", done.stdout)
        self.assertIn("the frozen list has to record every fleet-v tag", done.stdout)
        self.assertFalse([call for call in calls if call.startswith("run download")])

    def test_a_green_run_with_no_snapshot_takes_the_no_baseline_path(self):
        # A snapshot someone deleted must not wedge the audit red for good: the run goes on without a
        # baseline, and tag_audit.py then requires the frozen list to record every fleet-v tag.
        cases = {
            "the green run lists no artifact": '{"artifacts": []}',
            "another artifact only": '{"artifacts": [{"name": "other", "expired": false}]}',
        }
        for label, artifacts in cases.items():
            with self.subTest(label):
                done, calls = self.run_fetch(runs=RUN_77, artifacts=artifacts)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertIn("::notice::run 77 is the last green run but lists no fleet-tags-snapshot artifact",
                              done.stdout)
                self.assertNotIn("expired", done.stdout)
                self.assertIn("the frozen list has to record every fleet-v tag", done.stdout)
                self.assertFalse([call for call in calls if call.startswith("run download")])

    def test_the_fetch_step_fails_on_every_other_failure(self):
        listed = dict(runs=RUN_77,
                      artifacts='{"artifacts": [{"name": "fleet-tags-snapshot", "expired": false}]}')
        cases = {
            "the run listing fails": dict(runs=RUN_77, list_fails=True),
            "the artifact listing fails": dict(listed, api_fails=True),
            "the download fails": dict(listed, download_fails=True),
        }
        for label, kwargs in cases.items():
            with self.subTest(label):
                done, _ = self.run_fetch(**kwargs)
                self.assertNotEqual(done.returncode, 0, done.stdout)
                self.assertNotIn("expired", done.stdout)


class TagReleaseWorkflow(WorkflowCase):
    name = "tag-release.yml"

    def test_common_shape(self):
        self.assert_common_shape()

    def test_triggers_and_serialization(self):
        self.assertIn("  push:\n    branches: [main]\n", self.head)
        self.assertIn("\n  workflow_dispatch:\n", self.head)
        self.assertIn("  group: tag-release\n", self.head)
        self.assertIn("  cancel-in-progress: false\n", self.head)

    def test_one_job_in_the_bot_environment_audits_before_it_mints(self):
        self.assertEqual(list(self.jobs), ["tag"])
        job = self.jobs["tag"]
        self.assertIn("    environment: marketplace-bot\n", job)
        self.assertLess(job.index("tag_audit.py check"), job.index("actions/create-github-app-token@"))
        self.assertLess(job.index("actions/create-github-app-token@"), job.index("tag_release.py sweep"))
        self.assertNotRegex(self.text, r"(?m)^\s+(contents|pull-requests|issues): write")

    def test_branch_clean_up_follows_the_sweep_and_never_runs_after_a_failed_one(self):
        job = self.jobs["tag"]
        self.assertLess(job.index("tag_release.py sweep"), job.index("tag_release.py cleanup-branches"))
        # A step with a condition can run after an earlier one failed (`always()`, `failure()`); without one it cannot.
        self.assertNotRegex(job, r"(?m)^\s+if:")
        # `continue-on-error` lets a failed sweep step pass, and the next step would then run after it.
        self.assertNotIn("continue-on-error", job)


class ScriptTestsWorkflow(WorkflowCase):
    name = "script-tests.yml"

    def pull_request_paths(self) -> list[str]:
        found = re.search(r"(?m)^  pull_request:\n    paths:\n((?:      - .*\n)+)", self.head)
        self.assertIsNotNone(found, "the pull_request trigger has a paths filter")
        return [line.strip()[2:].strip('"') for line in found.group(1).splitlines()]

    def test_a_pull_request_that_changes_only_the_code_owners_file_runs_the_unit_tests(self):
        # tag-release reads that file strictly and stops the sweep on a shape it refuses. validate, the required
        # check, does not read it, so the unit test that reads the repository's own copy is the only check on the PR.
        self.assertIn(".github/CODEOWNERS", self.pull_request_paths())

    def test_the_test_that_reads_the_code_owners_file_is_still_there_for_that_path_to_run(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_tag_release.py"), encoding="utf-8") as handle:
            self.assertIn("def test_the_repositorys_own_codeowners_file_can_be_read(", handle.read())


class StalenessWorkflow(WorkflowCase):
    name = "staleness.yml"

    def test_common_shape(self):
        self.assert_common_shape()

    def test_hourly_with_a_drill_input(self):
        self.assertIn('    - cron: "7 * * * *"', self.head)
        self.assertRegex(self.head, r"(?s)\n      drill:\n.*?type: boolean\n")
        self.assertIn("  group: staleness\n", self.head)

    def test_no_secret_no_environment_and_only_file_issues_writes_issues(self):
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("environment:", self.text)
        self.assertEqual(list(self.jobs), ["evaluate", "file-issues"])
        self.assertNotIn("issues: write", self.jobs["evaluate"])
        self.assertIn("      issues: write\n", self.jobs["file-issues"])
        self.assertIn("    if: always()\n", self.jobs["file-issues"])

    # The first Node 24 release that bundles an npm of release_checks.MIN_NPM or later: v24.15.0 ships
    # npm 11.12.1 (nodejs.org/dist/index.json), and every later 24.x ships a newer one.
    FIRST_NODE_WITH_MIN_NPM = (24, 15, 0)

    def test_node_is_installed_at_a_release_that_ships_the_npm_the_gate_accepts(self):
        # setup-node uses a cached Node that satisfies the spec before it downloads one, so a bare "24"
        # can resolve to an older cached 24.x whose npm the release checks cannot finish on, and every
        # hourly run would then report the same no-verdict alert. Only an exact version, or a range
        # that starts at one, cannot.
        specs = re.findall(r'uses: actions/setup-node@[0-9a-f]{40}.*\n\s+with:\n\s+node-version: "([^"]+)"', self.text)
        self.assertEqual(len(specs), 1, "staleness installs Node exactly once, with a quoted node-version")
        match = re.fullmatch(r"(?:>=)?(\d+)\.(\d+)\.(\d+)(?: <\d+)?", specs[0])
        self.assertIsNotNone(match, f"node-version {specs[0]!r} can resolve to a cached Node with an older npm")
        self.assertGreaterEqual(tuple(int(part) for part in match.groups()), self.FIRST_NODE_WITH_MIN_NPM)

    def test_the_node_release_was_chosen_for_the_gates_npm_floor(self):
        self.assertEqual(release_checks.MIN_NPM, (11, 12, 0))

    def test_the_workflow_names_the_npm_it_needs_rather_than_just_a_major(self):
        self.assertIn("npm 11.12", self.text)
        self.assertNotIn("npm 11 (node 24)", self.text.lower())


class MainAuditWorkflow(WorkflowCase):
    name = "main-audit.yml"

    def test_common_shape(self):
        self.assert_common_shape()

    def test_every_push_to_main_is_audited_and_none_is_dropped(self):
        self.assertIn("  push:\n    branches: [main]\n", self.head)
        self.assertNotIn("concurrency:", self.text)

    def test_the_audit_sees_full_history_and_the_pushed_range(self):
        self.assertIn("          fetch-depth: 0\n", self.jobs["audit"])
        self.assertIn("          BEFORE: ${{ github.event.before }}\n", self.jobs["audit"])
        self.assertIn("          AFTER: ${{ github.event.after }}\n", self.jobs["audit"])

    def test_a_failed_audit_job_is_filed_against_its_push(self):
        # The router keys the failed-job issue to this push, so a second failed run opens its own.
        self.assertIn("          AFTER: ${{ github.event.after }}\n", self.jobs["file-issues"])
        # ... through the environment, never spliced into the command line.
        self.assertFalse([line for line in self.jobs["file-issues"].splitlines()
                          if line.strip().startswith("run:") and "${{" in line])

    def test_the_audit_job_may_read_checks_to_see_that_validate_passed(self):
        self.assertIn("      checks: read\n", self.jobs["audit"])
        self.assertNotIn("checks: write", self.text)

    def test_no_secret_no_environment_and_only_file_issues_writes_issues(self):
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("environment:", self.text)
        self.assertEqual(list(self.jobs), ["audit", "file-issues"])
        self.assertNotIn("issues: write", self.jobs["audit"])
        self.assertIn("      issues: write\n", self.jobs["file-issues"])
        self.assertIn("    if: always()\n", self.jobs["file-issues"])


if __name__ == "__main__":
    unittest.main()
