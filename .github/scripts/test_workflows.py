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
        # The schedule and forward dispatches share the first group on purpose: open-pr replaces a branch
        # no PR ever used, which is safe only while no other forward run is live. A scheduled tick can
        # therefore cancel a pending forward dispatch, and the workflow's header says so.
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

    def test_the_app_token_is_made_from_the_clients_id_not_the_deprecated_app_id(self):
        # create-github-app-token marks app-id deprecated ("Use 'client-id' instead"): every run would
        # warn, and a later major version may drop it. The secrets are the App's client id and key.
        self.assertIn("          client-id: ${{ secrets.MARKETPLACE_BOT_CLIENT_ID }}\n", self.jobs["open-pr"])
        self.assertIn("          private-key: ${{ secrets.MARKETPLACE_BOT_PRIVATE_KEY }}\n", self.jobs["open-pr"])
        self.assertNotRegex(self.text, r"(?m)^\s+app-id:")
        self.assertNotIn("MARKETPLACE_BOT_APP_ID", self.text)

    # The first Node 24 release that bundles an npm of release_checks.MIN_NPM or later: v24.15.0 ships
    # npm 11.12.1 (nodejs.org/dist/index.json), and every later 24.x ships a newer one.
    FIRST_NODE_WITH_MIN_NPM = (24, 15, 0)

    @staticmethod
    def lowest_admitted(spec):
        """The lowest release setup-node's version spec can resolve to, or None when it can
        resolve to a Node that does not ship the npm the gate needs: a bare major, an x-range,
        an alias, another major (Node 25.0.0 through 25.8.2 bundle npm 11.6 to 11.11), or a range
        with no upper bound, which setup-node resolves to the highest cached copy of any major.
        Only an exact 24.x.y, or a range from one up to but not including 25, is accepted."""
        match = re.fullmatch(r"24\.(\d+)\.(\d+)", spec) or re.fullmatch(r">=24\.(\d+)\.(\d+) <25", spec)
        return (24, int(match.group(1)), int(match.group(2))) if match else None

    def test_the_lowest_release_a_spec_admits(self):
        for spec, lowest in (
            ("24.15.0", (24, 15, 0)),
            ("24.16.1", (24, 16, 1)),
            (">=24.15.0 <25", (24, 15, 0)),
            (">=24.16.1 <25", (24, 16, 1)),
            # Another major bundles another npm: Node 25.0.0 through 25.8.2 ship npm 11.6 to 11.11.
            ("25.0.0", None),
            (">=25.9.0 <26", None),
            # No upper bound, or one past 25: the highest cached copy of any major can be chosen.
            (">=24.15.0", None),
            (">=24.16.1", None),
            (">=24.15.0 <26", None),
            (">=24.15.0 <24.99.0", None),
            ("<25", None),
            ("24", None),
            ("24.x", None),
            ("^24.15.0", None),
            (">=24", None),
            ("lts/*", None),
            ("latest", None),
        ):
            with self.subTest(spec):
                self.assertEqual(self.lowest_admitted(spec), lowest)

    def test_node_is_installed_at_a_release_that_ships_the_npm_the_gate_accepts(self):
        # setup-node uses a cached Node that satisfies the spec before it downloads one, so a bare "24"
        # can resolve to an older cached 24.x whose npm the release checks refuse, red, on every run.
        # Only an exact 24.x.y, or a range from one up to but not including 25, cannot.
        specs = re.findall(r'uses: actions/setup-node@[0-9a-f]{40}.*\n\s+with:\n\s+node-version: "([^"]+)"', self.text)
        self.assertEqual(len(specs), 1, "the importer installs Node exactly once, with a quoted node-version")
        lowest = self.lowest_admitted(specs[0])
        self.assertIsNotNone(lowest, f"node-version {specs[0]!r} can resolve to a cached Node with an older npm")
        self.assertGreaterEqual(lowest, self.FIRST_NODE_WITH_MIN_NPM)

    def test_the_verify_budget_ends_before_the_job_is_cancelled(self):
        # The plan reaches its own "no verdict" first; GitHub's cancellation of the job is not one.
        limits = re.findall(r"(?m)^    timeout-minutes: (\d+)\s*$", self.jobs["verify"])
        self.assertEqual(len(limits), 1, "the verify job must set one timeout")
        self.assertLess(release_checks.BUDGET_JOB, int(limits[0]) * 60)

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
            output = os.path.join(root, "github-output")
            env = {"PATH": os.path.dirname(stub) + os.pathsep + os.environ["PATH"], "GH_LOG": log,
                   "GITHUB_REPOSITORY": "akasecurity/marketplace", "RUNS": runs, "ARTIFACTS": artifacts,
                   "GITHUB_OUTPUT": output,
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
            # What the step handed on to the next one: "baseline=ready" or "baseline=none" (empty if it said nothing).
            self.fetch_outputs = {}
            if os.path.exists(output):
                with open(output, encoding="utf-8") as handle:
                    self.fetch_outputs = dict(line.split("=", 1) for line in handle.read().splitlines())
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

    def test_the_fetch_step_says_whether_there_is_a_baseline(self):
        cases = {
            "a downloaded snapshot": (dict(runs=RUN_77, artifacts=READY), "ready"),
            "no earlier green run": (dict(), "none"),
            "only pull request runs": (dict(runs='[{"databaseId": 99, "event": "pull_request"}]', artifacts=READY), "none"),
            "an expired snapshot": (dict(runs=RUN_77, artifacts='{"artifacts": [{"name": "fleet-tags-snapshot", "expired": true}]}'), "none"),
            "no snapshot listed": (dict(runs=RUN_77, artifacts='{"artifacts": []}'), "none"),
        }
        for label, (kwargs, baseline) in cases.items():
            with self.subTest(label):
                done, _ = self.run_fetch(**kwargs)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(self.fetch_outputs, {"baseline": baseline})

    def test_the_fetch_step_says_nothing_when_it_fails(self):
        listed = dict(runs=RUN_77, artifacts=READY)
        for label, kwargs in {"the run listing fails": dict(runs=RUN_77, list_fails=True),
                              "the artifact listing fails": dict(listed, api_fails=True),
                              "the download fails": dict(listed, download_fails=True)}.items():
            with self.subTest(label):
                done, _ = self.run_fetch(**kwargs)
                self.assertNotEqual(done.returncode, 0)
                self.assertEqual(self.fetch_outputs, {}, "a failed download must not read as 'ready'")

    def audit_script(self) -> str:
        audit = self.step("tag_audit.py check")
        return textwrap.dedent(audit.split("run: |\n", 1)[1].split("\n      - ", 1)[0])

    def run_audit(self, baseline: str):
        """Run the audit step's script with BASELINE as the fetch step would have set it, and a stand-in for
        python3 that records how tag_audit.py was called. Returns (exit code, the arguments, or None)."""
        with tempfile.TemporaryDirectory() as root:
            stub = os.path.join(root, "bin", "python3")
            os.makedirs(os.path.dirname(stub))
            log = os.path.join(root, "args")
            with open(stub, "w", encoding="utf-8") as handle:
                handle.write('#!/bin/sh\necho "$@" >> "$ARGS_LOG"\n')
            os.chmod(stub, os.stat(stub).st_mode | stat.S_IXUSR)
            env = {"PATH": os.path.dirname(stub) + os.pathsep + os.environ["PATH"], "ARGS_LOG": log, "BASELINE": baseline}
            done = subprocess.run(["bash", "-c", self.audit_script()], cwd=root, env=env, text=True, capture_output=True)
            called = None
            if os.path.exists(log):
                with open(log, encoding="utf-8") as handle:
                    called = handle.read().strip()
            return done.returncode, called

    def test_the_audit_asks_for_a_comparison_only_when_a_snapshot_was_downloaded(self):
        code, called = self.run_audit("ready")
        self.assertEqual(code, 0)
        self.assertIn(" --previous previous/fleet-tags.snapshot.json ", called)
        self.assertNotIn("--no-baseline", called)

    def test_the_audit_says_there_is_no_baseline_when_the_fetch_step_found_none(self):
        code, called = self.run_audit("none")
        self.assertEqual(code, 0)
        self.assertIn(" --no-baseline ", called)
        self.assertNotIn("--previous", called)

    def test_the_audit_never_guesses_the_baseline(self):
        for baseline in ("", "Ready", "true", "ready none"):
            with self.subTest(baseline):
                code, called = self.run_audit(baseline)
                self.assertNotEqual(code, 0)
                self.assertIsNone(called, "tag_audit.py must not run without a stated baseline")

    def test_the_snapshot_path_is_one_file(self):
        # The upload, the audit's --snapshot, the download's --dir and the audit's --previous name one file:
        # an artifact keeps its file's name, so the download puts it back at <dir>/<that name>.
        uploaded = re.search(r"(?m)^          path: (\S+)$", self.step("uses: actions/upload-artifact@")).group(1)
        audit = self.step("tag_audit.py check")
        written = re.search(r"--snapshot (\S+)", audit).group(1)
        read = re.search(r"--previous ([^\s)]+)", audit).group(1)
        directory = re.search(r"gh run download .*--dir (\S+)", self.step("name: fetch the snapshot")).group(1)
        self.assertEqual(written, uploaded)
        self.assertEqual(read, directory + "/" + os.path.basename(uploaded))
        self.assertIn(f"mkdir -p {directory}\n", self.step("name: fetch the snapshot"))

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


if __name__ == "__main__":
    unittest.main()
