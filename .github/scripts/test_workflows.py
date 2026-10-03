"""Structural guards on the workflow files: what may hold secrets, and what runs where.

The files are read as text (the stdlib has no YAML parser). These pin the
security-relevant shape; they do not replace reading a workflow in review.
"""
import os
import re
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


if __name__ == "__main__":
    unittest.main()
