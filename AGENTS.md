# AGENTS.md — marketplace

Per-repo conventions for any coding/ops agent. Builds on `~/aka/AGENTS.md` (company layer) and the
global layer — never repeats them.

## What this repo is

The **public** first-party plugin marketplace for AKA Security. It is a thin index: it holds no
plugin code, only manifests that reference each tool's own repository, so a tool's releases flow
through without a change here — with one deliberate exception, `ai-tc`, whose npm source is
pinned to an exact version (see "ai-tc is pinned" below).

Public. Everything committed is visible immediately.

## Four files, one set of facts

| File | Consumer |
|---|---|
| `.claude-plugin/marketplace.json` | Claude Code's `/plugin marketplace add` aggregator |
| `.agents/plugins/marketplace.json` | Codex's aggregator |
| `plugins.json` | harness-agnostic registry index (name, repo, category, status, harnesses) |
| `README.md` + `llms.txt` | humans and retrieval |

**A plugin's name, repo URL, and description appear in all four. Change one, change all four** —
then re-read them side by side before committing. This repo is the source of truth other surfaces
copy from (the org profile at `akasecurity/.github`, the Homebrew tap README, `ai-tc-docs`), so an
error here propagates outward.

The two aggregators deliberately differ: Claude Code serves all three plugins, Codex currently
serves only `preflight`. That asymmetry is real, not drift — the README's closing note states it.
Don't "fix" it by copying entries across.

## Adding or renaming a plugin

1. Confirm the source actually resolves — `gh api repos/<org>/<repo>` for a github source,
   `npm view <pkg> version` for an npm source. A GitHub rename keeps redirecting, so a stale repo
   name looks fine in a browser and is still wrong.
2. Update all four files.
3. Grep the tree for the old name before you finish: `rg -n '<old-name>' --hidden -g '!.git'`.
4. Renames do not propagate on their own. After a rename, check `akasecurity/.github`
   (`profile/README.md`), `akasecurity/homebrew-tap` (README + formula), and `akasecurity/ai-tc-docs`
   (`overrides/home.html`) for the old name.
5. The `ai-tc` entry is the exception for its package and its name: `validate` fails a human change
   to either, so such a change is a rare, fleet-wide act an org owner merges under break-glass,
   together with the matching release-pipeline change in `.github/scripts/release_checks.py`. Its
   `description` changes like any other plugin's, through a reviewed pull request.

## ai-tc is pinned; `fleet-v<N>` tags

`.claude-plugin/marketplace.json` pins the `ai-tc` entry's npm source to an **exact** version
(`source.version`) on the public registry (`source.registry`, `https://registry.npmjs.org`), and
records that version's npm integrity in the entry's free-form `metadata.integrity` (Claude Code
does not read it; fleet checks compare installed bytes against it). Claude Code honours the pin on
install and in its plugin auto-update pass, so a new `@akasecurity/ai-tc-claude-code` publish
reaches nobody through this marketplace until a code-owner-approved pull request moves the pin (an
org owner's break-glass merge aside, which `main-audit` reports). That is the
point: the pin is the audit trail, and it is what stops a fleet from advancing because a publish
happened. It holds for `main` and for `fleet-v2` onward; `fleet-v1` predates it — its ai-tc entry
names only the package — so a marketplace registered at `fleet-v1` (or any pre-pin commit) with
auto-update on installs npm `latest` on every pass. Only this file carries the pin —
`.agents/plugins/marketplace.json` does not list ai-tc, and `plugins.json` has no source/version
field — so "change all four" does not apply to a version change.

**How the pin moves: only through the release bot's pull requests** (see "The workflows").

- **A release** is a `bot/pin-ai-tc-<v>` PR that `import-plugin-release` opens after verifying the
  npm release: an exact `x.y.z`, the registry's dist, SLSA provenance whose signing certificate
  names ai-tc's release workflow at the version's own tag, and the certificate's commit on ai-tc's
  `main`. It changes the version and `metadata.integrity`, and adds the version's entry to
  `rollback-safety.json`. One code owner approves it after running the candidate in one real
  session (the PR's checklist), and auto-merge squash-merges it once `validate` is green.
- **A rollback** is a rollback-mode dispatch of the same workflow, with a version or a `fleet-v<N>`
  name. Its `bot/rollback-ai-tc-<from>-to-<v>` PR moves only the pin, down to a version a `fleet-v`
  tag has pinned and not below the rollback floor that `rollback-safety.json` records; one code
  owner approves it, and auto-merge squash-merges it once `validate` is green. Never reset `main`
  backwards, and never restore a whole manifest from a tag: that would undo the other entries'
  edits.
- **Nobody edits the ai-tc entry by hand.** `validate` fails any human change to it other than its
  `description` (see "Adding or renaming a plugin", step 5).
- **A `rollback-safety.json` entry is computed, never typed.** A release PR adds its version's
  entry, and `validate` recomputes it from the store migrations between the previous pinned
  release's attested commit and this one's. It recomputes an entry `main` already records for the
  version too, and fails one that runs up to another commit than the release's attested one or that
  is weaker than the computation (a stronger recorded class stands). A person changes an entry only
  in a code-owner-reviewed PR, and `validate` calls a change toward `additive` out as lowering the
  rollback floor; a person may not add an entry for a version nothing pins.

**Who signed a release is read from its signing certificate, never from the statement.**
`npm audit signatures` checks the signature and the certificate's chain, but no identity: a release
that verifies proves only that someone published with provenance, and anyone can do that from their
own repository. So `release_checks.py` reads the identity from the Sigstore certificate that npm
verified, the one that signed the statement, and requires it to name ai-tc's release workflow at the
version's own tag, pushed by that tag, from ai-tc's repository and owner (compared by GitHub's
numeric ids, which a rename cannot move), on a GitHub-hosted runner. The commit and the run the PR
shows are the certificate's too. The statement the publisher wrote must agree with the certificate,
and the commit must be on ai-tc's `main`; a statement that contradicts its own signer is refused as
forged.

**`fleet-v<N>` tags are cut automatically.** When a pin change merges, `tag-release` creates the next
annotated `fleet-v<N>` tag at its commit. The message records the version, integrity, PR, approver
and store-migration class, and for a rollback the version it rolled back from. The approver is the
code owner whose latest review approves the PR's final head; with none, the message says
`approver: none` and who merged it, and when CODEOWNERS at the commit's parent could not be read
the PR is still named but the approver is `unknown`, with the reason. Rulesets let only the release
bot create a `fleet-v` tag and nobody at all move or delete one, and refuse every other tag name:

- **Only a tag cut by hand is signed.** The `fleet-v` tags cut before `tag-release` existed were
  signed by hand; the tags `tag-release` cuts are annotated but **not signed**, because the release
  bot creates them through GitHub's API. What protects every `fleet-v` tag is the rulesets and
  `tag-audit`, not a signature, and nothing reads one: no check in this repository does, and the
  fleet configuration that registers this marketplace at a tag checks only that the name has the
  form `fleet-v<N>` and that the tag still resolves to the commit recorded for it.
- **Never move, delete or re-sign an existing `fleet-v<N>` tag.** `tag-audit` treats a tag that no
  longer resolves to its recorded object as a supply-chain event, not a typo;
  `.github/fleet-tags.frozen.json` records the tags that existed when it was switched on.
- Managed fleets either follow `main`, which moves only through a code-owner-approved pull request
  (an org owner's break-glass merge aside, which `main-audit` reports), or register this
  marketplace at a `fleet-v<N>` tag, which never moves; a fleet on a tag moves only when its own
  configuration names a later one. A tag is also the only way to hold a fleet on one release,
  since a marketplace ref cannot be a raw commit.
- **Checking a version by hand, registry-explicit.** The importer and `validate` run these checks
  as code. To repeat them, confirm the version on the **public** registry with the scope mapping
  pinned — a scoped `.npmrc` in your cwd can silently route `@akasecurity` to another registry that
  serves different bytes for the same version:
  `npm view @akasecurity/ai-tc-claude-code@<v> dist --@akasecurity:registry=https://registry.npmjs.org`
  (or `curl -s https://registry.npmjs.org/@akasecurity%2Fai-tc-claude-code | jq '.versions["<v>"].dist'`).
  `npm audit signatures` in a scratch dir that installs exactly `<v>` shows that its provenance
  verifies, but not who signed it (see above). To repeat every check, identity included, run
  `python3 .github/scripts/release_checks.py verify-version <v>` with npm 11.12 or later, the first
  npm that prints the attestations; an older one gives no verdict. It exits 0 when the release
  passes, 1 when a check refuses it, and 2 when no verdict could be reached.

`preflight` and `claude-tools` still float on their default branches (not fleet-deployed).

## Workflow

Every change reaches `main` through a pull request. `.github/CODEOWNERS` names the code owners of
every file, and the `main` ruleset requires one of them to approve (someone other than the PR's
last pusher) and the `validate` check to pass, so a code owner's own PR needs the other code
owner. Merges are squash merges. Keep `.github/CODEOWNERS` as one `*` line naming users:
`tag-release` and `main-audit` read it strictly, at a commit's parent, and can match a reviewer's
login only to a user, so a team, an email address, a path rule or a second rule is not read. A PR
merged on top of such a file gets `approver: unknown` in its tag and a `main-audit` issue, rather
than a guess, and that file is fixed history no later PR can change. The unit tests run on a PR
that changes the file and fail one the reader cannot read. Before pushing, validate the JSON and
run the scripts' tests:

```bash
for f in plugins.json .claude-plugin/marketplace.json .agents/plugins/marketplace.json; do
  jq empty "$f" && echo "ok $f"
done
python3 -m unittest discover -s .github/scripts -p 'test_*.py'
```

A malformed manifest breaks `/plugin marketplace add` for every user at once.

## The workflows

`validate`, `import-plugin-release` and `tag-release` are the release path; `staleness`,
`tag-audit` and `main-audit` watch it. Their logic lives in `.github/scripts/` (stdlib Python, with
tests beside it), so the workflow files stay thin. Only `import-plugin-release`'s `open-pr` job and
`tag-release` act as the release bot, through the `marketplace-bot` environment, which only `main`
may use.

- **`import-plugin-release`** runs every 15 minutes and by manual dispatch. Its `verify` job holds
  no secret: it takes the highest exact npm version above every version `main` or a `fleet-v` tag
  has pinned that passes the release checks, never npm `latest` on trust. Its `open-pr` job creates
  the bot branch with a create-only ref, never a force-push, opens the PR and enables auto-merge.
  What it does with a branch that already exists depends on what used it: one with an open bot PR
  is skipped; one the bot's closed PR used is skipped on a plain forward run, and deleted and
  created again only by a `reimport` or rollback dispatch; one no PR ever used was left by a run
  that died before opening it, and any run deletes it and creates it again. It never deletes the
  head of a PR the bot did not open: that run goes red until a person closes the PR. It tells its
  own PRs from anyone else's by their author (`release_checks.BOT_LOGIN`), so a person's PR from a
  `bot/` branch name neither stops the schedule nor is closed by it, and while no bot login is
  configured it refuses, red. A version a code owner rejected (its PR closed unmerged), or one a
  rollback moved away from, comes back only through a dispatch with `reimport: true`. A version
  `main` already records in `rollback-safety.json` is recomputed first, and the import stops, red,
  if the recorded entry runs up to another commit than the release's attested one or says
  `additive` where the computation says not-rollback-safe, since `validate` would fail the PR.
  `mode: rollback` with a `target` opens a rollback PR labelled `rollback`, turns off auto-merge on
  open forward pin PRs, and closes other rollback PRs; `below_floor: true` opens one below the
  rollback floor, which `validate` then fails, so only an org owner's break-glass merge lands it.
  While a rollback PR is open, the scheduled import opens nothing, and a forward PR opened by hand
  gets no auto-merge. The forward and rollback jobs do not wait for each other, so a forward job
  looks for an open rollback PR before it enables auto-merge and again after, and turns auto-merge
  off if one opened meanwhile. A candidate that fails a check
  is logged once and skipped, so it never hides a release above or below it. A candidate the
  checks cannot finish on (no verdict, below) is not skipped: the run stops there, red, and does
  not fall back to a lower version, because the one it could not check may be the real newest.
  The next run tries again, and a dispatch naming a lower `target` that is still above every pin
  imports that release meanwhile, since that path reads no candidate list. A dispatched `target` or
  rollback target with no verdict ends red the same way.
- **`validate`** (`pull_request_target`, required) checks every PR with the base branch's copy of
  its script, reading the PR's files as data. An approver confirms the check run is `validate.yml`'s
  run from `main`, and trusts its summary over the PR body. A check that cannot finish reports
  NO VERDICT and fails the required check; it is never reported as the PR breaking a rule. On a bot
  PR every commit must also carry GitHub's verified signature. The summary's `Main read at` row
  names the `main` commit whose pins and rollback floor it read, and every value taken from the PR
  appears in it inside a code span. `validate` does not run again when `main` moves, so if
  `rollback-safety.json` changed on `main` after a rollback PR's run, its approver re-runs the
  check before approving (the PR's checklist says so).
- **`tag-release`** (every push to `main`) runs `tag-audit`'s ledger and ruleset checks (not its
  comparison with the last green run's snapshot of the tags), tags every first-parent commit whose
  ai-tc version changed and has no `fleet-v` tag yet, and then deletes the bot's branches that
  still point at the head of a closed PR (a branch re-created after its PR closed is kept). Only a
  PR merged into `main` counts as a commit's merge. A commit that GitHub links to no merged PR is
  left untagged, and so is everything after it, until it is an hour old, so that a slow link never
  becomes a permanent `pr: none` tag; from then on it is tagged as a push without a PR, which
  `tag-audit` reports. A restore after the entry was removed is compared with the last version
  pinned before the removal, so a lower one records `rollback-from`. A tag or a branch deletion
  that GitHub refuses ends the run with one error naming the ruleset, not a traceback, and a failed
  sweep runs no clean-up.
- **`staleness`** (hourly) files an issue when a passing release above every pin (`main`'s
  included) has been on npm for 24 hours, npm has a version the importer refuses, the release
  checks reached no verdict on a version that has been on npm for over an hour, or whose publish
  time is unknown (its own issue, naming the version and the check that did not finish), a bot PR
  is open for 24 hours, a pin change is untagged for an hour, a stray tag or a second ref named
  `main` exists, or the ai-tc entry is gone; it posts a "rolled back, awaiting fix-forward" notice
  while the latest tag is a rollback. While such a version has no verdict, the unpinned-release and
  refused-version rules can still go red from the versions that did finish, but they are not
  cleared. A younger version is left out, because neither rule can name it yet, so an outage never
  closes the issue of a version they could name. Every script that reads `main` uses its full ref,
  so a tag named `main` cannot stand in for the branch before the stray-ref rule reports it.
- **`tag-audit`** (daily, on every tag push or deletion, and by hand) checks the `fleet-v` ledger
  against the frozen list, the last green run and `main`'s history, and that the rulesets are active
  as configured. A tag that changed since the last green run stays red until a reviewed PR
  re-freezes the list (`python3 .github/scripts/tag_audit.py freeze`), which is how a person records
  that the change is explained; a deleted tag has to be put back at its commit first. When there is
  no snapshot to compare with (none was kept, it expired after 90 days, or it was deleted), the
  frozen list has to record every `fleet-v` tag, so the baseline is re-set in a reviewed PR and not
  by the passage of time. Keep artifact retention at 90 days, and dispatch `tag-audit` once after
  turning it on so a baseline exists before `tag-release` cuts the first tag after the frozen list;
  `tag-release` asks for no comparison.
- **`main-audit`** (every push to `main`) opens an issue for each first-parent commit the push
  added that is not the merge of a PR with a code owner's approval of its final head, from someone
  other than the head's last pusher and not since withdrawn, and a passing `validate` check from
  GitHub Actions on that head. The branch commits a merge-commit merge brings in are not on that
  line and are not checked, and a rebase merge would report each rebased commit but the last, which
  is why merges are squash-only. The last pusher is the author or committer of the head commit
  (`web-flow` aside): the audit does not use GitHub's activity API, which does record pushers,
  because what it records for a push made by the App or by auto-merge is unverified, and a head
  that names neither is reported, since an approval could then be the pusher's own. CODEOWNERS is
  read strictly at the commit's parent, and a file that cannot be read is that commit's problem. A
  push that moves `main` without extending it (the old tip is not an ancestor of the new one) gets
  its own issue and audits the first-parent commits after the two tips' merge base, or only the new
  tip when there is no merge base to start from (for instance, the old tip is no longer in the
  checkout). A push the audit could not finish, and a job that failed, each get an issue of their
  own, keyed to the push; a person closes every `main-audit` issue.

**No verdict is not a refusal.** `release_checks.py` keeps two outcomes apart. A check that reached
a verdict and said no raises `ReleaseCheckError` (the command exits 1). A check that could not
finish, because the registry, the network, npm, git or the GitHub API failed, raises `InfraError`
(exit 2). They are sibling classes, not parent and child, so a handler written for a refusal never
catches an outage by accident, and a caller that forgets to handle one fails the run closed and
visibly instead of reading the outage as a verdict. Write new callers the same way: name the class
you mean, and decide what no verdict does there (`validate` fails, the importer stops red, and
`staleness` reports it on its own rule).

Issues go to the release approvers in `.github/release-approvers.json` and mention the code owners.
Each rule has one issue, found by a hidden marker among the issues the workflow's own token filed,
whatever labels it carries, so an issue a person filed never stands in for it. A rule that clears
closes its issue, and one that goes red again within 48 hours reopens that issue instead of opening a
new one, so its escalation clock keeps running; once an issue has been open for 48 hours the
escalation owner is assigned, once. A person's close is final, and `main-audit`'s issues, which are
keyed to a commit or a push, are closed only by a person.

**The release path covers one plugin.** `release_checks.py` names one package and one release
pipeline, and the importer, `validate`, `tag-release` and `staleness` act only on the entry that
pins it; `validate` checks every other entry only for parsing and unique names. Pinning another
plugin to an npm version gets none of these checks, and adding it to `RELEASE_PIPELINE` alone
changes nothing: pin one only together with the script changes that cover it.
