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

## ai-tc is pinned; `fleet-v<N>` tags

`.claude-plugin/marketplace.json` pins the `ai-tc` entry's npm source to an **exact** version
(`source.version`). Claude Code honours it on install and in its plugin auto-update pass, so a
new `@akasecurity/ai-tc-claude-code` publish reaches nobody through this marketplace until a
commit here moves the pin. That is the point: the pin is the audit trail, and it is what stops a
fleet from advancing because a publish happened. It holds for `main` and for `fleet-v2` onward;
`fleet-v1` predates it — its ai-tc entry names only the package — so a marketplace registered at
`fleet-v1` (or any pre-pin commit) with auto-update on installs npm `latest` on every pass. The
tag stays (never move a tag), but it is not a rollback target for the plugin version: a rollback
is a new tag pinning the lower version. Only this file carries it —
`.agents/plugins/marketplace.json` does not list ai-tc, and `plugins.json` has no source/version
field — so "change all four" does not apply to a version bump.

Managed fleets register this marketplace at a **signed, annotated `fleet-v<N>` tag** rather than
`main`, and record out-of-band the commit each tag must resolve to plus the pinned version's
registry integrity. Their checks re-derive that chain from the live world (tag → commit, manifest
at that commit → version, registry → integrity), so:

- **Never move, delete or re-sign an existing `fleet-v<N>` tag.** A tag that no longer resolves
  to its recorded commit is treated as a supply-chain event on the fleet side, not a typo.
- **A plugin release is a two-commit affair:** (1) here, bump `source.version` in one commit
  and cut `fleet-v<N+1>` at that commit — `git tag -s fleet-v<N+1> -m '<why>'`,
  `git push origin fleet-v<N+1>`; (2) the fleet configuration then advances its recorded
  commit, its template's `ref`, and its integrity record for the new version together. Do the
  marketplace half first: until the fleet side advances, its devices keep installing from the
  old tag, which still names the old (pinned) version.
- **Pre-flight before the tag, registry-explicit.** The tag is permanent, so confirm the version
  on the **public** registry with the scope mapping pinned — a scoped `.npmrc` in your cwd can
  silently route `@akasecurity` to another registry that serves different bytes for the same
  version:
  `npm view @akasecurity/ai-tc-claude-code@<v> dist --@akasecurity:registry=https://registry.npmjs.org`
  (or `curl -s https://registry.npmjs.org/@akasecurity%2Fai-tc-claude-code | jq '.versions["<v>"].dist'`).
  Managed fleets also require the publish to carry provenance from ai-tc's release workflow;
  `npm audit signatures` in a scratch dir that installs exactly `<v>` shows it. A version that
  fails either check must not be pinned.
- The pin bump and the tag are separate acts on purpose. A pin commit that no tag points at is
  visible to `main` installers only; a fleet only moves when its own configuration moves to the
  new tag.

`preflight` and `claude-tools` still float on their default branches (not fleet-deployed).

## Workflow

No CI. Small commits straight to `main`, but validate JSON before pushing:

```bash
for f in plugins.json .claude-plugin/marketplace.json .agents/plugins/marketplace.json; do
  jq empty "$f" && echo "ok $f"
done
```

A malformed manifest breaks `/plugin marketplace add` for every user at once.
