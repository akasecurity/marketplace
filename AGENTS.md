# AGENTS.md — marketplace

Per-repo conventions for any coding/ops agent. Builds on `~/aka/AGENTS.md` (company layer) and the
global layer — never repeats them.

## What this repo is

The **public** first-party plugin marketplace for AKA Security. It is a thin index: it holds no
plugin code, only manifests that reference each tool's own repository, so a tool's releases flow
through without a change here.

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

## Workflow

No CI. Small commits straight to `main`, but validate JSON before pushing:

```bash
for f in plugins.json .claude-plugin/marketplace.json .agents/plugins/marketplace.json; do
  jq empty "$f" && echo "ok $f"
done
```

A malformed manifest breaks `/plugin marketplace add` for every user at once.
