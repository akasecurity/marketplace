# AKA Security marketplace

**One place to install AKA Security's tools for coding agents.** Add the marketplace once and
install any tool your harness supports. First-party today; the manifests reference each tool's own
repository (nothing is vendored here), so a tool's own releases flow through automatically.

From [akasecurity](https://akasecurity.io). Each listed tool is licensed in its own repository.

## The tools

| Tool | What it does | Install handle | Status |
|---|---|---|---|
| **preflight** | An independent multi-model review crew for coding agents — two blind cross-family reads plus an independent judge that filters false positives. Report-only. | `preflight@akasecurity` | ✅ available |
| **claude-tools** | The security defaults Claude Code doesn't ship with — guard hooks (command-guard, leak-guard) that block pipe-to-shell and catch secrets before they leave. | `claude-tools@akasecurity` | ✅ available |
| **ai-tc** — AI Traffic Control | An open-source control plane for coding agents — intercepts prompts, tool calls, and responses, scans them against rule packs for secrets and sensitive data, then monitors, warns, redacts, or blocks before anything reaches the model. Runs entirely locally. | `ai-tc@akasecurity` | ✅ available |

## Install

**Claude Code** and **Codex** read this marketplace natively — add it once, then install any tool.

Claude Code:

```
/plugin marketplace add akasecurity/marketplace
/plugin install preflight@akasecurity
/plugin install claude-tools@akasecurity
/plugin install ai-tc@akasecurity
```

Codex:

```
codex plugin marketplace add akasecurity/marketplace
codex plugin add preflight@akasecurity
```

**Antigravity** (`agy`) has no marketplace mechanism — install a tool directly from its own repo:

```
agy plugin install https://github.com/akasecurity/preflight-skills
```

**Other harnesses** (Cursor, Gemini, Kimi, OpenCode, Pi): install per tool from its own repo, which
documents the exact command for each — e.g. OpenCode adds
`"preflight-skills@git+https://github.com/akasecurity/preflight-skills.git"` to `opencode.json`.
See [preflight-skills](https://github.com/akasecurity/preflight-skills) and
[claude-tools](https://github.com/akasecurity/claude-tools).

**Standalone CLI** (no coding agent): `brew install akasecurity/tap/aka-claude-tools` or
`brew install akasecurity/tap/preflight` — see
[homebrew-tap](https://github.com/akasecurity/homebrew-tap). **ai-tc**'s CLI (bin: `aka`) is the
CLI-first alternative to the marketplace plugin above (which stays the default): install via
`curl -fsSL https://raw.githubusercontent.com/akasecurity/ai-tc/cli-latest/tools/installer/install.sh | sh`
then run `aka init` — it detects whether the Claude Code plugin is installed and offers to add it.

> Codex and Antigravity currently install **preflight** (multi-harness). `claude-tools` and `ai-tc`
> are Claude Code tools; on other harnesses install `claude-tools` via its shell kit / Homebrew.

## About

First-party marketplace for [AKA Security](https://akasecurity.io) — security tooling and safe
defaults for coding agents. The `plugins.json` registry index is machine-readable and structured so
the marketplace can open to community submissions later without a rewrite. Community-health files
(Code of Conduct, Contributing, Security) are inherited from the
[akasecurity/.github](https://github.com/akasecurity/.github) org defaults.
