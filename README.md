# AKA Security marketplace

**One place to install AKA Security's tools for coding agents.** Add the marketplace once and
install any tool your harness supports. First-party today; the manifests reference each tool's own
repository (nothing is vendored here), so a tool's own releases flow through automatically.

From [akasecurity](https://akasecurity.io). Each listed tool is licensed in its own repository.

## The tools

| Tool | What it does | Install handle | Status |
|---|---|---|---|
| **flightcrew** | An independent multi-model review crew for coding agents — two blind cross-family reads plus an independent judge that filters false positives. Report-only. | `flightcrew@akasecurity` | ✅ available |
| **claude-tools** | The security defaults Claude Code doesn't ship with — guard hooks (command-guard, leak-guard) that block pipe-to-shell and catch secrets before they leave. | `claude-tools@akasecurity` | ✅ available |
| **ai-tc** — AI Traffic Control | Intercept, inspect, and govern prompts and responses from AI coding tools — scan for PII, credentials, and OWASP findings, then warn, redact, or block. | `ai-tc@akasecurity` | 🚧 landing soon |

## Install

**Claude Code** and **Codex** read this marketplace natively — add it once, then install any tool.

Claude Code:

```
/plugin marketplace add akasecurity/marketplace
/plugin install flightcrew@akasecurity
/plugin install claude-tools@akasecurity
```

Codex:

```
codex plugin marketplace add akasecurity/marketplace
codex plugin add flightcrew@akasecurity
```

**Antigravity** (`agy`) has no marketplace mechanism — install a tool directly from its own repo:

```
agy plugin install https://github.com/akasecurity/flightcrew-skills
```

**Other harnesses** (Cursor, Gemini, Kimi, OpenCode, Pi): install per tool from its own repo, which
documents the exact command for each — e.g. OpenCode adds
`"flightcrew-skills@git+https://github.com/akasecurity/flightcrew-skills.git"` to `opencode.json`.
See [flightcrew-skills](https://github.com/akasecurity/flightcrew-skills) and
[claude-tools](https://github.com/akasecurity/claude-tools).

**Standalone CLI** (no coding agent): `brew install akasecurity/tap/aka-claude-tools` or
`brew install akasecurity/tap/flightcrew` — see
[homebrew-tap](https://github.com/akasecurity/homebrew-tap).

> Codex and Antigravity currently install **flightcrew** (multi-harness). `claude-tools` and `ai-tc`
> are Claude Code tools; on other harnesses install `claude-tools` via its shell kit / Homebrew.

## ai-tc — landing soon

The **AI Traffic Control** (`ai-tc`) plugin is listed above but not yet installable from the
marketplace. It's tracked here so the roster is complete; the entry becomes live when the tool is
public. Until then, `/plugin install ai-tc@akasecurity` is not expected to work.

## About

First-party marketplace for [AKA Security](https://akasecurity.io) — security tooling and safe
defaults for coding agents. The `plugins.json` registry index is machine-readable and structured so
the marketplace can open to community submissions later without a rewrite. Community-health files
(Code of Conduct, Contributing, Security) are inherited from the
[akasecurity/.github](https://github.com/akasecurity/.github) org defaults.
