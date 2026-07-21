<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# AGT Codex CLI Governance Hooks

This package is the **production install surface** for Agent Governance Toolkit on the
[OpenAI Codex CLI](https://developers.openai.com/codex).

It installs AGT governance into Codex's lifecycle hooks and uses:

- Codex hooks for deterministic session, prompt, and pre-tool governance
- a bundled MCP server for operator-facing AGT inspection tools
- the AGT TypeScript SDK for policy evaluation, prompt defense, and MCP threat scanning

> **Status — proposed upstream.** This package is proposed for the main AGT repository via
> [RFC #3408: Codex Integration](https://github.com/microsoft/agent-governance-toolkit/issues/3408).
> It is a thin host adapter over the existing Claude Code governance core, following the same
> copy-and-adapt derivation used for the OpenCode integration
> ([#2658](https://github.com/microsoft/agent-governance-toolkit/pull/2658)). The design below
> — enforcement surface, decision mapping, and security model — is that RFC's reference
> implementation, verified in a sandboxed `CODEX_HOME` and live against Codex 0.144.6.

## What this package is

- a first-party Codex CLI governance integration
- a parity layer for the existing Claude Code governance package — it adapts the same
  governance core (policy engine, audit log, poisoning scanner) and adds a thin Codex host
  adapter, following the same copy-and-adapt pattern as the OpenCode package
- an npm package that installs hooks into a Codex home you choose

## What this package is not

- an in-process extension (Codex hooks run out-of-process, as subprocess command hooks)
- a guarantee of output redaction (see parity gaps below)
- a universal governance layer for every Codex surface

## Current scope

This package enforces three Codex lifecycle events:

- `SessionStart` — governance context injection
- `UserPromptSubmit` — prompt inspection with fail-closed blocking
- `PreToolUse` — tool-call inspection with allow, deny, or ask (review) decisions

Decisions map onto Codex's hook response schema: a policy deny returns
`permissionDecision: "deny"` with a reason; a review returns `permissionDecision: "ask"`;
an allow returns no decision. Every decision is appended to a tamper-evident,
hash-chained audit log under `<CODEX_HOME>/agt/audit-log.json`.

## Install

From the repo (works today — this package is not yet published to npm):

```bash
cd agent-governance-codex-cli
npm install
node bin/agt-codex.mjs install
```

After the package is released, the published flow matches the other AGT CLI packages:

```bash
npx @microsoft/agent-governance-codex-cli install
```

This merges AGT's hook entries into `<CODEX_HOME>/hooks.json` (default `~/.codex`) and
seeds a default developer-protection policy at `<CODEX_HOME>/agt/policy.json`. It does not
overwrite an existing policy, and it identifies its own entries by an `AGT governance`
status-message prefix so it never disturbs hooks you defined yourself.

Target a specific home (useful for testing) with `--codex-home`:

```bash
node bin/agt-codex.mjs install --codex-home /path/to/codex-home
```

### One-time trust step (required)

Codex does not run non-managed hooks until you review and trust them. After installing,
open Codex against that home and run:

```text
/hooks
```

Review the AGT hooks and trust them. Until you do, **Codex silently skips the hooks and no
governance is applied** — verify with `node bin/agt-codex.mjs status` and by confirming the audit log
grows after a governed action. For unattended automation that already vets its hook
sources, `codex exec --dangerously-bypass-hook-trust` runs trusted-by-policy without the
interactive step (do not use this on developer machines).

### Enterprise install

To enforce AGT hooks for all users without a per-user trust step, deploy them as managed
hooks via `requirements.toml` (`allow_managed_hooks_only` / `[hooks] managed_dir`). Managed
hooks skip user review. See the Codex hooks documentation for the managed-hook contract.

## Lifecycle commands

```bash
node bin/agt-codex.mjs install    [--codex-home <dir>]   # merge hooks + seed default policy
node bin/agt-codex.mjs status     [--codex-home <dir>]   # show installed hooks, policy, audit health
node bin/agt-codex.mjs uninstall  [--codex-home <dir>]   # remove only AGT-owned hook entries
```

## Parity gaps (Codex specifics)

- **No `PostToolUse` output redaction.** Codex hooks are out-of-process, so — as with
  Claude Code — this package cannot reliably strip secrets from tool output after a tool
  has already run. Enforcement is preventive (before execution), not output-filtering.
- **`PreToolUse` fires before shell and other tool calls**, so command-level governance
  covers the highest-risk surface. Tool coverage tracks Codex's own hook matcher support.
- **Hooks are trust-gated.** A fresh install applies no governance until the one-time
  trust step above. `node bin/agt-codex.mjs status` reports whether the audit chain is growing so this
  gap is observable, not silent.

## Development

```bash
cd agent-governance-codex-cli
npm install
npm test
```

The governance core (`lib/policy.mjs`, `lib/audit.mjs`, `lib/poisoning.mjs`,
`server/agt-mcp.mjs`) is adapted from `agent-governance-claude-code`, mirroring how the
OpenCode package was derived from it. Only host identity — surface name, agent id, config
paths, and the `AGT_CODEX_*` environment variables — is rebranded for Codex; the
governance logic is unchanged.
