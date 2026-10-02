<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# AGT Codex CLI Governance Hooks

This package is the **production install surface** for Agent Governance Toolkit on the
[OpenAI Codex CLI](https://developers.openai.com/codex).

It installs AGT governance into Codex's lifecycle hooks and uses:

- Codex hooks for deterministic session, prompt, and pre-tool governance
- the AGT TypeScript SDK for policy evaluation, prompt defense, and MCP threat scanning

> **Status: first-party package, not yet published to npm.** This package lives in the main
> AGT repository. It is a thin host adapter over the existing Claude Code governance core,
> following the same copy-and-adapt derivation used for the OpenCode integration
> ([#2658](https://github.com/microsoft/agent-governance-toolkit/pull/2658)), and originated from
> [RFC #3408: Codex Integration](https://github.com/microsoft/agent-governance-toolkit/issues/3408).
> The design below (enforcement surface, decision mapping, and security model) is covered by the
> package's process-boundary tests and sandboxed `CODEX_HOME` reproduction.

## What this package is

- a first-party Codex CLI governance integration
- a parity layer for the existing Claude Code governance package: it adapts the same
  governance core (policy engine, audit log, poisoning scanner) and adds a thin Codex host
  adapter, following the same copy-and-adapt pattern as the OpenCode package
- a Codex plugin (a `.codex-plugin/plugin.json` manifest + `hooks/hooks.json`) that you register into a Codex home you choose

## What this package is not

- an in-process extension (Codex hooks run out-of-process, as subprocess command hooks)
- a guarantee of output redaction (see parity gaps below)
- a universal governance layer for every Codex surface

## Current scope

This package enforces three Codex lifecycle events:

- `SessionStart`: governance context injection
- `UserPromptSubmit`: prompt inspection with fail-closed blocking
- `PreToolUse`: tool-call inspection with allow or deny decisions

Decisions map onto Codex's supported hook response schema: a policy deny returns
`permissionDecision: "deny"` with a reason, and an allow returns no decision. AGT policy
reviews are also denied because Codex does not support an interactive `ask` decision in
`PreToolUse`. Every decision is appended to a tamper-evident, hash-chained audit log under
`<CODEX_HOME>/agt/audit-log.json`.

## Install

From the repo (works today; this package is not yet published to npm):

```bash
cd agent-governance-codex-cli
npm install
node bin/agt-codex.mjs install
```

After the package is released, the published flow matches the other AGT CLI packages:

```bash
npx @microsoft/agent-governance-codex-cli install
```

This registers the package with Codex's plugin system: it adds the package as a plugin
marketplace and installs the `agt-governance` plugin (`codex plugin marketplace add` +
`codex plugin add`), then seeds a default developer-protection policy at
`<CODEX_HOME>/agt/policy.json` (default home `~/.codex`). The installer confirms Codex reports
the plugin `installed, enabled` before it returns, so it never silently no-ops. Codex loads the
plugin's `hooks/hooks.json` and expands `${PLUGIN_ROOT}` at runtime, so no absolute paths are
baked into your config and your own hooks are untouched. It does not overwrite an existing policy.

Target a specific home (useful for testing) with `--codex-home`:

```bash
node bin/agt-codex.mjs install --codex-home /path/to/codex-home
```

### One-time trust step (required)

Codex does not run non-managed plugin hooks until you review and trust them. After installing,
open Codex against that home and run:

```text
/plugins
```

Review the AGT plugin and trust it. Until you do, **Codex silently skips the hooks and no
governance is applied**. Verify with `node bin/agt-codex.mjs status` and by confirming the audit log
grows after a governed action. For unattended automation that already vets its plugin
sources, `codex exec --dangerously-bypass-hook-trust` runs trusted-by-policy without the
interactive step (do not use this on developer machines).

### Enterprise install

To enforce AGT hooks for all users without a per-user trust step, deploy them as managed
hooks via `requirements.toml` (`allow_managed_hooks_only` / `[hooks] managed_dir`). Managed
hooks skip user review. See the Codex hooks documentation for the managed-hook contract.

## Lifecycle commands

```bash
node bin/agt-codex.mjs install    [--codex-home <dir>]   # register + enable the plugin, seed default policy
node bin/agt-codex.mjs status     [--codex-home <dir>]   # show plugin state, policy, audit health
node bin/agt-codex.mjs uninstall  [--codex-home <dir>]   # remove the plugin and its marketplace
```

## Parity gaps (Codex specifics)

- **No `PostToolUse` output redaction.** Codex hooks are out-of-process, so as with
  Claude Code this package cannot reliably strip secrets from tool output after a tool
  has already run. Enforcement is preventive (before execution), not output-filtering.
- **`PreToolUse` fires before shell and other tool calls**, so command-level governance
  covers the highest-risk surface. Tool coverage tracks Codex's own hook matcher support.
- **Recursive-delete matching is command-position based.** The shipped rule recognizes
  multiline and control-flow command positions, relative/path-qualified `rm` and `find`,
  `find -delete`/`-exec`/`-execdir`, assignment prefixes, and the documented wrapper
  commands (`sudo`, `doas`, `command`, `exec`, `eval`, `nohup`, `busybox`, `nice`, `time`,
  `timeout`, `env`, `xargs`, and `strace`). It is not a shell sandbox and does not promise
  coverage for arbitrary nested interpreters such as `bash -c`, `chroot`, `ionice`,
  `setsid`, `unshare`, or quoted/escaped command names.
- **Hooks are trust-gated.** A fresh install applies no governance until the one-time
  trust step above. `node bin/agt-codex.mjs status` reports whether the audit chain is growing so this
  gap is observable, not silent.
- **The host can fail open.** Codex proceeds when a hook exceeds its 30-second timeout or
  exits with a status other than the hook-blocking exit code. Keep hook startup and policy
  evaluation deterministic; this package cannot override Codex's timeout and exit handling.
- **Audit corruption is fail closed.** A malformed or hand-edited `audit-log.json` causes
  prompt and tool evaluation to deny until the file is repaired or removed. Check
  `agt-codex status` before deleting it so the incident is recorded and investigated.
- **Concurrent audit writes are not serialized.** Parallel `PreToolUse` processes can race
  during the read/verify/write cycle and lose an entry even though each individual write is
  atomically renamed. Use a serialized hook runner or managed deployment when retaining a
  complete audit history is required.

## Development

```bash
cd agent-governance-codex-cli
npm install
npm test
```

The governance core (`lib/policy.mjs`, `lib/audit.mjs`, `lib/poisoning.mjs`) is
adapted from `agent-governance-claude-code`, mirroring how the
OpenCode package was derived from it. Codex-specific behavior includes the supported
`permissionDecision` mapping, fail-closed review handling, Codex config paths, Windows
installer invocation, and patch-target extraction; these differences are covered by the
Codex tests rather than being treated as a byte-identical copy.

The Windows installer regression covers package paths containing command-shell
metacharacters. The repository's current CI matrix is Linux-only, so that path is
verified locally on Windows rather than by hosted CI.
