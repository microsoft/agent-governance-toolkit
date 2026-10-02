# AGT OpenCode Plugin

This package is the **production package surface** for Agent Governance Toolkit
on [OpenCode](https://github.com/anomalyco/opencode).

It ships an OpenCode plugin that uses:

- OpenCode's in-process plugin hooks for deterministic session, prompt, tool,
  and output governance
- a bundled stdio MCP server (`server/agt-mcp.mjs`) for operator-facing AGT
  inspection tools
- the AGT TypeScript SDK for policy evaluation, prompt defense, and MCP threat
  scanning

> Public Preview — APIs and policy schema may change.

## What this package is

- a first-party OpenCode plugin package
- a parity layer for the existing Antigravity and Claude Code governance
  packages, adapted to OpenCode's richer in-process hook contract
- a publishable npm package (`@microsoft/agent-governance-opencode`) that can
  also be loaded locally from a workspace `.opencode/plugins/` directory

## What this package is not

- a Copilot-style extension
- a universal governance layer for every IDE surface
- a guarantee of full Copilot CLI feature parity

## Why OpenCode benefits from in-process governance

Unlike Claude Code (subprocess hooks) and Antigravity (subprocess hooks),
OpenCode loads plugins **in-process** as async TypeScript/JavaScript functions.
That means this package can:

- enforce policy on `tool.execute.before` without an extra subprocess round trip
- **redact** secrets from `tool.execute.after` output before the model sees it
  (a parity win over Claude Code, which cannot rewrite tool output)
- expose custom tools like `agt_policy_status` directly to the model without
  needing a separate MCP server

The stdio MCP server is still shipped for operators who want to invoke
governance tools from external workflows.

## Current scope

This initial package enforces:

- `session.created`         — best-effort status logging; no context injection
- `event` (chat-style)      — scans submitted prompts; throws to block
- `tool.execute.before`     — allow / review / deny tool calls
- `tool.execute.after`      — scans tool output and redacts known secret
                              patterns (AWS, GitHub PAT, OpenAI, JWT, PEM
                              private keys, Azure storage keys)

There is no failed-tool hook in this plugin. A failed call that never reaches
`tool.execute.after` does not receive an output audit entry.

It also exposes two custom tools (in-process **and** via the stdio MCP server):

- `agt_policy_status` — return the active AGT policy snapshot
- `agt_policy_check_text` — inspect arbitrary text for prompt-injection and
  context-poisoning findings

The stdio server accepts `Content-Length` frames and newline-delimited JSON
and always answers with newline-delimited JSON.
Headers are limited to 8 KiB; JSON messages are limited to 5 MiB in UTF-8 bytes,
including when a message arrives across multiple reads.

## Local development

Run these commands from the package directory:

```powershell
cd agent-governance-opencode
npm install
npm run check
```

## Loading the plugin in OpenCode

OpenCode loads plugins from:

1. `opencode.json` `plugin` entries (npm specifiers)
2. `~/.config/opencode/{plugin,plugins}/*.{ts,js}` (user-global)
3. `.opencode/{plugin,plugins}/*.{ts,js}` (workspace-local)

Use Option A for a normal installation. Workspace files must use `.js` or `.ts`;
OpenCode does not auto-discover `.mjs` plugin files. The package's internal
`.mjs` entry point is loaded through its npm export instead.

Configure AGT through **one** of these plugin-loading paths for a workspace. Do
not keep duplicate AGT shims or load the package both from `opencode.json` and a
workspace plugin file. Duplicate registrations for the same OpenCode client and
workspace are suppressed and emit a warning, but removing the duplicate source
keeps startup configuration unambiguous.

### Option A — workspace `opencode.json` (recommended)

OpenCode installs the configured npm package and its dependencies at startup.

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["@microsoft/agent-governance-opencode"]
}
```

### Option B — workspace plugin file with an installed package

From your project root, install the package into the OpenCode config directory:

```powershell
npm install --prefix .opencode @microsoft/agent-governance-opencode
```

Create `.opencode/plugins/agt.js` (the singular `.opencode/plugin/` directory
also works):

```js
export { default } from "@microsoft/agent-governance-opencode";
```

This imports the installed package from `.opencode/node_modules`; it does not
require an AGT repository checkout or a copied source directory.

### Verify plugin discovery

From the same project root, run this command without invoking a model:

```powershell
opencode debug config
```

Inspect the resolved `plugin` array. Option A should include the AGT npm
specifier; Option B should include a file URL ending in `/agt.js`. If neither
appears, stop and correct the configuration before using the agent.

Discovery alone does not prove that the module imports, initializes, or runs
its governance hooks. A broken re-export can still appear in this list. Review
startup errors and check the loaded plugin's `agt_policy_status` before use;
policy validity and plugin discovery are separate checks. Out-of-band runtime
activation evidence is tracked in issue #3708.

### Optional MCP server installation

The MCP server exposes inspection tools. Configuring it alone does not install
the in-process governance hooks from Option A or B. Install the package in your
project before using this path:

```powershell
npm install @microsoft/agent-governance-opencode
```

In `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "agt-governance": {
      "type": "local",
      "command": [
        "node",
        "./node_modules/@microsoft/agent-governance-opencode/server/agt-mcp.mjs"
      ]
    }
  }
}
```

## Configuration

The plugin loads policy from (in order):

1. `AGT_OPENCODE_POLICY_PATH` environment variable
2. `./.agt/policy.json` in the working directory
3. `~/.config/opencode/agt/policy.json`
4. The bundled `config/default-policy.json` (enforce mode, fail-closed)

Audit log path defaults to `~/.config/opencode/agt/audit-log.json` and can be
overridden via `AGT_OPENCODE_AUDIT_PATH`.

### Audit evidence

Each entry is a link in the audit hash chain and carries:

| Field | Always present | Meaning |
|-------|----------------|---------|
| `v` | yes | Entry schema version. `2` today. Entries without it are version 1. |
| `timestamp`, `agentId`, `action`, `decision` | yes | What ran, under which session, and how it was decided. |
| `previousHash`, `hash` | yes | Chain links. `hash` covers every other field on the entry. |
| `policyVersion` | yes | `sha256:<hex>` over the active policy, so a decision can be tied to the policy that produced it. |
| `reason` | when one exists | Why the decision was reached, flattened and capped at 1024 characters. |
| `argsDigest`, `argsDigestAlg` | tool calls only | Identifies the attempted arguments without storing them. |
| `argsTruncated` | only when `true` | Arguments exceeded 1 MiB and only the first 1 MiB was digested. |
| `argsUnserializable` | only when `true` | Arguments could not be serialized, so the digest is a constant and identifies nothing. |
| `principal` | when configured | `{ sub, iss? }`, the identity the agent acted for. |

Entries are verified against the version they were written under, so a log
written by an earlier release keeps verifying after an upgrade. New entries are
hashed over a canonical form with keys sorted by UTF-16 code unit, the ordering
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) specifies, so an external
verifier can reproduce a hash without knowing property insertion order.

**Rollover.** The log keeps the most recent 10,000 entries. When it rolls over,
the file changes from a bare array to `{ "seamHash": "<hex>", "entries": [...] }`,
where `seamHash` is the hash of the last evicted entry. The surviving head
anchors to that seam instead of to the genesis hash, so the chain stays
verifiable across an eviction. A file that has never rolled over stays a bare
array and is always anchored to the genesis hash, so a bare array whose head
does not anchor to genesis fails verification.

The chain is unkeyed, so this raises the cost of editing a log rather than
preventing it. Someone who can rewrite the file can also rewrap it as
`{ "seamHash": "<hash of the entry before the new head>", "entries": [...] }`
and it will verify. Detecting that needs a signature or an external anchor,
neither of which this format has.

If a log was already broken by the earlier rollover behaviour, it stays
unverifiable and appends keep failing, which is intended. Move that file aside
and let a new one start.

**The upgrade is one way.** Once a version 2 entry is written to a file, an
older release cannot verify that file. Because a failed chain denies every
request, downgrading after an upgrade means moving the audit file aside first.

**Reproducing a hash.** The preimage is the canonical JSON of the entry with
`hash` removed, encoded as UTF-8:

```
hash = sha256(canonicalJson(entry without hash))
```

**Reproducing `argsDigest`.** The preimage is the canonical JSON of the tool
arguments object, encoded as UTF-8, truncated to the first 1 MiB:

```
argsDigest = sha256(canonicalJson(args))          # HMAC-SHA256 when a key is set
```

Canonical JSON follows ordinary JSON semantics for the argument object, so a
value JSON drops is dropped. If the arguments cannot be serialized at all, for
example because they are cyclic, hold a bigint, or have a throwing getter, the
digest is taken over the constant `[unserializable]` and the entry carries
`argsUnserializable: true`. All such entries share one digest value, so it
identifies nothing.

**What the digest does and does not do.** `argsDigest` lets you match an entry
against another system's record of the same call. It does not hide the
arguments: tool arguments are often low entropy, such as a path or a short
command, and a plain SHA-256 of one can be recovered by guessing. Set
`AGT_OPENCODE_AUDIT_HMAC_KEY` to at least 32 bytes to switch to HMAC-SHA256,
which makes digests unguessable without the key. A shorter key is refused
rather than used. Verification never recomputes the digest, so rotating or
losing the key leaves existing entries verifiable.

The key is read from the OpenCode process environment, so tool subprocesses
such as `bash` inherit it. An agent able to run a shell command can read it and
forge digests. Treat it as raising the cost of guessing a digest, not as a
secret the agent cannot reach.

**Recording who the agent acted for.** `agentId` identifies the session, not the
person who delegated the work. Set `AGT_OPENCODE_PRINCIPAL_SUB`, and optionally
`AGT_OPENCODE_PRINCIPAL_ISS`, to record that identity alongside each decision.
The principal is read only from operator configuration, never from tool
arguments or model output, since a principal the agent can name is not
evidence.

**The principal is declared, not verified.** It records who the operator says
the agent acted for. Nothing proves that person authorised any particular
action, and on a single-user machine the same person whose actions are logged
usually controls that environment. Read it as a label on the session, not as
proof of approval.

A misconfigured principal or HMAC key is refused rather than silently dropped.
When `denyOnPolicyError` is on, which is the default, that refusal denies
requests until the configuration is fixed. With it off, decisions are still
recorded, but with an unkeyed digest and no principal.

**Limits.** `reason` names the rule that matched and its description, not the
value that matched it, so a denied read of a secret-bearing path does not write
that path into the log. `policyVersion` covers the policy document, so it does
not change when a package upgrade alters built-in defaults.

### Positive command and URL allowlists

Positive allowlist gates are opt-in. Set the relevant default effect to `deny`
to make unmatched values fail closed.

For command-bearing tool calls, configure `toolPolicies` with:

- `allowedCommandPatterns`: regex pattern objects with `source` and optional
  `flags`
- `commandDefaultEffect`: `allow` (default) or `deny`

Commands are normalized only for outer whitespace and CRLF line endings before
matching. When the whole command must be approved, use fully anchored patterns
and avoid broad suffixes such as `(?:\\s|$)` that also accept shell chaining,
command substitution, or additional arguments. The shipped example uses exact,
fully anchored command forms. Regex flags `g`, `y`, `m`, and `s` are rejected so
stateful or multiline matching cannot weaken an anchored command policy.

For HTTP(S) resources, configure `directResourcePolicies` with:

- `allowedDomains`: exact hosts or `*.example.com` subdomain wildcards, with an
  optional explicit port such as `internal.example:8443`
- `allowedUrlPatterns`: regex pattern objects evaluated against the normalized
  full URL
- `urlDefaultEffect`: `allow` (default) or `deny`

A wildcard such as `*.example.com` does not include the apex `example.com`.
A domain without a port matches that host on any port and on both `http://` and
`https://`; specifying a port restricts the match to that effective port. If a
policy must allow only HTTPS for a destination, use an anchored
`allowedUrlPatterns` entry for `https://...` rather than an `allowedDomains`
entry for that host.

`urlDefaultEffect: "deny"` governs HTTP(S) strings that are surfaced as tool
arguments. It is not a process-wide or network-layer default deny. URLs embedded
inside shell command strings, scheme-relative values such as `//evil.example`,
`ftp:` URLs, host names without a scheme, and redirects hidden inside an HTTP
client are outside this URL hook boundary. Pair URL restrictions with
`commandDefaultEffect: "deny"` and a narrow command allowlist when command tools
can initiate network access.

Every surfaced HTTP(S) string is checked, so an allowed primary URL does not
make a separate, unapproved redirect-target argument acceptable. HTTP(S) values
are canonicalized before existing `urlRules` are evaluated, including special
scheme forms without `//` such as `https:example.com`. Raw HTTP(S) authorities
that contain a backslash are denied because downstream clients can disagree
about which host such a value targets.

Existing deny and review rules keep their precedence. An allowlist match only
means the positive gate is satisfied; it cannot override a deny from
`blockedToolCalls`, `urlRules`, or another policy backend.

A complete opt-in example is provided at
`config/allowlist-policy.example.json`.

### Session-scoped monotonic state

Policies can opt into staged session state with a `sessionState` block. The
reference policy at `config/session-state-policy.example.json` allows a
`webfetch` before a sensitive-path read and denies it afterward.

- Declare boolean latches in `attributes`. A matching `transitions` entry
  stages its latch in `tool.execute.before`; the pending latch immediately
  participates in `rules`, so concurrent outbound calls in that session are
  blocked while the read is in flight. `tool.execute.after` commits the latch.
- A transition matches the tool name (`*` matches any tool) and, when
  `pathPatterns` is present, one of the configured top-level path arguments.
  The default argument keys are `filePath`, `file_path`, and `path`;
  `argumentKeys` can override them. Without `pathPatterns`, every call to the
  configured tool matches.
- Path matching is lexical: transitions do not resolve symlinks or inspect
  paths embedded in shell commands or other tool arguments. Use transitions
  with tools that expose the resource path directly, and pair them with
  command policy when shell tools can read the same sensitive data.
- Latches can only move from unset to set. Tool output is never parsed to
  create, clear, or downgrade state. Because OpenCode's tool hook does not
  expose a reliable success flag, a matching transition is finalized when
  `tool.execute.after` runs; `session.idle` also conservatively finalizes any
  still-pending transitions. The plugin clears state on `session.deleted`.
- Committed and pending latch events are written to the hash-chained AGT audit
  log and replayed on plugin initialization. Keep that audit log to preserve
  state across restarts. An invalid audit chain or invalid session-state policy
  fails closed. Replay only covers the retained window, so a latch older than
  the retention limit is lost on restart; see the retention note below.
- State is held per OpenCode session, with `maxSessions` defaulting to 1024
  (maximum 4096) and `maxPendingCallsPerSession` defaulting to 64 (maximum
  256); pending attribute references are additionally capped at 256 per
  session. When audit replay finds more latched sessions than `maxSessions`,
  it restores the most recently changed sessions and quarantines older session
  IDs. Quarantined sessions are denied until OpenCode emits `session.deleted`;
  state is never silently dropped to permit those sessions to continue. At
  runtime, reaching the state limit denies new transitions rather than
  evicting a tracked session. Deleted sessions are removed and recorded in the
  audit log.
- With `sessionState` enabled, tool evaluations sharing the audit path are
  serialized within the process so staged transitions and audit-chain updates
  stay ordered; each session retains an independent latch set. This lock is
  process-local. Do not run multiple OpenCode processes concurrently against
  the same audit file; the audit writer does not coordinate cross-process
  read-modify-write updates.

The audit writer retains at most 10,000 entries. Rollover now preserves a
verifiable anchor, so the chain stays valid across the trim and governance
keeps working past that point. See "Audit evidence" above for the file shape.

Replay only sees the retained window, so a latch whose events have scrolled
out of it is not restored on restart. A session that read sensitive data more
than 10,000 entries ago therefore comes back without that latch and its
outbound tools are allowed again. On a busy log, treat the retention limit as
the lifetime of persisted session state, and lower the limit or export the log
if a latch needs to outlive it.

## Important parity notes

- OpenCode's in-process plugin contract does not currently expose a server-side
  "ask the user" decision from inside `tool.execute.before`. When AGT decides
  `review`, this plugin marks the args with `__agt_review_reason` and lets
  OpenCode's normal permission flow run. Operators who want hard-deny behaviour
  on review should set `toolPolicies.defaultEffect: "deny"` in their policy.
- Output redaction is conservative: only well-known credential patterns are
  redacted. The audit entry records that a redaction occurred but never the
  redacted value.
- AGT fails **closed** by default. If the policy file is corrupt or evaluation
  throws, requests are denied. Set `denyOnPolicyError: false` in policy to opt
  into advisory mode.
