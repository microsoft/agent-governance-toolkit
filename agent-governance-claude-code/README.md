# AGT Claude Code Plugin

This package is the **production package surface** for Agent Governance Toolkit on Claude Code.

It ships a Claude Code plugin that uses:

- Claude hooks for deterministic session, prompt, and pre-tool governance
- a bundled MCP server for operator-facing AGT inspection tools
- the AGT TypeScript SDK for policy evaluation, prompt defense, and MCP threat scanning

## What this package is

- a first-party Claude Code plugin package
- an experimental parity layer for the existing Copilot CLI governance work
- a publishable npm package that can also be loaded locally with Claude Code

## What this package is not

- a Copilot-style in-process extension
- a universal governance layer for every Claude surface
- a guarantee of full Copilot CLI feature parity

## Current scope

This initial package enforces:

- `SessionStart` governance context injection
- `UserPromptSubmit` prompt inspection and fail-closed blocking
- `PreToolUse` tool-call inspection with allow, deny, or ask behavior

It also exposes two MCP tools:

- `agt_policy_status`
- `agt_policy_check_text`

The stdio server accepts `Content-Length` frames and newline-delimited JSON
and always answers with newline-delimited JSON.
Headers are limited to 8 KiB; JSON messages are limited to 5 MiB in UTF-8 bytes,
including when a message arrives across multiple reads.

## Important parity gaps

- Claude slash commands are markdown-driven, so `/agt-governance:agt-status` and `/agt-governance:agt-check` are thin wrappers around MCP tools rather than deterministic code handlers.
- `PostToolUse` in Claude cannot reliably redact tool output after the tool has already executed, so this package does not claim Copilot-style output suppression parity.
- Hook execution is out-of-process. The package keeps enforcement in command hooks so policy errors can fail closed.

## Recursive-delete protection for Bash

<!-- cspell:ignore talosrobotics -->
The bundled `recursive-delete` rule uses a quote-aware command tokenizer and
flag parser adapted from the OpenCode implementation and shell-comment handling
in PRs #4129 and #4142 by Ricky-G (MIT). PR #3834 by talosrobotics was the
earlier Claude Code regex fix for this rule.
It denies `rm` invocations with both recursive and force flags, including `-rf`,
`-fr`, `-r -f`, `--recursive --force`, quoted flags, and common wrappers such as
`sudo`, `env`, `command`, and `timeout`. It respects command boundaries, comments,
and the `--` end-of-options marker. Substitutions are scanned independently while
preserving the enclosing command and word, so `rm -r "$(pwd)/src" -f` is denied. Substitution output remains
unknown rather than being evaluated. Literal text such as `echo $(pwd) rm -rf src`
or `echo "rm -rf src"` does not trigger this rule. Redirection operators and their filenames are separated
from command arguments, so a filename such as `-rf` is not treated as a deletion
flag. Lookup, help, and list modes such as `command -v` do not count as execution.

The cleanup exception applies only to a single command whose targets are all
recognized relative build artifacts, such as `node_modules` or `dist`. Mixed
safe/unsafe targets, wildcard or variable targets, redirections, and incomplete
shell syntax do not qualify. For example, `rm -rf node_modules src/*` is denied.
Exempt commands still pass through the rest of the policy, including Bash review.

The built-in matcher applies to rules with `id: "recursive-delete"` and a Bash
tool name, using the configured rule effect. Bundled Bash rules have
`commandPatterns: []`; explicit user patterns continue to run alongside the
built-in matcher. Existing policies containing the old regex gain the parser's
coverage, but their explicit regex can still produce false positives. Remove
that obsolete pattern from the Bash rule to use only the built-in matcher.

This is a bounded tokenizer, not a full shell evaluator. It does not resolve
brace or variable expansions, shell strings passed to `eval` or `sh -c`, indirect
deletion through `find` or `xargs`, remote/container execution, or every wrapper.
Escaped nested backticks are not fully supported, and command text inside a
heredoc can conservatively trigger a denial. Recursive deletion without force
(for example, `rm -r src`) remains subject to the rest of the configured policy.
Keep Bash review enabled for forms outside this matcher's coverage.

## Local development

Run these commands from the **repository root** so the relative plugin path resolves correctly.

Install dependencies:

```powershell
cd agent-governance-claude-code
npm install
```

Load the plugin directly:

```powershell
claude --plugin-dir .\agent-governance-claude-code
```

```bash
claude --plugin-dir "$(pwd)/agent-governance-claude-code"
```

Inspect the active policy and command wiring:

```text
/agt-governance:agt-status
/agt-governance:agt-check suspicious text to inspect
```

Reload after edits:

```text
/reload-plugins
```

## Commands

The package provides two Claude commands:

- `/agt-governance:agt-status`
- `/agt-governance:agt-check`

## Example walkthrough

For a runnable repo-local walkthrough with a sample policy override, expected prompts, and cleanup
notes, see:

- [`examples/claude-code-agt`](../examples/claude-code-agt/README.md)
- [`docs/packages/claude-code-governance.md`](../docs/packages/claude-code-governance.md)

## Policy loading

The package loads policy in this order:

1. `AGT_CLAUDE_POLICY_PATH`
2. `%USERPROFILE%\.claude\agt\policy.json`
3. `~/.claude/agt/policy.json`
4. bundled `config/default-policy.json`

Audit entries are written to:

- Windows: `%USERPROFILE%\.claude\agt\audit-log.json`
- macOS/Linux: `~/.claude/agt/audit-log.json`

Override with `AGT_CLAUDE_AUDIT_PATH`.

The audit log retains the newest 10,000 entries. Before the first rollover it
uses the legacy JSON array format, whose chain is always anchored to the genesis
hash. After rollover, it stores the retained entries with a `seamHash` object so
the shortened hash chain stays verifiable. Removing entries from the front still
fails verification if the stored anchor and hashes are left unchanged (naive
tampering). This is an unkeyed SHA-256 chain, not proof against an attacker who
can rewrite the log: truncating and recomputing `seamHash`, or converting a legacy
array into the seam format with a matching anchor, can pass verification. Such
rewriting was already possible by recomputing the chain before this change.
A log already front-truncated by an older version is not automatically
re-anchored and remains unverifiable by design.

## Validation

```powershell
cd agent-governance-claude-code
npm run check
npm test
```
