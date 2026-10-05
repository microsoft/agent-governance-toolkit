<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# AGT Copilot CLI Installer

This package is the **production install surface** for the AGT Copilot CLI governance integration.

It installs a packaged Copilot CLI extension into the user's Copilot home, seeds a default
developer-protection policy, and provides explicit lifecycle commands:

- `agt-copilot install`
- `agt-copilot update`
- `agt-copilot uninstall`
- `agt-copilot doctor`

It uses `@microsoft/agent-governance-sdk` as the runtime dependency for the installed extension.

## Why this package exists

The repo also contains `examples/copilot-cli-agt`, which provides the scenario-driven tutorial.
This package owns the extension source, policy profiles, installer, and tests so production
installs do **not** depend on:

- repo-local SDK builds
- `npm install` side effects that mutate `~/.copilot`

## Install

Published install flow:

```powershell
npx @microsoft/agent-governance-copilot-cli install
```

To refresh an existing AGT-managed install in place:

```powershell
npx @microsoft/agent-governance-copilot-cli update
npx @microsoft/agent-governance-copilot-cli update --force-policy
```

From the repo during development:

```powershell
cd agent-governance-copilot-cli
npm ci
node .\bin\agt-copilot.mjs install
node .\bin\agt-copilot.mjs update --force-policy
```

The installer copies the extension into:

- `C:\Users\<you>\.copilot\extensions\agt-global-policy`

and seeds the default policy at:

- `C:\Users\<you>\.copilot\agt\policy.json`

It does **not** edit Copilot settings automatically. If extensions are not enabled yet, set:

```json
{
  "experimental": true,
  "experimental_flags": ["EXTENSIONS"]
}
```

Then reload Copilot CLI with:

```text
/clear
/agt status
```

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

## Commands

### Install

```powershell
agt-copilot install
agt-copilot install --force-policy
agt-copilot update
agt-copilot update --force-policy
agt-copilot install --copilot-home C:\temp\.copilot
```

### Policy

```powershell
agt-copilot policy path
agt-copilot policy show
agt-copilot policy validate
agt-copilot policy validate --file .\my-policy.json
agt-copilot policy apply --file .\my-policy.json
agt-copilot policy apply --profile balanced
```

Bundled profiles currently available:

- `strict`
- `balanced`
- `advisory`

### Uninstall

```powershell
agt-copilot uninstall
agt-copilot uninstall --remove-policy
```

By default, uninstall removes the managed extension but preserves the user's policy file.

### Doctor

```powershell
agt-copilot doctor
agt-copilot doctor --json
```

Doctor checks:

- whether the extension is installed
- whether the install is AGT-managed
- whether the vendored SDK is present
- whether the user policy parses cleanly and uses a supported schema version
- whether the installed extension version matches the package version you are running
- whether Copilot CLI extensions are enabled

If you accidentally save an invalid policy, remove `~/.copilot/agt/policy.json` or point
`AGT_COPILOT_POLICY_PATH` at a valid replacement.

## Default policy

The packaged default policy is a developer-protection baseline that:

- fails closed on policy errors
- reviews unknown tools by default unless they are explicitly allow-listed
- blocks downloaded script execution, credential reads, metadata endpoint access, and destructive shell patterns
- reviews risky shell, fetch-style, and persistence-oriented write operations
- scans fetched-content tools for poisoning and exfiltration cues
- inspects `bash` and `powershell` output in advisory mode so suspicious output is surfaced without being silently dropped

The package ships that strict baseline as the default. The `strict`, `balanced`, and `advisory`
profiles live under:

- `assets/extensions/agt-global-policy/config/profiles/`

Apply a bundled profile with `agt-copilot policy apply --profile <name>`.

## Notes

- `npm install` for this package should remain inert with respect to `~/.copilot`.
- The Copilot home mutation happens only through explicit CLI commands.
- If you were testing an older build in the same Copilot session, run `/agt reload` or `/clear`
  after updating so the refreshed policy runtime is reloaded.
- The installed extension keeps a bundled default policy so it can fall back safely even when the
  user policy file is missing or invalid.

## Example and tutorial

For a concrete walkthrough and test prompts, see:

- [`examples/copilot-cli-agt`](../examples/copilot-cli-agt/README.md)
- [the guarded repo-triage scenario](../examples/copilot-cli-agt/scenarios/guarded-repo-triage/README.md)

## Design references

The extension packaging and user experience were informed by
[`DamianEdwards/copilot-cli-cost`](https://github.com/DamianEdwards/copilot-cli-cost) and the
[`htek.dev` Copilot CLI extensions guide](https://htek.dev/articles/github-copilot-cli-extensions-complete-guide).
