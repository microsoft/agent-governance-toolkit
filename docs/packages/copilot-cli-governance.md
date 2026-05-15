# @microsoft/agent-governance-copilot-cli — Copilot CLI governance package

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../../LICENSE)
[![npm](https://img.shields.io/npm/v/%40microsoft/agent-governance-copilot-cli)](https://www.npmjs.com/package/@microsoft/agent-governance-copilot-cli)

`@microsoft/agent-governance-copilot-cli` is the production install surface for AGT-backed
GitHub Copilot CLI governance. It installs a packaged Copilot CLI extension into the user's
Copilot home, seeds a developer-protection policy, and provides explicit lifecycle commands for
install, update, uninstall, and diagnostics.

## What it is

- a first-party install surface for local Copilot CLI governance
- a package that depends on `@microsoft/agent-governance-sdk`
- an explicit `agt-copilot` CLI that mutates `~/.copilot` only when you ask it to

## What it is not

- not a `postinstall` package that silently writes into the user home directory
- not a replacement for organization-wide governance controls
- not the tutorial story; the runnable walkthrough remains in `examples/copilot-cli-agt`

## Install

```bash
npx @microsoft/agent-governance-copilot-cli install
```

The installer copies the extension into:

- Windows: `%USERPROFILE%\.copilot\extensions\agt-global-policy`
- macOS/Linux: `~/.copilot/extensions/agt-global-policy`

It seeds the default policy at:

- Windows: `%USERPROFILE%\.copilot\agt\policy.json`
- macOS/Linux: `~/.copilot/agt/policy.json`

## Commands

```bash
agt-copilot install
agt-copilot install --force-policy
agt-copilot update
agt-copilot update --force-policy
agt-copilot policy apply --profile balanced
agt-copilot policy validate
agt-copilot policy show
agt-copilot uninstall
agt-copilot uninstall --remove-policy
agt-copilot doctor
agt-copilot doctor --json
```

`install` writes a manifest so `uninstall` only removes AGT-managed installs. `update` refreshes an
existing AGT-managed install in place and can reseed the packaged policy with `--force-policy`.

Policy management is handled through first-class CLI commands rather than slash commands:

- `agt-copilot policy path`
- `agt-copilot policy show`
- `agt-copilot policy validate`
- `agt-copilot policy apply --file <path>`
- `agt-copilot policy apply --profile <strict|balanced|advisory>`

## Copilot CLI setup

The package does not auto-edit Copilot CLI settings. Enable extensions in your Copilot config:

```json
{
  "experimental": true,
  "experimental_flags": ["EXTENSIONS"]
}
```

Then reload Copilot CLI:

```text
/clear
/agt status
```

## Default developer-protection policy

The packaged default policy:

- fails closed on policy errors
- reviews unknown tools by default unless they are explicitly allow-listed
- blocks downloaded script execution, credential reads, metadata endpoint access, and policy-bypass shell patterns
- reviews risky shell, fetch-style, and persistence-oriented write operations
- scans fetched-content tools for poisoning and exfiltration cues
- inspects `bash` and `powershell` output in advisory mode so suspicious shell output is flagged without suppressing routine build and test logs

This PR keeps that behavior as the shipped **strict** baseline. For reviewer discussion and local
experimentation, example `strict`, `balanced`, and `advisory` profiles are included under
`examples/copilot-cli-agt/config/profiles/`.

The installed extension still carries its own bundled default policy so it can fall back safely if
the user policy file is missing or invalid.

If a custom policy becomes invalid, remove `~/.copilot/agt/policy.json` or point
`AGT_COPILOT_POLICY_PATH` at a valid replacement.

## Relationship to the example

For the scenario-driven tutorial, sample prompts, and expected outcomes, see:

- [Tutorial 46 — Copilot CLI governance installer](../tutorials/46-copilot-cli-governance.md)
- [`examples/copilot-cli-agt`](../../examples/copilot-cli-agt/README.md)

## Release model

GitHub Actions builds and tests the package in CI. Production npm publishing goes through the
ESRP-backed Azure DevOps release pipeline alongside the other AGT npm packages.
