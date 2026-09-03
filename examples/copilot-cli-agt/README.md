# AGT Copilot CLI guarded scenario

This example provides a repeatable repo-triage scenario for the AGT Copilot CLI
governance integration. The supported extension, policy profiles, installer, and
tests live in [`agent-governance-copilot-cli`](../../agent-governance-copilot-cli/README.md).
Keeping those executable assets in one package prevents the tutorial from drifting
away from the code users install.

## What lives here

The [`guarded-repo-triage`](scenarios/guarded-repo-triage/README.md) scenario contains:

- prompts that exercise prompt-injection and unsafe shell protections
- poisoned tool output for `/agt check`
- expected outcomes
- a machine-readable proof corpus and an evidence checklist

The package owns:

- the [extension runtime](../../agent-governance-copilot-cli/assets/extensions/agt-global-policy/lib/policy.mjs)
- the [default policy](../../agent-governance-copilot-cli/assets/extensions/agt-global-policy/config/default-policy.json)
- the `strict`, `balanced`, and `advisory` profiles
- installer and policy-management commands
- runtime and installer tests

## Install

Install the published package:

```bash
npx @microsoft/agent-governance-copilot-cli install
```

To test and install the current checkout instead, run these commands from the repository root:

```bash
npm --prefix agent-governance-copilot-cli ci
npm --prefix agent-governance-copilot-cli test
node agent-governance-copilot-cli/bin/agt-copilot.mjs install
```

The installer copies the extension to `~/.copilot/extensions/agt-global-policy` and seeds
`~/.copilot/agt/policy.json` when no policy exists. It does not edit Copilot CLI settings.

Enable extensions if needed:

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

## Run the scenario

Follow the steps in the
[`guarded-repo-triage` README](scenarios/guarded-repo-triage/README.md). The scenario checks:

1. prompt submission
2. tool invocation
3. tool output reuse

Use the package commands to inspect or change the active policy:

```bash
agt-copilot policy path
agt-copilot policy show
agt-copilot policy validate
agt-copilot policy apply --profile balanced
```

Available profiles are:

- [`strict`](../../agent-governance-copilot-cli/assets/extensions/agt-global-policy/config/profiles/strict.json)
- [`balanced`](../../agent-governance-copilot-cli/assets/extensions/agt-global-policy/config/profiles/balanced.json)
- [`advisory`](../../agent-governance-copilot-cli/assets/extensions/agt-global-policy/config/profiles/advisory.json)

Review a profile before applying it. Tool names and acceptable review prompts depend on the
Copilot CLI environment where the policy will run.

## Scope

This scenario demonstrates local governance for Copilot CLI sessions. It is not a replacement
for organization-side enforcement and does not claim coverage across every Copilot surface.
