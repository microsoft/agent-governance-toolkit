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

The repo also contains `examples/copilot-cli-agt`, which remains the tutorial and scenario-driven
reference implementation. This package exists so production installs do **not** depend on:

- example-local scripts
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
npm install
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

For this PR, the package keeps that strict baseline as the shipped default. Example profile
starting points for `strict`, `balanced`, and `advisory` live under:

- `examples/copilot-cli-agt/config/profiles/`

## Notes

- `npm install` for this package should remain inert with respect to `~/.copilot`.
- The Copilot home mutation happens only through explicit CLI commands.
- If you were testing an older build in the same Copilot session, run `/agt reload` or `/clear`
  after updating so the refreshed policy runtime is reloaded.
- The installed extension keeps a bundled default policy so it can fall back safely even when the
  user policy file is missing or invalid.

## Example and tutorial

For a concrete walkthrough and test prompts, see:

- `examples/copilot-cli-agt`
- `examples/copilot-cli-agt/scenarios/guarded-repo-triage`
