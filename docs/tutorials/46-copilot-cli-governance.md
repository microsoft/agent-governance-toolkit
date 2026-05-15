# Tutorial 46 — Copilot CLI governance installer

> **Package:** `@microsoft/agent-governance-copilot-cli` · **Time:** 15 minutes ·
> **Prerequisites:** Node.js 22+, GitHub Copilot CLI with extensions enabled

This tutorial shows how to install the AGT Copilot CLI governance package, confirm the extension is
active, and exercise the guarded repo triage scenario.

## What you'll do

1. install the production Copilot CLI governance package
2. confirm the local extension is loaded
3. run prompt, tool, and tool-output checks
4. compare the results against the scenario expectations

## Install the package

```bash
npx @microsoft/agent-governance-copilot-cli install
```

If you want to preserve an existing user policy, run the install without `--force-policy`. If you
want to reset to the packaged baseline, add:

```bash
npx @microsoft/agent-governance-copilot-cli install --force-policy
```

To refresh an existing AGT-managed install after pulling a newer package build:

```bash
npx @microsoft/agent-governance-copilot-cli update
npx @microsoft/agent-governance-copilot-cli update --force-policy
```

## Enable Copilot CLI extensions

Add the extension flags to your Copilot CLI settings if they are not already present:

```json
{
  "experimental": true,
  "experimental_flags": ["EXTENSIONS"]
}
```

Reload Copilot CLI:

```text
/clear
/agt status
```

At this point `/agt status` should report:

- the active policy source
- the vendored SDK source
- the audit path
- the configured prompt defense floor

## Run the guarded scenario

Open the scenario from the repo:

- [`examples/copilot-cli-agt/scenarios/guarded-repo-triage`](../../examples/copilot-cli-agt/scenarios/guarded-repo-triage/README.md)

Then run the scenario in order:

1. paste `prompts/prompt-injection.txt`
2. paste `prompts/unsafe-bootstrap.txt`
3. run `/agt check "<contents of tool-output/poisoned-web-content.txt>"`
4. compare against `expected-outcomes.md`

For a proof-oriented threat matrix and evidence checklist, also see:

- [`proof-package.md`](../../examples/copilot-cli-agt/scenarios/guarded-repo-triage/proof-package.md)
- [`proof-corpus.json`](../../examples/copilot-cli-agt/scenarios/guarded-repo-triage/proof-corpus.json)

## Example install from source

When developing from the repo, you can also use the local package directly:

```bash
cd agent-governance-copilot-cli
npm install
node ./bin/agt-copilot.mjs install
```

## Troubleshooting

### `/agt` is not available

Check:

- the extension exists under `~/.copilot/extensions/agt-global-policy`
- extensions are enabled in Copilot CLI settings
- you reloaded Copilot CLI with `/clear`

### `agt-copilot doctor`

Run:

```bash
agt-copilot doctor
```

Doctor validates:

- extension installation state
- AGT install manifest presence
- vendored SDK presence
- user policy parseability and supported schema version
- installed extension version versus the package version you are running
- Copilot CLI extension settings

If doctor reports an invalid policy, remove `~/.copilot/agt/policy.json` or set
`AGT_COPILOT_POLICY_PATH` to a valid replacement before reloading Copilot CLI.

### Try an example policy profile

The example repo path includes ready-to-copy policy profiles:

- `examples/copilot-cli-agt/config/profiles/strict.json`
- `examples/copilot-cli-agt/config/profiles/balanced.json`
- `examples/copilot-cli-agt/config/profiles/advisory.json`

For example:

```powershell
Copy-Item .\examples\copilot-cli-agt\config\profiles\balanced.json $HOME\.copilot\agt\policy.json -Force
```

Then reload Copilot CLI with `/clear` and inspect the result with `/agt status`.

You can also manage policy files directly with the installer CLI:

```bash
agt-copilot policy path
agt-copilot policy validate
agt-copilot policy apply --profile balanced
```

### Node is missing

This package requires a working Node runtime. If `node --version` fails, install Node.js LTS and
retry the package install.

## Next steps

- customize `~/.copilot/agt/policy.json` for your team baseline
- re-run the scenario in `advisory` mode
- inspect the audit log at `~/.copilot/agt/audit-log.json`
