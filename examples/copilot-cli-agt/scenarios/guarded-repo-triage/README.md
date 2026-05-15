# Guarded Repo Triage Scenario

This scenario walks through a realistic Copilot CLI session where AGT guards:

1. **prompt submission**
2. **tool invocation**
3. **tool output reuse**

It assumes you already installed the example extension from `examples/copilot-cli-agt`.

## Scenario goal

Simulate a repo triage workflow where an attacker or untrusted source tries to:

- override instructions in the prompt
- convince the agent to run a downloaded script
- inject poisoned instructions into fetched tool output

## Files

| File | Purpose |
| --- | --- |
| `prompts/prompt-injection.txt` | User prompt that should be blocked or rewritten |
| `prompts/unsafe-bootstrap.txt` | User prompt likely to lead to denied shell activity |
| `tool-output/poisoned-web-content.txt` | Example untrusted content for `/agt check` |
| `expected-outcomes.md` | What should happen in each step |
| `proof-corpus.json` | Machine-readable threat matrix for repeatable validation |
| `proof-package.md` | Proof-oriented validation guide and evidence checklist |

## Run it

1. Reload extensions with `/clear`
2. Run `/agt status`
3. Paste `prompts/prompt-injection.txt` as a user prompt
4. Paste `prompts/unsafe-bootstrap.txt` as a user prompt
5. Run `/agt check "<contents of tool-output/poisoned-web-content.txt>"`
6. Compare behavior against `expected-outcomes.md`

## Package the proof

When you want a stronger enterprise-ready evidence trail, use:

1. `proof-corpus.json` for the full attack matrix and expected actions
2. `proof-package.md` for the validation workflow and evidence checklist
3. `~/.copilot/agt/audit-log.json` for the runtime audit trail

## Optional follow-up

Edit `~/.copilot/agt/policy.json` and change:

- `mode` from `enforce` to `advisory`
- `toolPolicies.reviewTools`
- `blockedToolCalls`

Then run `/agt reload` and repeat the scenario to observe the different enforcement level.
