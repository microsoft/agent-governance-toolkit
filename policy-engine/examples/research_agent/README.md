# Node research agent example

This Node SDK example drives ACS manually with `evaluateInterventionPoint` and `enforce`. It guards input, output, `pre_tool_call`, and `post_tool_call` around deterministic research tools.

## Threat or governance need

Research agents retrieve untrusted content and may post summaries to external systems. The example blocks prompt injection and disallowed domains, escalates internal domains and webhook posts, warns on large content, and redacts secrets in retrieved pages and final output.

## Run

```sh
cd sdk/node
npm ci
npm run build
cd ../..
node examples/research_agent/app/index.js
```

`opa` must be available through `$OPA`, `$OPA_PATH`, `PATH`, or `$HOME/.local/bin/opa`.

## Expected verdicts

The runner demonstrates allow, deny, escalate with approval, warn, and redaction outcomes. It exits with `demo verification: PASS` after all assertions pass.

## Where to look

`manifest.yaml` declares tool metadata and annotations. `policy/web_research_agent_guardrails.rego` contains the Rego rules. `app/index.js` shows manual Node enforcement and transformed policy target use.
