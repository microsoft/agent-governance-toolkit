# Web research agent ACS Node demo

This runnable demo uses the generated manifest and Rego policy with the ACS Node SDK. It simulates a web research agent with `http_fetch` and `post_webhook`, supplies host-side classifier annotations, evaluates OPA at `input`, `pre_tool_call`, `post_tool_call`, and `output`, and shows allow, deny, escalate/approval, warn, and redaction effects.

This is an advanced custom-dispatcher example. It supplies its own annotator dispatcher because the classifier annotations are produced by local deterministic host heuristics rather than a reachable endpoint, so it does not use the bundled zero-config annotator default. A host whose manifest uses Rego policies and either declares no annotators or points them at configured endpoints integrates in roughly three lines with `fromPath`. See [Zero-config construction](../../README.md#zero-config-construction).

## Run

From the repository root:

```sh
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
cd sdk/node && npm install && npm run build
cd ../../examples/research_agent/app && npm start
```

`opa` is expected at `~/.local/bin/opa` (or set `OPA=/path/to/opa`).
