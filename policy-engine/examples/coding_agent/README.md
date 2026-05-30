# Coding agent ACS Rust demo

This folder contains the generated ACS policy plus a runnable Rust host app in `app/`.

Run it from the repository root:

```sh
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
cargo run --manifest-path examples/coding_agent/app/Cargo.toml
```

The demo loads `manifest.yaml`, evaluates `policy/software_engineering_assistant_guardrails.rego` with OPA at `input`, `pre_tool_call`, `post_tool_call`, and `output`, supplies simple host-side classifier annotations, and prints allowed, denied, escalated-with-approval, redacted, and streaming flows.

This is an advanced custom-dispatcher example. It supplies its own annotator dispatcher because the classifier annotations are produced by local deterministic host heuristics rather than a reachable endpoint, so it does not use the bundled zero-config annotator default. A host whose manifest uses Rego policies and either declares no annotators or points them at configured endpoints integrates in roughly three lines with `from_path`. See [Zero-config construction](../../README.md#zero-config-construction).

## Manifest composition (`extends`)

The manifest is split to exercise composition. `base.manifest.yaml` is an
org-wide baseline that owns the shared policy, tools, annotators, and the
`input` and `output` intervention points (deny malicious input, redact secrets
in the final answer). `manifest.yaml` is the agent overlay: it `extends` the
base and adds the coding-agent-specific `pre_tool_call` and `post_tool_call`
guardrails. The core loader merges them additively before evaluation.

## Streaming aggregation

The core only ever evaluates complete snapshots. The streaming flow shows the
required host pattern: the model output is produced as chunks, the host
aggregates them, and only the complete text is evaluated at `output`. The demo
deliberately splits a secret across chunk boundaries (`...TOK` + `EN=abc123`) to
show that per-chunk scanning would miss it while aggregate-then-enforce
redacts it.

