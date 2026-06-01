# Rust coding agent example

This Rust SDK example guards a local coding assistant with custom annotators and a Rego policy. It demonstrates input checks, file tool mediation, shell command escalation, secret redaction, generated Rego artifact loading, and stream aggregation before output evaluation.

## Threat or governance need

Coding agents can read files, write files, run commands, and leak secrets. The example blocks prompt injection, constrains file writes to the workspace, escalates risky shell commands, redacts secret-like output, and shows that streamed text is assembled before ACS evaluates `output`.

## Run

```sh
cargo run --manifest-path examples/coding_agent/app/Cargo.toml --quiet
```

`opa` must be available through `$OPA`, `$OPA_PATH`, `PATH`, or `$HOME/.local/bin/opa`.

## Expected verdicts

The runner demonstrates allowed file operations, denied input, escalated shell approval, output redaction, and redaction of a token split across stream chunks after aggregation.

## Where to look

`manifest.yaml` extends `base.manifest.yaml`. `policy/software_engineering_assistant_guardrails.rego` contains the generated guardrails. `app/src/main.rs` shows Rust dispatchers, approval handling, and streaming aggregation.
