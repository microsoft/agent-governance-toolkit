# Information-flow-control agent ACS Rust demo

This is the canonical zero-config example. The manifest declares a Rego policy bundle and no annotators, so `AgentControl::from_path` wires the bundled OPA policy dispatcher against the manifest-relative Rego bundle with no host dispatcher code. The demo in `demo.rs` constructs the runtime in one line and evaluates a `pre_tool_call` information-flow check that allows a public egress of public-labeled data and denies egress of confidential-labeled data. It also shows stateless label propagation: the policy returns the produced data's label in `verdict.result_labels`, and the demo threads that label back in as a source label on a follow-up turn into a confidential-cleared sink.

Run it from the repository root:

```sh
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
cargo run -p agent_control_specification --example ifc_agent
```

`opa` is expected at `~/.local/bin/opa` (or on `PATH`). The demo prints `demo verification: PASS` when the allowed and denied flows match the policy.

For demos that supply custom dispatchers because their annotations come from local deterministic host heuristics, see [`records_agent`](../records_agent), [`research_agent`](../research_agent), and [`coding_agent`](../coding_agent). See [Zero-config construction](../../README.md#zero-config-construction) for when each constructor applies.
