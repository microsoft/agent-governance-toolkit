# Information flow control example

This Rust example uses `AgentControl::from_path` with a Rego policy bundle and no annotators. It enforces a no write down label policy at `pre_tool_call` by comparing `snapshot.ifc.source_labels` with the projected tool clearance.

## Threat or governance need

A host that tracks data provenance needs a deterministic sink check before data leaves the agent through a tool. ACS stays stateless. The host supplies source labels on each call, and the policy returns `result_labels` for the host to persist with produced data.

## Run

```sh
cargo run -p agent_control_specification --example ifc_agent --quiet
```

`opa` must be available on `PATH`.

## Expected verdicts

Public data sent to `public_egress` allows. The propagated public label then allows into `trusted_archive`. Confidential data sent to `public_egress` denies with `ifc_clearance_violation`.

## Where to look

`manifest.yaml` declares tool clearances and the `pre_tool_call` target. `policy/ifc_agent.rego` imports `policy/lib/ifc.rego`. `demo.rs` shows host label propagation and zero configuration construction.
