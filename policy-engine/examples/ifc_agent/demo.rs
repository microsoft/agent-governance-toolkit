use agent_control_specification::{AgentControl, Decision, EnforcementMode, InterventionPoint};
use serde_json::json;
use std::{env, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let example_dir = sdk_dir.join("../../examples/ifc_agent").canonicalize()?;
    env::set_current_dir(&example_dir)?;

    // Zero-config construction. The manifest declares a Rego policy bundle and no
    // annotators, so from_path wires the bundled OPA policy dispatcher against the
    // manifest-relative bundle with no host dispatcher code.
    let control = AgentControl::from_path("manifest.yaml")?;

    let allowed = control.evaluate_intervention_point(
        InterventionPoint::PreToolCall,
        json!({
            "ifc": {"source_labels": ["public"]},
            "tool_call": {
                "name": "public_egress",
                "args": {"body": "weather summary"}
            }
        }),
        EnforcementMode::Enforce,
    );

    assert_eq!(allowed.verdict.decision, Decision::Allow);

    // Stateless label propagation. The policy returns the join of the incoming
    // source labels in `result_labels`. The core stores nothing; the host is
    // expected to persist this with the data the sink produced and re-supply it
    // as a source label on later turns.
    assert_eq!(allowed.verdict.result_labels, vec!["public".to_string()]);
    let propagated_labels = allowed.verdict.result_labels.clone();

    // A subsequent turn threads the returned label back in as a source label.
    // Here the produced data flows into a confidential-cleared sink, which
    // dominates the propagated public label, so the flow is allowed and the
    // label propagates again unchanged.
    let next_turn = control.evaluate_intervention_point(
        InterventionPoint::PreToolCall,
        json!({
            "ifc": {"source_labels": propagated_labels},
            "tool_call": {
                "name": "trusted_archive",
                "args": {"body": "weather summary"}
            }
        }),
        EnforcementMode::Enforce,
    );

    assert_eq!(next_turn.verdict.decision, Decision::Allow);
    assert_eq!(next_turn.verdict.result_labels, vec!["public".to_string()]);

    let denied = control.evaluate_intervention_point(
        InterventionPoint::PreToolCall,
        json!({
            "ifc": {"source_labels": ["confidential"]},
            "tool_call": {
                "name": "public_egress",
                "args": {"body": "customer account balance"}
            }
        }),
        EnforcementMode::Enforce,
    );

    assert_eq!(denied.verdict.decision, Decision::Deny);
    assert_eq!(
        denied.verdict.reason.as_deref(),
        Some("ifc_clearance_violation")
    );

    println!("demo verification: PASS");
    Ok(())
}
