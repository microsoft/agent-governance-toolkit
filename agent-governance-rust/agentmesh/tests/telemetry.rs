#![cfg(feature = "telemetry")]

use agentmesh::telemetry::{
    hex_sha256, NoopTelemetrySink, OtelTelemetrySink, PolicyTelemetryEvent, TelemetrySink,
};
use agentmesh::{AgentMeshClient, ClientOptions, PolicyDecision};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct RecordingSink {
    events: Mutex<Vec<PolicyTelemetryEvent>>,
}

impl RecordingSink {
    fn events(&self) -> Vec<PolicyTelemetryEvent> {
        self.events.lock().expect("events lock").clone()
    }
}

impl TelemetrySink for RecordingSink {
    fn record_policy_evaluation(&self, event: &PolicyTelemetryEvent) {
        self.events.lock().expect("events lock").push(event.clone());
    }
}

fn policy_yaml() -> String {
    r#"
version: "1.0"
agent: telemetry-test
policies:
  - name: capability-gate
    type: capability
    allowed_actions:
      - "data.read"
    denied_actions:
      - "shell:*"
"#
    .to_string()
}

#[test]
fn recording_sink_receives_sanitized_allow_event() {
    let sink = Arc::new(RecordingSink::default());
    let opts = ClientOptions {
        policy_yaml: Some(policy_yaml()),
        telemetry_sink: Some(sink.clone()),
        ..Default::default()
    };
    let client = AgentMeshClient::with_options("telemetry-agent", opts).unwrap();

    let result = client.execute_with_governance("data.read", None);

    assert!(result.allowed);
    assert_eq!(result.decision, PolicyDecision::Allow);
    let events = sink.events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.decision_label, "allow");
    assert!(event.allowed);
    assert_eq!(event.action_hash, hex_sha256("data.read"));
    assert_eq!(event.action_len_bytes, "data.read".len());
    assert_eq!(event.agent_id_hash, hex_sha256(&client.identity.did));
    assert_eq!(event.agent_id_hash.len(), 64);
    assert_eq!(event.action_hash.len(), 64);
    assert!(event.elapsed >= Duration::ZERO);
}

#[test]
fn telemetry_event_does_not_expose_denied_reason_or_context_values() {
    let sink = Arc::new(RecordingSink::default());
    let opts = ClientOptions {
        policy_yaml: Some(policy_yaml()),
        telemetry_sink: Some(sink.clone()),
        ..Default::default()
    };
    let client = AgentMeshClient::with_options("secret-agent", opts).unwrap();
    let mut context = HashMap::new();
    context.insert(
        "token".to_string(),
        serde_yaml::Value::String("SECRET-TOKEN-123".to_string()),
    );

    let result = client.execute_with_governance("shell:rm", Some(&context));

    assert!(!result.allowed);
    assert!(matches!(result.decision, PolicyDecision::Deny(_)));
    let rendered = format!("{:?}", sink.events());
    for raw in [
        "shell:rm",
        "secret-agent",
        &client.identity.did,
        "SECRET-TOKEN-123",
        "Blocked by policy",
        "capability-gate",
    ] {
        assert!(
            !rendered.contains(raw),
            "telemetry event leaked raw value {raw:?}: {rendered}"
        );
    }
    assert!(rendered.contains("deny"));
}

#[test]
fn noop_sink_preserves_governance_behavior() {
    let opts = ClientOptions {
        policy_yaml: Some(policy_yaml()),
        telemetry_sink: Some(Arc::new(NoopTelemetrySink)),
        ..Default::default()
    };
    let client = AgentMeshClient::with_options("noop-agent", opts).unwrap();

    let result = client.execute_with_governance("data.read", None);

    assert!(result.allowed);
    assert_eq!(result.decision, PolicyDecision::Allow);
    assert!(client.audit.verify());
}

#[test]
fn otel_sink_uses_global_noop_provider_without_panicking() {
    let sink = OtelTelemetrySink::new();
    let event = PolicyTelemetryEvent::new(
        "did:agentmesh:otel-agent",
        "data.read",
        &PolicyDecision::Allow,
        Duration::from_millis(7),
    );

    sink.record_policy_evaluation(&event);
}
