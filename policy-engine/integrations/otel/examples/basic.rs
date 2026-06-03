use agent_control_specification_core::{
    Decision, EnforcementMode, InterventionPoint, TelemetryEvent, TelemetryEventType, TelemetrySink,
};
use agent_control_specification_otel::OtelTelemetrySink;

fn main() {
    let sink = OtelTelemetrySink::default();
    sink.emit(
        TelemetryEvent::new(TelemetryEventType::Decision, InterventionPoint::Input)
            .with_enforcement_mode(EnforcementMode::Enforce)
            .with_decision(Decision::Allow)
            .with_policy_id("example_policy")
            .with_duration_ms(0.5),
    );
}
