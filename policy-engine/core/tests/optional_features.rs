// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(feature = "rego")]
#[test]
fn rego_runner_is_available_through_the_shim() {
    let _: agent_control_spec::rego::RegorusRegoRunner =
        agent_control_specification_core::rego::RegorusRegoRunner::new();
}

#[cfg(feature = "streaming")]
#[test]
fn stream_span_is_available_through_the_shim() {
    let span = agent_control_specification_core::stream_session::StreamSpan::new(
        agent_control_specification_core::stream_session::StreamSourceType::UserRequest,
        0,
        1,
    );
    assert_eq!(span.unwrap().range.end, 1);
}
