// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Classified audit events for context-envelope transitions.
//!
//! The wire values and event shape follow the Python implementation introduced
//! in <https://github.com/microsoft/agent-governance-toolkit/pull/2800>.

use crate::context::ContextEnvelope;
use crate::governance_support::DataClassification;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CONTEXT_ENVELOPE_CREATED: &str = "CONTEXT_ENVELOPE_CREATED";
pub const CONTEXT_ENVELOPE_UPDATED: &str = "CONTEXT_ENVELOPE_UPDATED";
pub const CONTEXT_AGGREGATION_ELEVATED: &str = "CONTEXT_AGGREGATION_ELEVATED";
pub const CONTEXT_DELEGATED: &str = "CONTEXT_DELEGATED";
pub const CONTEXT_REDACTED: &str = "CONTEXT_REDACTED";
pub const DERIVED_ARTIFACT_LABELED: &str = "DERIVED_ARTIFACT_LABELED";

/// Governance-relevant delta between two context-envelope versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextEvent {
    pub event_type: String,
    pub agent_id: String,
    pub context_envelope_id: String,
    pub previous_sensitivity: DataClassification,
    pub new_sensitivity: DataClassification,
    pub labels_added: BTreeSet<String>,
    pub rules_applied: Vec<String>,
    pub restrictions_added: BTreeSet<String>,
    pub classification: DataClassification,
}

/// Build an event whose classification is never below either envelope.
pub fn context_event<I, S>(
    event_type: impl Into<String>,
    agent_id: impl Into<String>,
    before: &ContextEnvelope,
    after: &ContextEnvelope,
    rules_applied: I,
) -> ContextEvent
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    ContextEvent {
        event_type: event_type.into(),
        agent_id: agent_id.into(),
        context_envelope_id: after.envelope_id().to_string(),
        previous_sensitivity: before.aggregate_sensitivity(),
        new_sensitivity: after.aggregate_sensitivity(),
        labels_added: after
            .labels()
            .difference(before.labels())
            .cloned()
            .collect(),
        rules_applied: rules_applied.into_iter().map(Into::into).collect(),
        restrictions_added: after
            .restrictions()
            .difference(before.restrictions())
            .cloned()
            .collect(),
        classification: before
            .aggregate_sensitivity()
            .max(after.aggregate_sensitivity()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_event_records_delta_and_classification_floor() {
        let before = ContextEnvelope::new("env-1", "workflow-1")
            .fold(["pii"], DataClassification::Confidential);
        let after = before
            .fold(["financial"], DataClassification::Restricted)
            .apply_restrictions(["no_external_export"]);
        let event = context_event(
            CONTEXT_AGGREGATION_ELEVATED,
            "agent.customer-success",
            &before,
            &after,
            ["pii_financial_restricted"],
        );

        assert_eq!(event.previous_sensitivity, DataClassification::Confidential);
        assert_eq!(event.new_sensitivity, DataClassification::Restricted);
        assert_eq!(
            event.labels_added,
            BTreeSet::from(["financial".to_string()])
        );
        assert_eq!(
            event.restrictions_added,
            BTreeSet::from(["no_external_export".to_string()])
        );
        assert_eq!(event.rules_applied, ["pii_financial_restricted"]);
        assert_eq!(event.classification, DataClassification::Restricted);
        assert_eq!(
            serde_json::to_value(&event)
                .expect("context event should serialize")
                .get("event_type"),
            Some(&serde_json::json!("CONTEXT_AGGREGATION_ELEVATED"))
        );
    }

    #[test]
    fn wire_values_and_higher_previous_classification_are_preserved() {
        assert_eq!(
            [
                CONTEXT_ENVELOPE_CREATED,
                CONTEXT_ENVELOPE_UPDATED,
                CONTEXT_AGGREGATION_ELEVATED,
                CONTEXT_DELEGATED,
                CONTEXT_REDACTED,
                DERIVED_ARTIFACT_LABELED,
            ],
            [
                "CONTEXT_ENVELOPE_CREATED",
                "CONTEXT_ENVELOPE_UPDATED",
                "CONTEXT_AGGREGATION_ELEVATED",
                "CONTEXT_DELEGATED",
                "CONTEXT_REDACTED",
                "DERIVED_ARTIFACT_LABELED",
            ]
        );

        let before = ContextEnvelope::new("env-1", "workflow-1")
            .fold(std::iter::empty::<&str>(), DataClassification::Restricted);
        let after = ContextEnvelope::new("env-1", "workflow-1")
            .fold(std::iter::empty::<&str>(), DataClassification::Internal);
        let event = context_event(
            CONTEXT_ENVELOPE_UPDATED,
            "agent-1",
            &before,
            &after,
            std::iter::empty::<&str>(),
        );

        assert_eq!(event.classification, DataClassification::Restricted);
    }
}
