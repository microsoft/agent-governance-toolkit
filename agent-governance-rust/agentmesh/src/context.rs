// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Accumulated context governance for multi-step agent workflows.
//!
//! The semantic contract follows the Python implementation introduced in
//! <https://github.com/microsoft/agent-governance-toolkit/pull/2800>.

use crate::governance_support::DataClassification;
use crate::types::PolicyDecision;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Immutable, versioned governance state accumulated by a workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextEnvelope {
    envelope_id: String,
    workflow_id: String,
    labels: BTreeSet<String>,
    aggregate_sensitivity: DataClassification,
    restrictions: BTreeSet<String>,
    version: u64,
    parent_envelope_id: Option<String>,
    created_at: String,
}

impl ContextEnvelope {
    /// Create an empty public envelope.
    pub fn new(envelope_id: impl Into<String>, workflow_id: impl Into<String>) -> Self {
        Self {
            envelope_id: envelope_id.into(),
            workflow_id: workflow_id.into(),
            labels: BTreeSet::new(),
            aggregate_sensitivity: DataClassification::Public,
            restrictions: BTreeSet::new(),
            version: 0,
            parent_envelope_id: None,
            created_at: String::new(),
        }
    }

    /// Record the parent envelope for a delegated workflow.
    pub fn with_parent_envelope_id(mut self, parent_envelope_id: impl Into<String>) -> Self {
        self.parent_envelope_id = Some(parent_envelope_id.into());
        self
    }

    /// Attach a caller-supplied timestamp without reading the wall clock.
    pub fn with_created_at(mut self, created_at: impl Into<String>) -> Self {
        self.created_at = created_at.into();
        self
    }

    pub fn envelope_id(&self) -> &str {
        &self.envelope_id
    }

    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    pub fn labels(&self) -> &BTreeSet<String> {
        &self.labels
    }

    pub fn aggregate_sensitivity(&self) -> DataClassification {
        self.aggregate_sensitivity
    }

    pub fn restrictions(&self) -> &BTreeSet<String> {
        &self.restrictions
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn parent_envelope_id(&self) -> Option<&str> {
        self.parent_envelope_id.as_deref()
    }

    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    /// Return the next envelope after joining actual result labels and sensitivity.
    pub fn fold<I, S>(&self, new_labels: I, new_sensitivity: DataClassification) -> ContextEnvelope
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut next = self.clone();
        next.labels.extend(new_labels.into_iter().map(Into::into));
        next.aggregate_sensitivity = next.aggregate_sensitivity.max(new_sensitivity);
        next.version = next
            .version
            .checked_add(1)
            .expect("context envelope version overflow");
        next
    }

    /// Return the next envelope after adding restrictions.
    pub fn apply_restrictions<I, S>(&self, restrictions: I) -> ContextEnvelope
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut next = self.clone();
        next.restrictions
            .extend(restrictions.into_iter().map(Into::into));
        next.version = next
            .version
            .checked_add(1)
            .expect("context envelope version overflow");
        next
    }

    /// Project the envelope onto the only value intended to cross a trust boundary.
    pub fn reference(&self) -> EnvelopeReference {
        EnvelopeReference {
            envelope_id: self.envelope_id.clone(),
            sensitivity: self.aggregate_sensitivity,
        }
    }
}

/// Opaque cross-boundary handle that does not expose envelope contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeReference {
    pub envelope_id: String,
    pub sensitivity: DataClassification,
}

/// Organization-authored rule over a combination of accumulated labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregationRule {
    pub name: String,
    pub all_labels: BTreeSet<String>,
    pub sets_sensitivity: DataClassification,
    pub adds_restrictions: BTreeSet<String>,
}

impl AggregationRule {
    pub fn new<I, S>(
        name: impl Into<String>,
        all_labels: I,
        sets_sensitivity: DataClassification,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            name: name.into(),
            all_labels: all_labels.into_iter().map(Into::into).collect(),
            sets_sensitivity,
            adds_restrictions: BTreeSet::new(),
        }
    }

    pub fn with_restrictions<I, S>(mut self, restrictions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.adds_restrictions = restrictions.into_iter().map(Into::into).collect();
        self
    }
}

/// Result of evaluating an envelope against aggregation rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregationResult {
    pub aggregate_sensitivity: DataClassification,
    pub restrictions: BTreeSet<String>,
    pub escalate: bool,
    pub rules_applied: Vec<String>,
}

/// Apply matching rules and escalate unknown combinations at the configured threshold.
pub fn evaluate_aggregation(
    envelope: &ContextEnvelope,
    rules: &[AggregationRule],
    category_threshold: usize,
) -> AggregationResult {
    let mut aggregate_sensitivity = envelope.aggregate_sensitivity;
    let mut restrictions = envelope.restrictions.clone();
    let mut rules_applied = Vec::new();

    for rule in rules {
        if rule.all_labels.is_subset(&envelope.labels) {
            aggregate_sensitivity = aggregate_sensitivity.max(rule.sets_sensitivity);
            restrictions.extend(rule.adds_restrictions.iter().cloned());
            rules_applied.push(rule.name.clone());
        }
    }

    AggregationResult {
        aggregate_sensitivity,
        restrictions,
        escalate: rules_applied.is_empty() && envelope.labels.len() >= category_threshold,
        rules_applied,
    }
}

/// A restriction the host must enforce before an action proceeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obligation {
    pub key: String,
    pub satisfied: bool,
}

/// Obligations and labels carried by a constrained outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObligationSet {
    pub obligations: Vec<Obligation>,
    pub result_labels: BTreeSet<String>,
}

impl ObligationSet {
    pub fn all_satisfied(&self) -> bool {
        self.obligations
            .iter()
            .all(|obligation| obligation.satisfied)
    }
}

/// Context-aware governance outcome before mapping to the SDK policy surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextOutcome {
    Allow,
    Constrain,
    Deny,
    Escalate,
}

/// Context-aware decision and any obligations it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextDecision {
    pub outcome: ContextOutcome,
    pub obligations: ObligationSet,
    pub aggregate_sensitivity: DataClassification,
    pub reason: String,
}

/// Fold an action's actual result into an envelope and re-run aggregation.
pub fn accumulate<I, S>(
    envelope: &ContextEnvelope,
    result_labels: I,
    result_sensitivity: DataClassification,
    rules: &[AggregationRule],
    category_threshold: usize,
) -> ContextEnvelope
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut folded = envelope.fold(result_labels, result_sensitivity);
    let aggregation = evaluate_aggregation(&folded, rules, category_threshold);
    folded.aggregate_sensitivity = aggregation.aggregate_sensitivity;
    folded.apply_restrictions(aggregation.restrictions)
}

/// Gate a flow-bearing action against already accumulated context.
pub fn decide_next(
    envelope: &ContextEnvelope,
    action: &str,
    rules: &[AggregationRule],
    category_threshold: usize,
    restricted_floor: DataClassification,
) -> ContextDecision {
    let aggregation = evaluate_aggregation(envelope, rules, category_threshold);

    if aggregation.escalate {
        return ContextDecision {
            outcome: ContextOutcome::Escalate,
            obligations: ObligationSet {
                result_labels: envelope.labels.clone(),
                ..ObligationSet::default()
            },
            aggregate_sensitivity: aggregation.aggregate_sensitivity,
            reason: "aggregation threshold crossed with no governing rule".to_string(),
        };
    }

    let gating_restriction = match action {
        "export" => Some("no_external_export"),
        "delegate" => Some("no_external_delegation"),
        "memory_write" => Some("no_memory_write"),
        _ => None,
    };
    let restriction_present =
        gating_restriction.is_some_and(|restriction| envelope.restrictions.contains(restriction));
    let floor_triggered =
        gating_restriction.is_some() && aggregation.aggregate_sensitivity >= restricted_floor;

    if restriction_present || floor_triggered {
        let reason = if restriction_present {
            format!(
                "action {action:?} restricted by {:?}",
                gating_restriction.expect("restriction checked above")
            )
        } else {
            format!("action {action:?} gated by sensitivity floor")
        };
        return ContextDecision {
            outcome: ContextOutcome::Constrain,
            obligations: ObligationSet {
                obligations: envelope
                    .restrictions
                    .iter()
                    .map(|restriction| Obligation {
                        key: restriction.clone(),
                        satisfied: false,
                    })
                    .collect(),
                result_labels: envelope.labels.clone(),
            },
            aggregate_sensitivity: aggregation.aggregate_sensitivity,
            reason,
        };
    }

    ContextDecision {
        outcome: ContextOutcome::Allow,
        obligations: ObligationSet {
            result_labels: envelope.labels.clone(),
            ..ObligationSet::default()
        },
        aggregate_sensitivity: aggregation.aggregate_sensitivity,
        reason: String::new(),
    }
}

/// Map a context outcome to the SDK policy decision without failing open.
pub fn to_policy_decision(
    decision: &ContextDecision,
    has_obligation_channel: bool,
) -> PolicyDecision {
    match decision.outcome {
        ContextOutcome::Allow => PolicyDecision::Allow,
        ContextOutcome::Deny => PolicyDecision::Deny(reason_or(
            &decision.reason,
            "accumulated context denied the action",
        )),
        ContextOutcome::Escalate => PolicyDecision::RequiresApproval(reason_or(
            &decision.reason,
            "accumulated context requires review",
        )),
        ContextOutcome::Constrain
            if has_obligation_channel
                || (!decision.obligations.obligations.is_empty()
                    && decision.obligations.all_satisfied()) =>
        {
            PolicyDecision::Allow
        }
        ContextOutcome::Constrain => PolicyDecision::Deny(reason_or(
            &decision.reason,
            "context obligations cannot be enforced",
        )),
    }
}

/// Inherit every parent restriction while allowing a child to add more.
pub fn merge_restrictions<I, S>(parent: &ContextEnvelope, child_declared: I) -> BTreeSet<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut restrictions = parent.restrictions.clone();
    restrictions.extend(child_declared.into_iter().map(Into::into));
    restrictions
}

fn reason_or(reason: &str, fallback: &str) -> String {
    if reason.is_empty() {
        fallback.to_string()
    } else {
        reason.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aggregation_rule() -> AggregationRule {
        AggregationRule::new(
            "pii_financial_restricted",
            ["pii", "financial"],
            DataClassification::Restricted,
        )
        .with_restrictions(["no_external_export"])
    }

    #[test]
    fn envelope_join_is_immutable_commutative_and_grow_only() {
        let original = ContextEnvelope::new("env-1", "workflow-1")
            .with_parent_envelope_id("parent-1")
            .with_created_at("2026-07-28T00:00:00Z");
        let first = original
            .fold(["pii"], DataClassification::Internal)
            .fold(["financial"], DataClassification::Confidential);
        let reversed = original
            .fold(["financial"], DataClassification::Confidential)
            .fold(["pii"], DataClassification::Internal);

        assert!(original.labels().is_empty());
        assert_eq!(first.labels(), reversed.labels());
        assert_eq!(
            first.aggregate_sensitivity(),
            reversed.aggregate_sensitivity()
        );
        assert_eq!(
            first
                .fold(["pii"], DataClassification::Public)
                .aggregate_sensitivity(),
            DataClassification::Confidential
        );

        let restricted = first
            .apply_restrictions(["no_external_export"])
            .apply_restrictions(std::iter::empty::<&str>());
        assert!(restricted.restrictions().contains("no_external_export"));
        assert_eq!(restricted.version(), 4);
        assert_eq!(restricted.parent_envelope_id(), Some("parent-1"));
    }

    #[test]
    fn envelope_reference_does_not_serialize_context_contents() {
        let reference = ContextEnvelope::new("env-1", "workflow-1")
            .fold(["pii"], DataClassification::TopSecret)
            .apply_restrictions(["no_external_export"])
            .reference();
        let value = serde_json::to_value(reference).expect("reference should serialize");

        assert_eq!(
            value,
            serde_json::json!({
                "envelope_id": "env-1",
                "sensitivity": "top_secret"
            })
        );
    }

    #[test]
    fn aggregation_applies_rules_and_escalates_unknown_combinations() {
        let rules = [aggregation_rule()];
        let governed = ContextEnvelope::new("env-1", "workflow-1")
            .fold(["pii", "financial"], DataClassification::Internal);
        let result = evaluate_aggregation(&governed, &rules, 3);

        assert_eq!(result.aggregate_sensitivity, DataClassification::Restricted);
        assert!(result.restrictions.contains("no_external_export"));
        assert_eq!(result.rules_applied, ["pii_financial_restricted"]);
        assert!(!result.escalate);

        let unknown = ContextEnvelope::new("env-2", "workflow-1").fold(
            ["pii", "behavioral", "location"],
            DataClassification::Internal,
        );
        assert!(evaluate_aggregation(&unknown, &rules, 3).escalate);
    }

    #[test]
    fn accumulation_uses_actual_results_and_gates_the_next_action() {
        let rules = [aggregation_rule()];
        let envelope =
            ContextEnvelope::new("env-1", "workflow-1").fold(["pii"], DataClassification::Internal);
        let accumulated = accumulate(
            &envelope,
            ["financial"],
            DataClassification::Confidential,
            &rules,
            3,
        );

        assert!(accumulated.labels().contains("financial"));
        assert_eq!(
            accumulated.aggregate_sensitivity(),
            DataClassification::Restricted
        );
        assert!(accumulated.restrictions().contains("no_external_export"));

        let decision = decide_next(
            &accumulated,
            "export",
            &rules,
            3,
            DataClassification::Restricted,
        );
        assert_eq!(decision.outcome, ContextOutcome::Constrain);
        assert!(matches!(
            to_policy_decision(&decision, false),
            PolicyDecision::Deny(_)
        ));
        assert_eq!(to_policy_decision(&decision, true), PolicyDecision::Allow);
    }

    #[test]
    fn restrictions_and_sensitivity_floor_gate_independently() {
        let explicit = ContextEnvelope::new("env-1", "workflow-1")
            .fold(["pii"], DataClassification::Confidential)
            .apply_restrictions(["no_external_export"]);
        let explicit_decision =
            decide_next(&explicit, "export", &[], 99, DataClassification::Restricted);
        assert_eq!(explicit_decision.outcome, ContextOutcome::Constrain);

        let floor = ContextEnvelope::new("env-2", "workflow-1")
            .fold(["pii"], DataClassification::Restricted);
        let floor_decision =
            decide_next(&floor, "delegate", &[], 99, DataClassification::Restricted);
        assert_eq!(floor_decision.outcome, ContextOutcome::Constrain);
    }

    #[test]
    fn escalation_maps_to_a_non_allowing_review_decision() {
        let envelope = ContextEnvelope::new("env-1", "workflow-1").fold(
            ["pii", "financial", "location"],
            DataClassification::Internal,
        );
        let decision = decide_next(&envelope, "read", &[], 3, DataClassification::Restricted);

        assert_eq!(decision.outcome, ContextOutcome::Escalate);
        assert!(matches!(
            to_policy_decision(&decision, false),
            PolicyDecision::RequiresApproval(_)
        ));
    }

    #[test]
    fn constrain_without_a_channel_only_allows_satisfied_obligations() {
        let mut decision = ContextDecision {
            outcome: ContextOutcome::Constrain,
            obligations: ObligationSet::default(),
            aggregate_sensitivity: DataClassification::Restricted,
            reason: "restricted".to_string(),
        };
        assert!(matches!(
            to_policy_decision(&decision, false),
            PolicyDecision::Deny(_)
        ));

        decision.obligations.obligations.push(Obligation {
            key: "no_external_export".to_string(),
            satisfied: true,
        });
        assert_eq!(to_policy_decision(&decision, false), PolicyDecision::Allow);
    }

    #[test]
    fn delegation_restrictions_are_a_grow_only_union() {
        let parent =
            ContextEnvelope::new("parent", "workflow-1").apply_restrictions(["no_external_export"]);
        let child_restrictions = merge_restrictions(&parent, ["no_memory_write"]);

        assert_eq!(
            child_restrictions,
            BTreeSet::from([
                "no_external_export".to_string(),
                "no_memory_write".to_string()
            ])
        );
    }
}
