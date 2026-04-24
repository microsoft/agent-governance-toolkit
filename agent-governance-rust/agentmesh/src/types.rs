// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared types for the AgentMesh governance framework.

use serde::{Deserialize, Serialize};

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Action is allowed.
    Allow,
    /// Action is denied with a reason.
    Deny(String),
    /// Action requires human approval.
    RequiresApproval(String),
    /// Action is rate-limited; retry after the given number of seconds.
    RateLimited { retry_after_secs: u64 },
}

impl PolicyDecision {
    /// Returns `true` if the decision permits the action.
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }

    /// Short label used in audit logs.
    pub fn label(&self) -> &'static str {
        match self {
            PolicyDecision::Allow => "allow",
            PolicyDecision::Deny(_) => "deny",
            PolicyDecision::RequiresApproval(_) => "requires_approval",
            PolicyDecision::RateLimited { .. } => "rate_limited",
        }
    }
}

/// Trust tier derived from a numeric score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// Score 900–1000.
    VerifiedPartner,
    /// Score 700–899.
    Trusted,
    /// Score 500–699.
    Standard,
    /// Score 300–499.
    Probationary,
    /// Score 0–299.
    Untrusted,
}

impl TrustTier {
    /// Derive the tier from a numeric score (0–1000).
    pub fn from_score(score: u32) -> Self {
        match score {
            900..=1000 => TrustTier::VerifiedPartner,
            700..=899 => TrustTier::Trusted,
            500..=699 => TrustTier::Standard,
            300..=499 => TrustTier::Probationary,
            _ => TrustTier::Untrusted,
        }
    }
}

/// Snapshot of an agent's trust standing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    pub agent_id: String,
    pub score: u32,
    pub tier: TrustTier,
    pub interactions: u64,
}

/// A single immutable entry in the hash-chain audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub timestamp: String,
    pub agent_id: String,
    pub action: String,
    pub decision: String,
    pub previous_hash: String,
    pub hash: String,
}

/// Filter for querying audit entries.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    pub agent_id: Option<String>,
    pub action: Option<String>,
    pub decision: Option<String>,
}

/// Conflict resolution strategy when multiple policy rules produce different decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolutionStrategy {
    /// Any deny decision overrides allows.
    DenyOverrides,
    /// Any allow decision overrides denies.
    AllowOverrides,
    /// The candidate with the highest priority wins.
    #[default]
    PriorityFirstMatch,
    /// The most specific scope wins, with priority as tiebreaker.
    MostSpecificWins,
}

/// The scope at which a policy rule applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyScope {
    /// Applies to all tenants and agents.
    #[default]
    Global,
    /// Applies to a specific tenant.
    Tenant,
    /// Applies to a specific agent.
    Agent,
}

impl PolicyScope {
    /// Returns a numeric specificity value (higher = more specific).
    pub fn specificity(self) -> u32 {
        match self {
            PolicyScope::Global => 0,
            PolicyScope::Tenant => 1,
            PolicyScope::Agent => 2,
        }
    }
}

/// A candidate decision produced by a single policy rule evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateDecision {
    pub decision: PolicyDecision,
    pub priority: u32,
    pub scope: PolicyScope,
    pub rule_name: String,
}

/// Result of conflict resolution across multiple candidate decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionResult {
    pub winning_decision: PolicyDecision,
    pub strategy_used: ConflictResolutionStrategy,
    pub conflict_detected: bool,
    pub candidates_evaluated: usize,
}

/// Result returned by [`AgentMeshClient::execute_with_governance`].
#[derive(Debug, Clone)]
pub struct GovernanceResult {
    pub decision: PolicyDecision,
    pub trust_score: TrustScore,
    pub audit_entry: AuditEntry,
    pub allowed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_decision_is_allowed_allow() {
        assert!(PolicyDecision::Allow.is_allowed());
    }

    #[test]
    fn test_policy_decision_is_allowed_deny() {
        assert!(!PolicyDecision::Deny("reason".to_string()).is_allowed());
    }

    #[test]
    fn test_policy_decision_is_allowed_requires_approval() {
        assert!(!PolicyDecision::RequiresApproval("reason".to_string()).is_allowed());
    }

    #[test]
    fn test_policy_decision_is_allowed_rate_limited() {
        assert!(!PolicyDecision::RateLimited {
            retry_after_secs: 10
        }
        .is_allowed());
    }

    #[test]
    fn test_policy_decision_label_allow() {
        assert_eq!(PolicyDecision::Allow.label(), "allow");
    }

    #[test]
    fn test_policy_decision_label_deny() {
        assert_eq!(PolicyDecision::Deny("x".to_string()).label(), "deny");
    }

    #[test]
    fn test_policy_decision_label_requires_approval() {
        assert_eq!(
            PolicyDecision::RequiresApproval("x".to_string()).label(),
            "requires_approval"
        );
    }

    #[test]
    fn test_policy_decision_label_rate_limited() {
        assert_eq!(
            PolicyDecision::RateLimited {
                retry_after_secs: 5
            }
            .label(),
            "rate_limited"
        );
    }

    #[test]
    fn test_trust_tier_boundary_0() {
        assert_eq!(TrustTier::from_score(0), TrustTier::Untrusted);
    }

    #[test]
    fn test_trust_tier_boundary_299() {
        assert_eq!(TrustTier::from_score(299), TrustTier::Untrusted);
    }

    #[test]
    fn test_trust_tier_boundary_300() {
        assert_eq!(TrustTier::from_score(300), TrustTier::Probationary);
    }

    #[test]
    fn test_trust_tier_boundary_499() {
        assert_eq!(TrustTier::from_score(499), TrustTier::Probationary);
    }

    #[test]
    fn test_trust_tier_boundary_500() {
        assert_eq!(TrustTier::from_score(500), TrustTier::Standard);
    }

    #[test]
    fn test_trust_tier_boundary_699() {
        assert_eq!(TrustTier::from_score(699), TrustTier::Standard);
    }

    #[test]
    fn test_trust_tier_boundary_700() {
        assert_eq!(TrustTier::from_score(700), TrustTier::Trusted);
    }

    #[test]
    fn test_trust_tier_boundary_899() {
        assert_eq!(TrustTier::from_score(899), TrustTier::Trusted);
    }

    #[test]
    fn test_trust_tier_boundary_900() {
        assert_eq!(TrustTier::from_score(900), TrustTier::VerifiedPartner);
    }

    #[test]
    fn test_trust_tier_boundary_1000() {
        assert_eq!(TrustTier::from_score(1000), TrustTier::VerifiedPartner);
    }

    #[test]
    fn test_trust_score_serialization_roundtrip() {
        let score = TrustScore {
            agent_id: "agent-1".to_string(),
            score: 750,
            tier: TrustTier::Trusted,
            interactions: 42,
        };
        let json = serde_json::to_string(&score).unwrap();
        let deserialized: TrustScore = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.agent_id, "agent-1");
        assert_eq!(deserialized.score, 750);
        assert_eq!(deserialized.tier, TrustTier::Trusted);
        assert_eq!(deserialized.interactions, 42);
    }

    #[test]
    fn test_audit_entry_serialization_roundtrip() {
        let entry = AuditEntry {
            seq: 0,
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            agent_id: "agent-1".to_string(),
            action: "data.read".to_string(),
            decision: "allow".to_string(),
            previous_hash: "".to_string(),
            hash: "abc123".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.seq, 0);
        assert_eq!(deserialized.agent_id, "agent-1");
        assert_eq!(deserialized.action, "data.read");
        assert_eq!(deserialized.decision, "allow");
        assert_eq!(deserialized.hash, "abc123");
    }

    #[test]
    fn test_policy_decision_serialization_allow() {
        let d = PolicyDecision::Allow;
        let json = serde_json::to_string(&d).unwrap();
        let back: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, PolicyDecision::Allow);
    }

    #[test]
    fn test_policy_decision_serialization_deny() {
        let d = PolicyDecision::Deny("blocked".to_string());
        let json = serde_json::to_string(&d).unwrap();
        let back: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back, PolicyDecision::Deny("blocked".to_string()));
    }

    #[test]
    fn test_policy_decision_serialization_requires_approval() {
        let d = PolicyDecision::RequiresApproval("needs review".to_string());
        let json = serde_json::to_string(&d).unwrap();
        let back: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back,
            PolicyDecision::RequiresApproval("needs review".to_string())
        );
    }

    #[test]
    fn test_policy_decision_serialization_rate_limited() {
        let d = PolicyDecision::RateLimited {
            retry_after_secs: 30,
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back,
            PolicyDecision::RateLimited {
                retry_after_secs: 30
            }
        );
    }

    #[test]
    fn test_governance_result_fields_populated() {
        let result = GovernanceResult {
            allowed: true,
            decision: PolicyDecision::Allow,
            trust_score: TrustScore {
                agent_id: "agent-1".to_string(),
                score: 500,
                tier: TrustTier::Standard,
                interactions: 0,
            },
            audit_entry: AuditEntry {
                seq: 0,
                timestamp: "2025-01-01T00:00:00Z".to_string(),
                agent_id: "agent-1".to_string(),
                action: "test".to_string(),
                decision: "allow".to_string(),
                previous_hash: "".to_string(),
                hash: "abc".to_string(),
            },
        };
        assert!(result.allowed);
        assert_eq!(result.decision, PolicyDecision::Allow);
        assert_eq!(result.trust_score.agent_id, "agent-1");
        assert_eq!(result.audit_entry.action, "test");
    }

    #[test]
    fn test_audit_filter_default_has_all_none() {
        let filter = AuditFilter::default();
        assert!(filter.agent_id.is_none());
        assert!(filter.action.is_none());
        assert!(filter.decision.is_none());
    }

    #[test]
    fn test_trust_tier_partial_eq() {
        assert_eq!(TrustTier::Standard, TrustTier::Standard);
        assert_ne!(TrustTier::Standard, TrustTier::Trusted);
        assert_eq!(TrustTier::VerifiedPartner, TrustTier::VerifiedPartner);
        assert_ne!(TrustTier::Untrusted, TrustTier::Probationary);
    }
}
