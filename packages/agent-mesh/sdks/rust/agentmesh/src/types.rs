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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolutionStrategy {
    /// Any deny decision overrides allows.
    DenyOverrides,
    /// Any allow decision overrides denies.
    AllowOverrides,
    /// The candidate with the highest priority wins.
    PriorityFirstMatch,
    /// The most specific scope wins, with priority as tiebreaker.
    MostSpecificWins,
}

impl Default for ConflictResolutionStrategy {
    fn default() -> Self {
        ConflictResolutionStrategy::PriorityFirstMatch
    }
}

/// The scope at which a policy rule applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyScope {
    /// Applies to all tenants and agents.
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

impl Default for PolicyScope {
    fn default() -> Self {
        PolicyScope::Global
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
