// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! YAML-based policy evaluation engine with four-way decisions:
//! allow, deny, requires-approval, and rate-limit.

use crate::types::{
    CandidateDecision, ConflictResolutionStrategy, PolicyDecision, PolicyScope, ResolutionResult,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::Instant;

/// A single rule inside a policy profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: String,
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    #[serde(default)]
    pub denied_actions: Vec<String>,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub min_approvals: u32,
    #[serde(default)]
    pub max_calls: u32,
    #[serde(default)]
    pub window: String,
    #[serde(default)]
    pub conditions: HashMap<String, serde_yaml::Value>,
    /// Rule priority — higher values are evaluated first.
    #[serde(default)]
    pub priority: u32,
    /// The scope at which this rule applies.
    #[serde(default)]
    pub scope: PolicyScope,
}

/// A loaded policy profile parsed from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyProfile {
    pub version: String,
    pub agent: String,
    pub policies: Vec<PolicyRule>,
}

/// Policy evaluation engine.
///
/// Rules are evaluated in order; first match wins.
/// When no profile is loaded, all actions are allowed.
pub struct PolicyEngine {
    profile: RwLock<Option<PolicyProfile>>,
    rate_counters: Mutex<HashMap<String, (u64, Instant)>>,
    conflict_strategy: ConflictResolutionStrategy,
}

impl PolicyEngine {
    /// Create an empty policy engine (allows everything) with default
    /// [`ConflictResolutionStrategy::PriorityFirstMatch`].
    pub fn new() -> Self {
        Self {
            profile: RwLock::new(None),
            rate_counters: Mutex::new(HashMap::new()),
            conflict_strategy: ConflictResolutionStrategy::PriorityFirstMatch,
        }
    }

    /// Create a policy engine with a specific conflict resolution strategy.
    pub fn with_strategy(strategy: ConflictResolutionStrategy) -> Self {
        Self {
            profile: RwLock::new(None),
            rate_counters: Mutex::new(HashMap::new()),
            conflict_strategy: strategy,
        }
    }

    /// Return the active conflict resolution strategy.
    pub fn strategy(&self) -> ConflictResolutionStrategy {
        self.conflict_strategy
    }

    /// Resolve conflicts among multiple candidate decisions using the
    /// configured strategy.
    ///
    /// Returns a [`ResolutionResult`] describing which decision won,
    /// whether a conflict was detected, and how many candidates were
    /// evaluated.
    pub fn resolve_conflicts(&self, candidates: &[CandidateDecision]) -> ResolutionResult {
        if candidates.is_empty() {
            return ResolutionResult {
                winning_decision: PolicyDecision::Allow,
                strategy_used: self.conflict_strategy,
                conflict_detected: false,
                candidates_evaluated: 0,
            };
        }

        if candidates.len() == 1 {
            return ResolutionResult {
                winning_decision: candidates[0].decision.clone(),
                strategy_used: self.conflict_strategy,
                conflict_detected: false,
                candidates_evaluated: 1,
            };
        }

        let has_allow = candidates.iter().any(|c| c.decision.is_allowed());
        let has_deny = candidates
            .iter()
            .any(|c| matches!(c.decision, PolicyDecision::Deny(_)));
        let conflict_detected = has_allow && has_deny;

        let mut sorted = candidates.to_vec();

        let winning = match self.conflict_strategy {
            ConflictResolutionStrategy::DenyOverrides => {
                sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
                match sorted
                    .iter()
                    .find(|c| matches!(c.decision, PolicyDecision::Deny(_)))
                {
                    Some(d) => d.clone(),
                    None => sorted[0].clone(),
                }
            }
            ConflictResolutionStrategy::AllowOverrides => {
                sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
                match sorted.iter().find(|c| c.decision.is_allowed()) {
                    Some(a) => a.clone(),
                    None => sorted[0].clone(),
                }
            }
            ConflictResolutionStrategy::PriorityFirstMatch => {
                sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
                sorted[0].clone()
            }
            ConflictResolutionStrategy::MostSpecificWins => {
                sorted.sort_by(|a, b| {
                    b.scope
                        .specificity()
                        .cmp(&a.scope.specificity())
                        .then(b.priority.cmp(&a.priority))
                });
                sorted[0].clone()
            }
        };

        ResolutionResult {
            winning_decision: winning.decision,
            strategy_used: self.conflict_strategy,
            conflict_detected,
            candidates_evaluated: candidates.len(),
        }
    }

    /// Whether a policy profile is loaded.
    pub fn is_loaded(&self) -> bool {
        self.profile.read().unwrap().is_some()
    }

    /// Load a policy profile from a YAML string.
    pub fn load_from_yaml(&self, yaml: &str) -> Result<(), PolicyError> {
        let profile: PolicyProfile =
            serde_yaml::from_str(yaml).map_err(PolicyError::InvalidYaml)?;
        *self.profile.write().unwrap() = Some(profile);
        Ok(())
    }

    /// Load a policy profile from a YAML file on disk.
    pub fn load_from_file(&self, path: &str) -> Result<(), PolicyError> {
        let yaml = std::fs::read_to_string(path).map_err(PolicyError::Io)?;
        self.load_from_yaml(&yaml)
    }

    /// Evaluate an action against the loaded policy.
    ///
    /// If no profile is loaded, returns [`PolicyDecision::Allow`].
    /// An optional `context` map is matched against rule conditions.
    pub fn evaluate(
        &self,
        action: &str,
        context: Option<&HashMap<String, serde_yaml::Value>>,
    ) -> PolicyDecision {
        let guard = self.profile.read().unwrap();
        let profile = match guard.as_ref() {
            Some(p) => p,
            None => return PolicyDecision::Allow,
        };

        for rule in &profile.policies {
            if !conditions_match(&rule.conditions, context) {
                continue;
            }

            match rule.rule_type.as_str() {
                "capability" => {
                    // Deny list takes precedence
                    for denied in &rule.denied_actions {
                        if action_matches(action, denied) {
                            return PolicyDecision::Deny(format!(
                                "Blocked by policy '{}': action '{}' is denied",
                                rule.name, action
                            ));
                        }
                    }
                    // Allow list: if the action matches an allow pattern, permit it.
                    // If the list is non-empty but no pattern matches, deny only
                    // when the action matches a deny-list prefix (scoped deny).
                    // Actions outside the rule's scope fall through to later rules.
                    if !rule.allowed_actions.is_empty() {
                        if rule.allowed_actions.iter().any(|a| action_matches(action, a)) {
                            return PolicyDecision::Allow;
                        }
                        // Only deny if action is in scope (matches a denied prefix
                        // or shares a namespace with an allowed action)
                        let in_scope = rule.denied_actions.iter().any(|d| {
                            let ns = d.trim_end_matches('*').trim_end_matches(':');
                            action.starts_with(ns)
                        }) || rule.allowed_actions.iter().any(|a| {
                            let ns = a.split('.').next().unwrap_or("");
                            action.starts_with(ns)
                        });
                        if in_scope {
                            return PolicyDecision::Deny(format!(
                                "Blocked by policy '{}': action '{}' not in allowlist",
                                rule.name, action
                            ));
                        }
                    }
                }
                "approval" => {
                    for pattern in &rule.actions {
                        if action_matches(action, pattern) {
                            return PolicyDecision::RequiresApproval(format!(
                                "Policy '{}' requires {} approval(s) for '{}'",
                                rule.name, rule.min_approvals, action
                            ));
                        }
                    }
                }
                "rate_limit" => {
                    if rule.max_calls > 0 {
                        for pattern in &rule.actions {
                            if action_matches(action, pattern) {
                                return self.check_rate_limit(
                                    &rule.name,
                                    rule.max_calls,
                                    &rule.window,
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        PolicyDecision::Allow
    }

    fn check_rate_limit(&self, name: &str, max_calls: u32, window: &str) -> PolicyDecision {
        let window_secs = parse_duration(window);
        let mut counters = self.rate_counters.lock().unwrap();
        let entry = counters
            .entry(name.to_string())
            .or_insert((0, Instant::now()));

        if entry.1.elapsed().as_secs() > window_secs {
            *entry = (1, Instant::now());
            PolicyDecision::Allow
        } else if entry.0 >= max_calls as u64 {
            let retry_after = window_secs.saturating_sub(entry.1.elapsed().as_secs());
            PolicyDecision::RateLimited {
                retry_after_secs: retry_after,
            }
        } else {
            entry.0 += 1;
            PolicyDecision::Allow
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors returned by policy operations.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid YAML: {0}")]
    InvalidYaml(serde_yaml::Error),
    #[error("I/O error: {0}")]
    Io(std::io::Error),
}

/// Glob-style pattern matching: `shell:*` matches `shell:ls`.
fn action_matches(action: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return action.starts_with(&format!("{}.", prefix));
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return action.starts_with(prefix);
    }
    action == pattern
}

fn conditions_match(
    conditions: &HashMap<String, serde_yaml::Value>,
    context: Option<&HashMap<String, serde_yaml::Value>>,
) -> bool {
    if conditions.is_empty() {
        return true;
    }
    let ctx = match context {
        Some(c) => c,
        None => return false,
    };
    for (key, expected) in conditions {
        match ctx.get(key) {
            Some(actual) if actual == expected => {}
            _ => return false,
        }
    }
    true
}

fn parse_duration(s: &str) -> u64 {
    if let Some(val) = s.strip_suffix('m') {
        val.parse::<u64>().unwrap_or(1) * 60
    } else if let Some(val) = s.strip_suffix('s') {
        val.parse::<u64>().unwrap_or(60)
    } else if let Some(val) = s.strip_suffix('h') {
        val.parse::<u64>().unwrap_or(1) * 3600
    } else {
        s.parse::<u64>().unwrap_or(60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY_YAML: &str = r#"
version: "1.0"
agent: test-agent
policies:
  - name: capability-gate
    type: capability
    allowed_actions:
      - "data.read"
      - "data.write"
    denied_actions:
      - "shell:*"
  - name: deploy-approval
    type: approval
    actions:
      - "deploy.*"
    min_approvals: 2
  - name: api-rate-limit
    type: rate_limit
    actions:
      - "api.call"
    max_calls: 3
    window: "60s"
"#;

    #[test]
    fn test_allow_listed_action() {
        let engine = PolicyEngine::new();
        engine.load_from_yaml(POLICY_YAML).unwrap();
        assert_eq!(engine.evaluate("data.read", None), PolicyDecision::Allow);
    }

    #[test]
    fn test_deny_shell() {
        let engine = PolicyEngine::new();
        engine.load_from_yaml(POLICY_YAML).unwrap();
        let decision = engine.evaluate("shell:rm", None);
        assert!(matches!(decision, PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_not_in_allowlist_in_scope() {
        let engine = PolicyEngine::new();
        engine.load_from_yaml(POLICY_YAML).unwrap();
        // "data.delete" shares the "data" namespace with allowed "data.read"/"data.write"
        let decision = engine.evaluate("data.delete", None);
        assert!(matches!(decision, PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_out_of_scope_falls_through() {
        let engine = PolicyEngine::new();
        engine.load_from_yaml(POLICY_YAML).unwrap();
        // "admin.delete" is outside the capability rule's scope, falls through to Allow
        let decision = engine.evaluate("admin.delete", None);
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_approval_required() {
        let engine = PolicyEngine::new();
        engine.load_from_yaml(POLICY_YAML).unwrap();
        let decision = engine.evaluate("deploy.production", None);
        assert!(matches!(decision, PolicyDecision::RequiresApproval(_)));
    }

    #[test]
    fn test_rate_limiting() {
        let engine = PolicyEngine::new();
        engine.load_from_yaml(POLICY_YAML).unwrap();
        // First 3 calls should be allowed
        for _ in 0..3 {
            assert_eq!(engine.evaluate("api.call", None), PolicyDecision::Allow);
        }
        // 4th call should be rate-limited
        let decision = engine.evaluate("api.call", None);
        assert!(matches!(decision, PolicyDecision::RateLimited { .. }));
    }

    #[test]
    fn test_no_profile_allows_all() {
        let engine = PolicyEngine::new();
        assert_eq!(engine.evaluate("anything", None), PolicyDecision::Allow);
    }

    #[test]
    fn test_action_matches() {
        assert!(action_matches("shell:ls", "shell:*"));
        assert!(action_matches("data.read", "data.*"));
        assert!(action_matches("deploy.staging", "deploy.*"));
        assert!(!action_matches("data.read", "shell:*"));
        assert!(action_matches("anything", "*"));
        assert!(action_matches("data.read", "data.read"));
        assert!(!action_matches("data.write", "data.read"));
    }

    #[test]
    fn test_with_strategy_constructor() {
        let engine = PolicyEngine::with_strategy(ConflictResolutionStrategy::DenyOverrides);
        assert_eq!(engine.strategy(), ConflictResolutionStrategy::DenyOverrides);
    }

    #[test]
    fn test_default_strategy_is_priority_first_match() {
        let engine = PolicyEngine::new();
        assert_eq!(
            engine.strategy(),
            ConflictResolutionStrategy::PriorityFirstMatch
        );
    }

    #[test]
    fn test_resolve_conflicts_empty() {
        let engine = PolicyEngine::new();
        let result = engine.resolve_conflicts(&[]);
        assert_eq!(result.winning_decision, PolicyDecision::Allow);
        assert!(!result.conflict_detected);
        assert_eq!(result.candidates_evaluated, 0);
    }

    #[test]
    fn test_resolve_conflicts_single() {
        let engine = PolicyEngine::new();
        let candidates = vec![CandidateDecision {
            decision: PolicyDecision::Deny("blocked".into()),
            priority: 1,
            scope: PolicyScope::Global,
            rule_name: "rule-1".into(),
        }];
        let result = engine.resolve_conflicts(&candidates);
        assert!(matches!(result.winning_decision, PolicyDecision::Deny(_)));
        assert!(!result.conflict_detected);
        assert_eq!(result.candidates_evaluated, 1);
    }

    #[test]
    fn test_resolve_conflicts_deny_overrides() {
        let engine = PolicyEngine::with_strategy(ConflictResolutionStrategy::DenyOverrides);
        let candidates = vec![
            CandidateDecision {
                decision: PolicyDecision::Allow,
                priority: 10,
                scope: PolicyScope::Global,
                rule_name: "allow-rule".into(),
            },
            CandidateDecision {
                decision: PolicyDecision::Deny("no".into()),
                priority: 5,
                scope: PolicyScope::Global,
                rule_name: "deny-rule".into(),
            },
        ];
        let result = engine.resolve_conflicts(&candidates);
        assert!(matches!(result.winning_decision, PolicyDecision::Deny(_)));
        assert!(result.conflict_detected);
    }

    #[test]
    fn test_resolve_conflicts_allow_overrides() {
        let engine = PolicyEngine::with_strategy(ConflictResolutionStrategy::AllowOverrides);
        let candidates = vec![
            CandidateDecision {
                decision: PolicyDecision::Deny("blocked".into()),
                priority: 10,
                scope: PolicyScope::Global,
                rule_name: "deny-rule".into(),
            },
            CandidateDecision {
                decision: PolicyDecision::Allow,
                priority: 5,
                scope: PolicyScope::Global,
                rule_name: "allow-rule".into(),
            },
        ];
        let result = engine.resolve_conflicts(&candidates);
        assert_eq!(result.winning_decision, PolicyDecision::Allow);
        assert!(result.conflict_detected);
    }

    #[test]
    fn test_resolve_conflicts_priority_first_match() {
        let engine = PolicyEngine::with_strategy(ConflictResolutionStrategy::PriorityFirstMatch);
        let candidates = vec![
            CandidateDecision {
                decision: PolicyDecision::Deny("low".into()),
                priority: 1,
                scope: PolicyScope::Global,
                rule_name: "low-rule".into(),
            },
            CandidateDecision {
                decision: PolicyDecision::Allow,
                priority: 10,
                scope: PolicyScope::Global,
                rule_name: "high-rule".into(),
            },
        ];
        let result = engine.resolve_conflicts(&candidates);
        assert_eq!(result.winning_decision, PolicyDecision::Allow);
        assert!(result.conflict_detected);
    }

    #[test]
    fn test_resolve_conflicts_most_specific_wins() {
        let engine = PolicyEngine::with_strategy(ConflictResolutionStrategy::MostSpecificWins);
        let candidates = vec![
            CandidateDecision {
                decision: PolicyDecision::Allow,
                priority: 100,
                scope: PolicyScope::Global,
                rule_name: "global-allow".into(),
            },
            CandidateDecision {
                decision: PolicyDecision::Deny("agent-deny".into()),
                priority: 1,
                scope: PolicyScope::Agent,
                rule_name: "agent-deny".into(),
            },
        ];
        let result = engine.resolve_conflicts(&candidates);
        assert!(matches!(result.winning_decision, PolicyDecision::Deny(_)));
        assert!(result.conflict_detected);
    }

    #[test]
    fn test_resolve_conflicts_most_specific_tiebreaker() {
        let engine = PolicyEngine::with_strategy(ConflictResolutionStrategy::MostSpecificWins);
        let candidates = vec![
            CandidateDecision {
                decision: PolicyDecision::Deny("low".into()),
                priority: 1,
                scope: PolicyScope::Tenant,
                rule_name: "tenant-low".into(),
            },
            CandidateDecision {
                decision: PolicyDecision::Allow,
                priority: 10,
                scope: PolicyScope::Tenant,
                rule_name: "tenant-high".into(),
            },
        ];
        let result = engine.resolve_conflicts(&candidates);
        assert_eq!(result.winning_decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_policy_rule_priority_and_scope_defaults() {
        let yaml = r#"
version: "1.0"
agent: test
policies:
  - name: simple-rule
    type: capability
    allowed_actions:
      - "data.read"
"#;
        let profile: PolicyProfile = serde_yaml::from_str(yaml).unwrap();
        let rule = &profile.policies[0];
        assert_eq!(rule.priority, 0);
        assert_eq!(rule.scope, PolicyScope::Global);
    }

    #[test]
    fn test_policy_rule_with_priority_and_scope() {
        let yaml = r#"
version: "1.0"
agent: test
policies:
  - name: agent-rule
    type: capability
    allowed_actions:
      - "data.read"
    priority: 10
    scope: agent
"#;
        let profile: PolicyProfile = serde_yaml::from_str(yaml).unwrap();
        let rule = &profile.policies[0];
        assert_eq!(rule.priority, 10);
        assert_eq!(rule.scope, PolicyScope::Agent);
    }

    #[test]
    fn test_no_conflict_when_all_same_decision() {
        let engine = PolicyEngine::with_strategy(ConflictResolutionStrategy::DenyOverrides);
        let candidates = vec![
            CandidateDecision {
                decision: PolicyDecision::Allow,
                priority: 5,
                scope: PolicyScope::Global,
                rule_name: "r1".into(),
            },
            CandidateDecision {
                decision: PolicyDecision::Allow,
                priority: 10,
                scope: PolicyScope::Tenant,
                rule_name: "r2".into(),
            },
        ];
        let result = engine.resolve_conflicts(&candidates);
        assert!(!result.conflict_detected);
        assert_eq!(result.winning_decision, PolicyDecision::Allow);
    }
}
