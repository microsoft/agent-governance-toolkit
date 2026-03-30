// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! # AgentMesh Rust SDK
//!
//! Rust SDK for the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
//! — policy evaluation, trust scoring, hash-chain audit logging, and Ed25519 agent identity.
//!
//! ## Quick Start
//!
//! ```rust
//! use agentmesh::AgentMeshClient;
//!
//! let client = AgentMeshClient::new("my-agent")
//!     .expect("failed to create client");
//!
//! let result = client.execute_with_governance("data.read", None);
//! assert!(result.allowed);
//! ```

pub mod audit;
pub mod identity;
pub mod policy;
pub mod trust;
pub mod types;

pub use audit::AuditLogger;
pub use identity::{AgentIdentity, PublicIdentity};
pub use policy::{PolicyEngine, PolicyError};
pub use trust::{TrustConfig, TrustManager};
pub use types::{
    AuditEntry, AuditFilter, CandidateDecision, ConflictResolutionStrategy, GovernanceResult,
    PolicyDecision, PolicyScope, ResolutionResult, TrustScore, TrustTier,
};

use std::collections::HashMap;

/// Unified governance client combining identity, policy, trust, and audit.
///
/// This is the primary entry point for most users.
pub struct AgentMeshClient {
    pub identity: AgentIdentity,
    pub trust: TrustManager,
    pub policy: PolicyEngine,
    pub audit: AuditLogger,
}

/// Builder options for [`AgentMeshClient`].
pub struct ClientOptions {
    pub capabilities: Vec<String>,
    pub trust_config: Option<TrustConfig>,
    pub policy_yaml: Option<String>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            capabilities: Vec::new(),
            trust_config: None,
            policy_yaml: None,
        }
    }
}

impl AgentMeshClient {
    /// Create a new client with default configuration.
    pub fn new(agent_id: &str) -> Result<Self, ClientError> {
        Self::with_options(agent_id, ClientOptions::default())
    }

    /// Create a new client with custom options.
    pub fn with_options(agent_id: &str, opts: ClientOptions) -> Result<Self, ClientError> {
        let identity = AgentIdentity::generate(agent_id, opts.capabilities)
            .map_err(ClientError::Identity)?;

        let trust_config = opts.trust_config.unwrap_or_default();
        let trust = TrustManager::new(trust_config);

        let policy = PolicyEngine::new();
        if let Some(yaml) = &opts.policy_yaml {
            policy.load_from_yaml(yaml).map_err(ClientError::Policy)?;
        }

        Ok(Self {
            identity,
            trust,
            policy,
            audit: AuditLogger::new(),
        })
    }

    /// Run an action through the full governance pipeline:
    /// policy → audit → trust update.
    pub fn execute_with_governance(
        &self,
        action: &str,
        context: Option<&HashMap<String, serde_yaml::Value>>,
    ) -> GovernanceResult {
        let decision = self.policy.evaluate(action, context);
        let audit_entry = self.audit.log(&self.identity.did, action, decision.label());
        let trust_score = self.trust.get_trust_score(&self.identity.did);

        match &decision {
            PolicyDecision::Allow => self.trust.record_success(&self.identity.did),
            PolicyDecision::Deny(_) => self.trust.record_failure(&self.identity.did),
            _ => {}
        }

        GovernanceResult {
            allowed: decision.is_allowed(),
            decision,
            trust_score,
            audit_entry,
        }
    }
}

/// Errors returned by [`AgentMeshClient`] construction.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("identity error: {0}")]
    Identity(identity::IdentityError),
    #[error("policy error: {0}")]
    Policy(policy::PolicyError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_default_allows_everything() {
        let client = AgentMeshClient::new("test-agent").unwrap();
        let result = client.execute_with_governance("anything", None);
        assert!(result.allowed);
        assert_eq!(result.decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_client_with_policy() {
        let yaml = r#"
version: "1.0"
agent: test
policies:
  - name: gate
    type: capability
    allowed_actions:
      - "data.read"
    denied_actions:
      - "shell:*"
"#;
        let opts = ClientOptions {
            policy_yaml: Some(yaml.to_string()),
            ..Default::default()
        };
        let client = AgentMeshClient::with_options("test", opts).unwrap();

        let r1 = client.execute_with_governance("data.read", None);
        assert!(r1.allowed);

        let r2 = client.execute_with_governance("shell:rm", None);
        assert!(!r2.allowed);
        assert!(matches!(r2.decision, PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_governance_updates_trust() {
        let client = AgentMeshClient::new("trust-test").unwrap();
        let did = client.identity.did.clone();

        client.execute_with_governance("action1", None); // allow → +trust
        client.execute_with_governance("action2", None); // allow → +trust
        let score = client.trust.get_trust_score(&did);
        assert!(score.score > 500);
    }

    #[test]
    fn test_governance_creates_audit_chain() {
        let client = AgentMeshClient::new("audit-test").unwrap();
        client.execute_with_governance("a", None);
        client.execute_with_governance("b", None);
        client.execute_with_governance("c", None);
        assert!(client.audit.verify());
        assert_eq!(client.audit.entries().len(), 3);
    }

    #[test]
    fn test_client_with_custom_trust_config() {
        let opts = ClientOptions {
            trust_config: Some(TrustConfig {
                initial_score: 800,
                threshold: 700,
                reward: 20,
                penalty: 100,
                persist_path: None,
            }),
            ..Default::default()
        };
        let client = AgentMeshClient::with_options("custom-trust", opts).unwrap();
        let score = client.trust.get_trust_score(&client.identity.did);
        assert_eq!(score.score, 800);
        assert_eq!(score.tier, TrustTier::Trusted);
    }

    #[test]
    fn test_client_with_capabilities() {
        let opts = ClientOptions {
            capabilities: vec!["data.read".to_string(), "data.write".to_string()],
            ..Default::default()
        };
        let client = AgentMeshClient::with_options("cap-agent", opts).unwrap();
        assert_eq!(
            client.identity.capabilities,
            vec!["data.read", "data.write"]
        );
    }

    #[test]
    fn test_client_with_invalid_yaml_returns_error() {
        let opts = ClientOptions {
            policy_yaml: Some("not: valid: yaml: {{{{".to_string()),
            ..Default::default()
        };
        let result = AgentMeshClient::with_options("bad-yaml", opts);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ClientError::Policy(_)));
    }

    #[test]
    fn test_multiple_governance_executions_build_audit_chain() {
        let client = AgentMeshClient::new("chain-agent").unwrap();
        for i in 0..5 {
            client.execute_with_governance(&format!("action.{}", i), None);
        }
        let entries = client.audit.entries();
        assert_eq!(entries.len(), 5);
        for i in 0..5 {
            assert_eq!(entries[i].seq, i as u64);
        }
        // Each entry's prev_hash links to the previous entry's hash
        for i in 1..5 {
            assert_eq!(entries[i].previous_hash, entries[i - 1].hash);
        }
        assert!(client.audit.verify());
    }

    #[test]
    fn test_governance_with_denied_action_decreases_trust() {
        let yaml = r#"
version: "1.0"
agent: test
policies:
  - name: gate
    type: capability
    denied_actions:
      - "dangerous.*"
"#;
        let opts = ClientOptions {
            policy_yaml: Some(yaml.to_string()),
            ..Default::default()
        };
        let client = AgentMeshClient::with_options("deny-trust", opts).unwrap();
        let did = client.identity.did.clone();
        let initial = client.trust.get_trust_score(&did).score;
        client.execute_with_governance("dangerous.action", None);
        let after = client.trust.get_trust_score(&did).score;
        assert!(after < initial);
    }

    #[test]
    fn test_governance_with_approval_required_action() {
        let yaml = r#"
version: "1.0"
agent: test
policies:
  - name: deploy-gate
    type: approval
    actions:
      - "deploy.*"
    min_approvals: 3
"#;
        let opts = ClientOptions {
            policy_yaml: Some(yaml.to_string()),
            ..Default::default()
        };
        let client = AgentMeshClient::with_options("approval-test", opts).unwrap();
        let result = client.execute_with_governance("deploy.prod", None);
        assert!(!result.allowed);
        assert!(matches!(
            result.decision,
            PolicyDecision::RequiresApproval(_)
        ));
    }

    #[test]
    fn test_governance_with_rate_limited_action() {
        let yaml = r#"
version: "1.0"
agent: test
policies:
  - name: rate-gate
    type: rate_limit
    actions:
      - "api.*"
    max_calls: 2
    window: "60s"
"#;
        let opts = ClientOptions {
            policy_yaml: Some(yaml.to_string()),
            ..Default::default()
        };
        let client = AgentMeshClient::with_options("rate-test", opts).unwrap();
        let r1 = client.execute_with_governance("api.call", None);
        assert!(r1.allowed);
        let r2 = client.execute_with_governance("api.call", None);
        assert!(r2.allowed);
        let r3 = client.execute_with_governance("api.call", None);
        assert!(!r3.allowed);
        assert!(matches!(r3.decision, PolicyDecision::RateLimited { .. }));
    }

    #[test]
    fn test_client_identity_did_is_correct() {
        let client = AgentMeshClient::new("my-agent-42").unwrap();
        assert_eq!(client.identity.did, "did:agentmesh:my-agent-42");
    }

    #[test]
    fn test_audit_chain_integrity_after_mixed_allow_deny() {
        let yaml = r#"
version: "1.0"
agent: test
policies:
  - name: gate
    type: capability
    allowed_actions:
      - "safe.*"
    denied_actions:
      - "bad.*"
"#;
        let opts = ClientOptions {
            policy_yaml: Some(yaml.to_string()),
            ..Default::default()
        };
        let client = AgentMeshClient::with_options("mixed-test", opts).unwrap();
        let r1 = client.execute_with_governance("safe.read", None);
        assert!(r1.allowed);
        let r2 = client.execute_with_governance("bad.delete", None);
        assert!(!r2.allowed);
        let r3 = client.execute_with_governance("safe.write", None);
        assert!(r3.allowed);

        assert!(client.audit.verify());
        assert_eq!(client.audit.entries().len(), 3);

        let entries = client.audit.entries();
        assert_eq!(entries[0].decision, "allow");
        assert_eq!(entries[1].decision, "deny");
        assert_eq!(entries[2].decision, "allow");
    }
}
