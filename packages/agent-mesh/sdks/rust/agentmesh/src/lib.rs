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
pub use types::{AuditEntry, AuditFilter, GovernanceResult, PolicyDecision, TrustScore, TrustTier};

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
}
