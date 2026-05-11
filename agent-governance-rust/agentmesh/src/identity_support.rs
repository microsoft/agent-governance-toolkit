// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extended identity primitives for parity with the broader AgentMesh SDK surface.

use crate::identity::{AgentIdentity, IdentityError, PublicIdentity, MAX_DELEGATION_DEPTH};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hex_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_agent_name_from_did(did: &str) -> Result<&str, IdentityError> {
    did.strip_prefix("did:agentmesh:")
        .filter(|name| !name.is_empty())
        .ok_or_else(|| IdentityError::InvalidInput {
            field: "did",
            message: format!("expected did:agentmesh:<name>, got '{did}'"),
        })
}

fn capabilities_contain(parent_caps: &[String], cap: &str) -> bool {
    parent_caps.iter().any(|parent_cap| {
        parent_cap == "*"
            || parent_cap == cap
            || parent_cap
                .strip_suffix(":*")
                .map(|prefix| cap.starts_with(&format!("{prefix}:")))
                .unwrap_or(false)
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentDID(String);

impl AgentDID {
    pub fn new(agent_name: &str) -> Result<Self, IdentityError> {
        if agent_name.trim().is_empty() {
            return Err(IdentityError::InvalidInput {
                field: "agent_name",
                message: "must not be empty".to_string(),
            });
        }
        Ok(Self(format!("did:agentmesh:{agent_name}")))
    }

    pub fn parse(did: &str) -> Result<Self, IdentityError> {
        parse_agent_name_from_did(did)?;
        Ok(Self(did.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn agent_name(&self) -> &str {
        self.0
            .strip_prefix("did:agentmesh:")
            .expect("AgentDID always uses did:agentmesh prefix")
    }
}

impl fmt::Display for AgentDID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HumanSponsor {
    pub email: String,
    pub display_name: Option<String>,
    pub verified: bool,
    pub team: Option<String>,
}

impl HumanSponsor {
    pub fn new(email: &str) -> Result<Self, IdentityError> {
        if !email.contains('@') {
            return Err(IdentityError::InvalidInput {
                field: "email",
                message: "must contain '@'".to_string(),
            });
        }
        Ok(Self {
            email: email.to_string(),
            display_name: None,
            verified: false,
            team: None,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Active,
    Rotated,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub credential_id: String,
    pub agent_did: String,
    pub token: String,
    pub token_hash: String,
    pub capabilities: Vec<String>,
    pub resources: Vec<String>,
    pub issued_at_secs: u64,
    pub expires_at_secs: u64,
    pub ttl_seconds: u64,
    pub status: CredentialStatus,
    pub revoked_at_secs: Option<u64>,
    pub revocation_reason: Option<String>,
    pub previous_credential_id: Option<String>,
    pub rotation_count: u32,
    pub issued_for: Option<String>,
    pub client_ip: Option<String>,
}

impl Credential {
    pub fn issue(
        agent_did: &str,
        capabilities: Vec<String>,
        resources: Vec<String>,
        ttl_seconds: u64,
        issued_for: Option<String>,
    ) -> Self {
        let issued_at_secs = unix_secs_now();
        let expires_at_secs = issued_at_secs + ttl_seconds.max(1);
        let signing_key = SigningKey::generate(&mut OsRng);
        let token = URL_SAFE_NO_PAD.encode(signing_key.to_bytes());
        Self {
            credential_id: format!("cred_{:016x}", rand::random::<u64>()),
            agent_did: agent_did.to_string(),
            token_hash: hex_sha256(&token),
            token,
            capabilities,
            resources,
            issued_at_secs,
            expires_at_secs,
            ttl_seconds: ttl_seconds.max(1),
            status: CredentialStatus::Active,
            revoked_at_secs: None,
            revocation_reason: None,
            previous_credential_id: None,
            rotation_count: 0,
            issued_for,
            client_ip: None,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.status == CredentialStatus::Active && unix_secs_now() < self.expires_at_secs
    }

    pub fn is_expiring_soon(&self, threshold_seconds: u64) -> bool {
        self.expires_at_secs.saturating_sub(unix_secs_now()) <= threshold_seconds
    }

    pub fn verify_token(&self, token: &str) -> bool {
        self.token_hash == hex_sha256(token)
    }

    pub fn revoke(&mut self, reason: &str) {
        self.status = CredentialStatus::Revoked;
        self.revoked_at_secs = Some(unix_secs_now());
        self.revocation_reason = Some(reason.to_string());
    }

    pub fn rotate(&mut self) -> Credential {
        self.status = CredentialStatus::Rotated;
        let mut next = Credential::issue(
            &self.agent_did,
            self.capabilities.clone(),
            self.resources.clone(),
            self.ttl_seconds,
            self.issued_for.clone(),
        );
        next.previous_credential_id = Some(self.credential_id.clone());
        next.rotation_count = self.rotation_count + 1;
        next
    }

    pub fn has_capability(&self, capability: &str) -> bool {
        capabilities_contain(&self.capabilities, capability)
    }

    pub fn can_access_resource(&self, resource: &str) -> bool {
        self.resources.is_empty()
            || self
                .resources
                .iter()
                .any(|entry| entry == "*" || entry == resource)
    }

    pub fn bearer_token(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

pub struct CredentialManager {
    default_ttl: u64,
    credentials: Mutex<HashMap<String, Credential>>,
    by_agent: Mutex<HashMap<String, Vec<String>>>,
}

impl CredentialManager {
    pub fn new(default_ttl: u64) -> Self {
        Self {
            default_ttl: default_ttl.max(1),
            credentials: Mutex::new(HashMap::new()),
            by_agent: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(
        &self,
        agent_did: &str,
        capabilities: Vec<String>,
        resources: Vec<String>,
        issued_for: Option<String>,
    ) -> Credential {
        let credential = Credential::issue(
            agent_did,
            capabilities,
            resources,
            self.default_ttl,
            issued_for,
        );
        self.credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(credential.credential_id.clone(), credential.clone());
        self.by_agent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(agent_did.to_string())
            .or_default()
            .push(credential.credential_id.clone());
        credential
    }

    pub fn validate(&self, credential_id: &str, token: &str) -> bool {
        self.credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(credential_id)
            .map(|credential| credential.is_valid() && credential.verify_token(token))
            .unwrap_or(false)
    }

    pub fn revoke(&self, credential_id: &str, reason: &str) -> bool {
        if let Some(credential) = self
            .credentials
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(credential_id)
        {
            credential.revoke(reason);
            return true;
        }
        false
    }

    pub fn rotate(&self, credential_id: &str) -> Option<Credential> {
        let mut store = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        let current = store.get_mut(credential_id)?;
        let rotated = current.rotate();
        store.insert(rotated.credential_id.clone(), rotated.clone());
        self.by_agent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(rotated.agent_did.clone())
            .or_default()
            .push(rotated.credential_id.clone());
        Some(rotated)
    }

    pub fn active_for_agent(&self, agent_did: &str) -> Vec<Credential> {
        let store = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        let ids = self.by_agent.lock().unwrap_or_else(|e| e.into_inner());
        ids.get(agent_did)
            .into_iter()
            .flat_map(|entries| entries.iter())
            .filter_map(|id| store.get(id))
            .filter(|credential| credential.is_valid())
            .cloned()
            .collect()
    }
}

impl Default for CredentialManager {
    fn default() -> Self {
        Self::new(900)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserContext {
    pub user_id: String,
    pub user_email: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub issued_at_secs: u64,
    pub expires_at_secs: Option<u64>,
    pub metadata: HashMap<String, String>,
}

impl UserContext {
    pub fn create(
        user_id: &str,
        user_email: Option<String>,
        roles: Vec<String>,
        permissions: Vec<String>,
        ttl_seconds: u64,
    ) -> Self {
        let issued_at_secs = unix_secs_now();
        Self {
            user_id: user_id.to_string(),
            user_email,
            roles,
            permissions,
            issued_at_secs,
            expires_at_secs: Some(issued_at_secs + ttl_seconds.max(1)),
            metadata: HashMap::new(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.expires_at_secs
            .map(|expires_at| unix_secs_now() < expires_at)
            .unwrap_or(true)
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions
            .iter()
            .any(|entry| entry == "*" || entry == permission)
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|entry| entry == role)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLink {
    pub link_id: String,
    pub depth: u32,
    pub parent_did: String,
    pub child_did: String,
    pub parent_capabilities: Vec<String>,
    pub delegated_capabilities: Vec<String>,
    pub created_at_secs: u64,
    pub expires_at_secs: Option<u64>,
    pub user_context: Option<UserContext>,
    // Compatibility marker only; not cryptographically validated by ScopeChain.
    pub parent_signature: String,
    pub link_hash: String,
    pub previous_link_hash: Option<String>,
}

impl DelegationLink {
    pub fn new(
        depth: u32,
        parent_did: &str,
        child_did: &str,
        parent_capabilities: Vec<String>,
        delegated_capabilities: Vec<String>,
        previous_link_hash: Option<String>,
    ) -> Result<Self, IdentityError> {
        if depth > MAX_DELEGATION_DEPTH {
            return Err(IdentityError::DelegationDepthExceeded {
                current: depth,
                max: MAX_DELEGATION_DEPTH,
            });
        }
        let created_at_secs = unix_secs_now();
        let signable = format!(
            "{parent_did}:{child_did}:{}",
            delegated_capabilities.join(",")
        );
        let mut link = Self {
            link_id: format!("link_{:016x}", rand::random::<u64>()),
            depth,
            parent_did: parent_did.to_string(),
            child_did: child_did.to_string(),
            parent_capabilities,
            delegated_capabilities,
            created_at_secs,
            expires_at_secs: None,
            user_context: None,
            // Compatibility marker only (deterministic digest, not a digital signature).
            parent_signature: hex_sha256(&signable),
            link_hash: String::new(),
            previous_link_hash,
        };
        link.link_hash = link.compute_hash();
        Ok(link)
    }

    pub fn verify_capability_narrowing(&self) -> bool {
        self.delegated_capabilities
            .iter()
            .all(|capability| capabilities_contain(&self.parent_capabilities, capability))
    }

    pub fn compute_hash(&self) -> String {
        hex_sha256(&format!(
            "{}|{}|{}|{}|{}|{}",
            self.link_id,
            self.depth,
            self.parent_did,
            self.child_did,
            self.delegated_capabilities.join(","),
            self.previous_link_hash.clone().unwrap_or_default()
        ))
    }

    pub fn is_valid(&self) -> bool {
        self.verify_capability_narrowing()
            && self
                .expires_at_secs
                .map(|expires_at| unix_secs_now() < expires_at)
                .unwrap_or(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeChain {
    pub chain_id: String,
    pub max_depth: u32,
    pub root_sponsor_email: String,
    pub root_sponsor_verified: bool,
    pub root_capabilities: Vec<String>,
    pub links: Vec<DelegationLink>,
    pub leaf_did: String,
    pub leaf_capabilities: Vec<String>,
    pub created_at_secs: u64,
    pub total_depth: u32,
    pub chain_hash: String,
}

impl ScopeChain {
    pub fn new(
        root_sponsor_email: &str,
        root_capabilities: Vec<String>,
        leaf_did: &str,
    ) -> Result<Self, IdentityError> {
        if !root_sponsor_email.contains('@') {
            return Err(IdentityError::InvalidInput {
                field: "root_sponsor_email",
                message: "must contain '@'".to_string(),
            });
        }
        Ok(Self {
            chain_id: format!("chain_{:016x}", rand::random::<u64>()),
            max_depth: MAX_DELEGATION_DEPTH,
            root_sponsor_email: root_sponsor_email.to_string(),
            root_sponsor_verified: false,
            root_capabilities: root_capabilities.clone(),
            links: Vec::new(),
            leaf_did: leaf_did.to_string(),
            leaf_capabilities: root_capabilities,
            created_at_secs: unix_secs_now(),
            total_depth: 0,
            chain_hash: String::new(),
        })
    }

    pub fn get_depth(&self) -> usize {
        self.links.len()
    }

    pub fn add_link(&mut self, link: DelegationLink) -> Result<(), IdentityError> {
        let new_depth = self.links.len() as u32 + 1;
        if new_depth > self.max_depth {
            return Err(IdentityError::DelegationDepthExceeded {
                current: new_depth,
                max: self.max_depth,
            });
        }
        if !link.is_valid() {
            return Err(IdentityError::InvalidInput {
                field: "link",
                message: "delegation link is not valid".to_string(),
            });
        }
        if let Some(last) = self.links.last() {
            if link.parent_did != last.child_did {
                return Err(IdentityError::InvalidInput {
                    field: "link.parent_did",
                    message: "delegation link does not connect to previous child".to_string(),
                });
            }
            if link.previous_link_hash.as_deref() != Some(last.link_hash.as_str()) {
                return Err(IdentityError::InvalidInput {
                    field: "link.previous_link_hash",
                    message: "delegation link hash chain does not line up".to_string(),
                });
            }
        }
        self.leaf_did = link.child_did.clone();
        self.leaf_capabilities = link.delegated_capabilities.clone();
        self.links.push(link);
        self.total_depth = self.links.len() as u32;
        self.chain_hash = self.compute_hash();
        Ok(())
    }

    pub fn compute_hash(&self) -> String {
        let chain = self
            .links
            .iter()
            .map(|link| link.link_hash.clone())
            .collect::<Vec<_>>()
            .join("|");
        hex_sha256(&format!(
            "{}|{}|{}|{}",
            self.chain_id, self.root_sponsor_email, self.leaf_did, chain
        ))
    }

    pub fn is_valid(&self) -> bool {
        let mut previous_hash: Option<&str> = None;
        for (index, link) in self.links.iter().enumerate() {
            if !link.is_valid() || link.depth != index as u32 {
                return false;
            }
            if link.previous_link_hash.as_deref() != previous_hash {
                return false;
            }
            previous_hash = Some(link.link_hash.as_str());
        }
        self.chain_hash == self.compute_hash()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl RiskSeverity {
    fn weight(self) -> u32 {
        match self {
            RiskSeverity::Critical => 5,
            RiskSeverity::High => 4,
            RiskSeverity::Medium => 3,
            RiskSeverity::Low => 2,
            RiskSeverity::Info => 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSignal {
    pub signal_type: String,
    pub severity: RiskSeverity,
    pub value: f64,
    pub timestamp_secs: u64,
    pub source: Option<String>,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Minimal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub agent_did: String,
    pub total_score: u32,
    pub risk_level: RiskLevel,
    pub identity_score: u32,
    pub behavior_score: u32,
    pub network_score: u32,
    pub compliance_score: u32,
    pub active_signals: u32,
    pub critical_signals: u32,
    pub calculated_at_secs: u64,
    pub next_update_at_secs: u64,
}

impl RiskScore {
    pub fn new(agent_did: &str) -> Self {
        let now = unix_secs_now();
        Self {
            agent_did: agent_did.to_string(),
            total_score: 500,
            risk_level: RiskLevel::Medium,
            identity_score: 50,
            behavior_score: 50,
            network_score: 50,
            compliance_score: 50,
            active_signals: 0,
            critical_signals: 0,
            calculated_at_secs: now,
            next_update_at_secs: now + 30,
        }
    }

    pub fn get_risk_level(score: u32) -> RiskLevel {
        match score {
            900..=1000 => RiskLevel::Minimal,
            700..=899 => RiskLevel::Low,
            450..=699 => RiskLevel::Medium,
            250..=449 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    pub fn update(
        &mut self,
        identity: u32,
        behavior: u32,
        network: u32,
        compliance: u32,
        active_signals: u32,
        critical_signals: u32,
    ) {
        self.identity_score = identity.min(100);
        self.behavior_score = behavior.min(100);
        self.network_score = network.min(100);
        self.compliance_score = compliance.min(100);
        self.total_score = self.identity_score * 2
            + self.behavior_score * 3
            + self.network_score * 2
            + self.compliance_score * 3;
        self.risk_level = Self::get_risk_level(self.total_score);
        self.active_signals = active_signals;
        self.critical_signals = critical_signals;
        self.calculated_at_secs = unix_secs_now();
        self.next_update_at_secs = self.calculated_at_secs + 30;
    }
}

pub struct RiskScorer {
    scores: Mutex<HashMap<String, RiskScore>>,
    signals: Mutex<HashMap<String, Vec<RiskSignal>>>,
}

impl RiskScorer {
    pub fn new() -> Self {
        Self {
            scores: Mutex::new(HashMap::new()),
            signals: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_score(&self, agent_did: &str) -> RiskScore {
        let mut scores = self.scores.lock().unwrap_or_else(|e| e.into_inner());
        scores
            .entry(agent_did.to_string())
            .or_insert_with(|| RiskScore::new(agent_did))
            .clone()
    }

    pub fn add_signal(&self, agent_did: &str, signal: RiskSignal) {
        self.signals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(agent_did.to_string())
            .or_default()
            .push(signal);
        self.recalculate(agent_did);
    }

    pub fn recalculate(&self, agent_did: &str) -> RiskScore {
        let recent_cutoff = unix_secs_now().saturating_sub(24 * 3600);
        let signals = self
            .signals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(agent_did)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|signal| signal.timestamp_secs >= recent_cutoff)
            .collect::<Vec<_>>();
        let active_signals = signals.len() as u32;
        let critical_signals = signals
            .iter()
            .filter(|signal| signal.severity == RiskSeverity::Critical)
            .count() as u32;

        let component_score = |prefix: &str, baseline: u32| -> u32 {
            let deduction = signals
                .iter()
                .filter(|signal| signal.signal_type.starts_with(prefix))
                .map(|signal| (signal.value * signal.severity.weight() as f64 * 10.0) as u32)
                .sum::<u32>();
            baseline.saturating_sub(deduction).min(100)
        };

        let mut score = self.get_score(agent_did);
        score.update(
            component_score("identity.", 80),
            component_score("behavior.", 70),
            component_score("network.", 75),
            component_score("compliance.", 85),
            active_signals,
            critical_signals,
        );
        self.scores
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(agent_did.to_string(), score.clone());
        score
    }

    pub fn get_high_risk_agents(&self, threshold: u32) -> Vec<RiskScore> {
        self.scores
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|score| score.total_score < threshold)
            .cloned()
            .collect()
    }
}

impl Default for RiskScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SvidType {
    X509,
    Jwt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SVID {
    pub spiffe_id: String,
    pub svid_type: SvidType,
    pub certificate_chain: Option<Vec<String>>,
    pub private_key_type: Option<String>,
    pub jwt_token: Option<String>,
    pub trust_domain: String,
    pub issued_at_secs: u64,
    pub expires_at_secs: u64,
    pub agent_did: String,
}

impl SVID {
    pub fn parse_spiffe_id(spiffe_id: &str) -> Result<(String, String), IdentityError> {
        let without_prefix =
            spiffe_id
                .strip_prefix("spiffe://")
                .ok_or_else(|| IdentityError::InvalidInput {
                    field: "spiffe_id",
                    message: format!("expected spiffe://trust-domain/path, got '{spiffe_id}'"),
                })?;
        let mut parts = without_prefix.splitn(2, '/');
        let trust_domain = parts.next().unwrap_or_default();
        if trust_domain.is_empty() {
            return Err(IdentityError::InvalidInput {
                field: "spiffe_id",
                message: "missing trust domain".to_string(),
            });
        }
        let path = format!("/{}", parts.next().unwrap_or_default());
        Ok((trust_domain.to_string(), path))
    }

    pub fn is_valid(&self) -> bool {
        let now = unix_secs_now();
        self.issued_at_secs <= now && now < self.expires_at_secs
    }

    pub fn time_remaining(&self) -> Duration {
        Duration::from_secs(self.expires_at_secs.saturating_sub(unix_secs_now()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SPIFFEIdentity {
    pub agent_did: String,
    pub agent_name: String,
    pub spiffe_id: String,
    pub trust_domain: String,
    pub workload_path: String,
    pub current_svid: Option<SVID>,
    pub created_at_secs: u64,
}

impl SPIFFEIdentity {
    pub fn create(
        agent_did: &str,
        agent_name: &str,
        trust_domain: &str,
        organization: Option<&str>,
    ) -> Self {
        let org_part = organization
            .map(|org| format!("/{org}"))
            .unwrap_or_default();
        let workload_path = format!("/agentmesh{org_part}/{agent_name}");
        let spiffe_id = format!("spiffe://{trust_domain}{workload_path}");
        Self {
            agent_did: agent_did.to_string(),
            agent_name: agent_name.to_string(),
            spiffe_id,
            trust_domain: trust_domain.to_string(),
            workload_path,
            current_svid: None,
            created_at_secs: unix_secs_now(),
        }
    }

    pub fn issue_svid(&mut self, ttl_hours: u64, svid_type: SvidType) -> SVID {
        let issued_at_secs = unix_secs_now();
        let svid = SVID {
            spiffe_id: self.spiffe_id.clone(),
            svid_type,
            certificate_chain: None,
            private_key_type: None,
            jwt_token: None,
            trust_domain: self.trust_domain.clone(),
            issued_at_secs,
            expires_at_secs: issued_at_secs + ttl_hours.max(1) * 3600,
            agent_did: self.agent_did.clone(),
        };
        self.current_svid = Some(svid.clone());
        svid
    }

    pub fn get_valid_svid(&self) -> Option<&SVID> {
        self.current_svid.as_ref().filter(|svid| svid.is_valid())
    }

    pub fn needs_rotation(&self, threshold_minutes: u64) -> bool {
        self.current_svid
            .as_ref()
            .map(|svid| svid.time_remaining() < Duration::from_secs(threshold_minutes * 60))
            .unwrap_or(true)
    }
}

pub struct SPIFFERegistry {
    trust_domain: String,
    identities: Mutex<HashMap<String, SPIFFEIdentity>>,
}

impl SPIFFERegistry {
    pub fn new(trust_domain: &str) -> Self {
        Self {
            trust_domain: trust_domain.to_string(),
            identities: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(
        &self,
        agent_did: &str,
        agent_name: &str,
        organization: Option<&str>,
    ) -> SPIFFEIdentity {
        let mut identities = self.identities.lock().unwrap_or_else(|e| e.into_inner());
        identities
            .entry(agent_did.to_string())
            .or_insert_with(|| {
                SPIFFEIdentity::create(agent_did, agent_name, &self.trust_domain, organization)
            })
            .clone()
    }

    pub fn validate_svid(&self, svid: &SVID) -> bool {
        svid.is_valid()
            && svid.trust_domain == self.trust_domain
            && self
                .identities
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&svid.agent_did)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceRule {
    pub namespace_prefix: String,
    pub required_capability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentNamespace {
    pub namespace: String,
    pub owner_did: String,
    pub allowed_patterns: Vec<String>,
}

pub struct NamespaceManager {
    rules: Mutex<Vec<NamespaceRule>>,
}

impl NamespaceManager {
    pub fn new() -> Self {
        Self {
            rules: Mutex::new(Vec::new()),
        }
    }

    pub fn add_rule(&self, rule: NamespaceRule) {
        self.rules
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(rule);
    }

    pub fn is_allowed(&self, namespace: &str, capabilities: &[String]) -> bool {
        let rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        rules.iter().all(|rule| {
            !namespace.starts_with(&rule.namespace_prefix)
                || capabilities_contain(capabilities, &rule.required_capability)
        })
    }
}

impl Default for NamespaceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub subject: String,
    pub reason: String,
    pub revoked_at_secs: u64,
}

pub struct RevocationList {
    entries: Mutex<HashMap<String, RevocationEntry>>,
}

impl RevocationList {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn revoke(&self, subject: &str, reason: &str) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                subject.to_string(),
                RevocationEntry {
                    subject: subject.to_string(),
                    reason: reason.to_string(),
                    revoked_at_secs: unix_secs_now(),
                },
            );
    }

    pub fn is_revoked(&self, subject: &str) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(subject)
    }
}

impl Default for RevocationList {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotatedKeyRecord {
    pub did: String,
    pub previous_public_key: Vec<u8>,
    pub rotated_at_secs: u64,
}

pub struct KeyRotationManager {
    history: Mutex<Vec<RotatedKeyRecord>>,
}

impl KeyRotationManager {
    pub fn new() -> Self {
        Self {
            history: Mutex::new(Vec::new()),
        }
    }

    pub fn rotate(&self, identity: &AgentIdentity) -> AgentIdentity {
        self.history
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(RotatedKeyRecord {
                did: identity.did.clone(),
                previous_public_key: identity.public_key.to_bytes().to_vec(),
                rotated_at_secs: unix_secs_now(),
            });
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        AgentIdentity {
            did: identity.did.clone(),
            public_key,
            capabilities: identity.capabilities.clone(),
            parent_did: identity.parent_did.clone(),
            delegation_depth: identity.delegation_depth,
            signing_key,
        }
    }

    pub fn history_for(&self, did: &str) -> Vec<RotatedKeyRecord> {
        self.history
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|entry| entry.did == did)
            .cloned()
            .collect()
    }
}

impl Default for KeyRotationManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn to_jwk(identity: &AgentIdentity, include_private: bool) -> Value {
    let mut jwk = Map::new();
    jwk.insert("kty".to_string(), Value::String("OKP".to_string()));
    jwk.insert("crv".to_string(), Value::String("Ed25519".to_string()));
    jwk.insert(
        "x".to_string(),
        Value::String(URL_SAFE_NO_PAD.encode(identity.public_key.to_bytes())),
    );
    jwk.insert("kid".to_string(), Value::String(identity.did.clone()));
    jwk.insert(
        "capabilities".to_string(),
        Value::Array(
            identity
                .capabilities
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    if include_private {
        jwk.insert(
            "d".to_string(),
            Value::String(URL_SAFE_NO_PAD.encode(identity.signing_key.to_bytes())),
        );
    }
    Value::Object(jwk)
}

pub fn from_jwk(jwk: &Value) -> Result<AgentIdentity, IdentityError> {
    let object = jwk.as_object().ok_or_else(|| IdentityError::InvalidInput {
        field: "jwk",
        message: "expected JSON object".to_string(),
    })?;
    let did =
        object
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| IdentityError::InvalidInput {
                field: "jwk.kid",
                message: "missing key id".to_string(),
            })?;
    let private_key = object
        .get("d")
        .and_then(Value::as_str)
        .ok_or(IdentityError::MissingPrivateKey)?;
    let private_key_bytes = URL_SAFE_NO_PAD
        .decode(private_key)
        .map_err(|err| IdentityError::Base64(err.to_string()))?;
    let private_key_bytes: [u8; 32] =
        private_key_bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidInput {
                field: "jwk.d",
                message: "expected 32-byte Ed25519 secret".to_string(),
            })?;
    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let capabilities = object
        .get("capabilities")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(AgentIdentity {
        did: did.to_string(),
        public_key: signing_key.verifying_key(),
        capabilities,
        parent_did: None,
        delegation_depth: 0,
        signing_key,
    })
}

pub fn to_jwks(identity: &AgentIdentity, include_private: bool) -> Value {
    Value::Object(
        [(
            "keys".to_string(),
            Value::Array(vec![to_jwk(identity, include_private)]),
        )]
        .into_iter()
        .collect(),
    )
}

pub fn from_jwks(jwks: &Value, kid: Option<&str>) -> Result<AgentIdentity, IdentityError> {
    let keys =
        jwks.get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| IdentityError::InvalidInput {
                field: "jwks.keys",
                message: "missing keys array".to_string(),
            })?;
    let selected = if let Some(target_kid) = kid {
        keys.iter()
            .find(|value| value.get("kid").and_then(Value::as_str) == Some(target_kid))
            .ok_or_else(|| IdentityError::InvalidInput {
                field: "jwks.keys",
                message: format!("no key with kid '{target_kid}'"),
            })?
    } else {
        keys.first().ok_or_else(|| IdentityError::InvalidInput {
            field: "jwks.keys",
            message: "keys array is empty".to_string(),
        })?
    };
    from_jwk(selected)
}

impl AgentIdentity {
    pub fn to_jwk(&self, include_private: bool) -> Value {
        to_jwk(self, include_private)
    }

    pub fn from_jwk(jwk: &Value) -> Result<Self, IdentityError> {
        from_jwk(jwk)
    }

    pub fn to_jwks(&self, include_private: bool) -> Value {
        to_jwks(self, include_private)
    }

    pub fn from_jwks(jwks: &Value, kid: Option<&str>) -> Result<Self, IdentityError> {
        from_jwks(jwks, kid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MTLSConfig {
    pub require_client_certificate: bool,
    pub allowed_trust_domains: Vec<String>,
    pub expected_agent_did: Option<String>,
}

#[derive(Debug, Default)]
pub struct MTLSIdentityVerifier;

impl MTLSIdentityVerifier {
    pub fn verify(
        &self,
        config: &MTLSConfig,
        spiffe_identity: &SPIFFEIdentity,
        svid: &SVID,
    ) -> bool {
        (!config.require_client_certificate || svid.svid_type == SvidType::X509)
            && config
                .allowed_trust_domains
                .iter()
                .any(|domain| domain == &spiffe_identity.trust_domain)
            && config
                .expected_agent_did
                .as_ref()
                .map(|did| did == &spiffe_identity.agent_did)
                .unwrap_or(true)
            && svid.agent_did == spiffe_identity.agent_did
            && svid.spiffe_id == spiffe_identity.spiffe_id
            && svid.is_valid()
    }
}

pub trait KeyStore: Send + Sync {
    fn store(&self, identity: &AgentIdentity) -> Result<(), IdentityError>;
    fn get(&self, did: &str) -> Result<Option<PublicIdentity>, IdentityError>;
    fn remove(&self, did: &str) -> Result<(), IdentityError>;
    fn list(&self) -> Result<Vec<String>, IdentityError>;
}

#[derive(Default)]
pub struct SoftwareKeyStore {
    identities: Mutex<HashMap<String, PublicIdentity>>,
}

impl SoftwareKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for SoftwareKeyStore {
    fn store(&self, identity: &AgentIdentity) -> Result<(), IdentityError> {
        self.identities
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                identity.did.clone(),
                PublicIdentity {
                    did: identity.did.clone(),
                    public_key: identity.public_key.to_bytes().to_vec(),
                    capabilities: identity.capabilities.clone(),
                },
            );
        Ok(())
    }

    fn get(&self, did: &str) -> Result<Option<PublicIdentity>, IdentityError> {
        Ok(self
            .identities
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(did)
            .cloned())
    }

    fn remove(&self, did: &str) -> Result<(), IdentityError> {
        self.identities
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(did);
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>, IdentityError> {
        Ok(self
            .identities
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect())
    }
}

pub struct PKCS11KeyStore {
    label: String,
    inner: SoftwareKeyStore,
}

impl PKCS11KeyStore {
    pub fn new(label: &str) -> Self {
        Self {
            label: label.to_string(),
            inner: SoftwareKeyStore::new(),
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }
}

impl KeyStore for PKCS11KeyStore {
    fn store(&self, identity: &AgentIdentity) -> Result<(), IdentityError> {
        self.inner.store(identity)
    }

    fn get(&self, did: &str) -> Result<Option<PublicIdentity>, IdentityError> {
        self.inner.get(did)
    }

    fn remove(&self, did: &str) -> Result<(), IdentityError> {
        self.inner.remove(did)
    }

    fn list(&self) -> Result<Vec<String>, IdentityError> {
        self.inner.list()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_did_roundtrip() {
        let did = AgentDID::new("analyst").unwrap();
        assert_eq!(did.to_string(), "did:agentmesh:analyst");
        assert_eq!(
            AgentDID::parse(did.as_str()).unwrap().agent_name(),
            "analyst"
        );
    }

    #[test]
    fn credential_manager_issues_rotates_and_revokes() {
        let manager = CredentialManager::default();
        let credential = manager.issue(
            "did:agentmesh:test",
            vec!["data.read".into()],
            vec!["reports".into()],
            Some("integration-test".into()),
        );
        assert!(manager.validate(&credential.credential_id, &credential.token));
        let rotated = manager.rotate(&credential.credential_id).unwrap();
        assert_eq!(
            rotated.previous_credential_id.as_deref(),
            Some(credential.credential_id.as_str())
        );
        assert!(manager.revoke(&rotated.credential_id, "done"));
        assert!(!manager.validate(&rotated.credential_id, &rotated.token));
    }

    #[test]
    fn scope_chain_tracks_narrowing() {
        let mut chain = ScopeChain::new(
            "owner@example.com",
            vec!["data:*".into(), "admin".into()],
            "did:agentmesh:root",
        )
        .unwrap();
        let link = DelegationLink::new(
            0,
            "did:agentmesh:root",
            "did:agentmesh:child",
            vec!["data:*".into(), "admin".into()],
            vec!["data:read".into()],
            None,
        )
        .unwrap();
        chain.add_link(link).unwrap();
        assert_eq!(chain.leaf_did, "did:agentmesh:child");
        assert!(chain.is_valid());
    }

    #[test]
    fn risk_scorer_marks_agents_high_risk() {
        let scorer = RiskScorer::new();
        scorer.add_signal(
            "did:agentmesh:test",
            RiskSignal {
                signal_type: "compliance.violation".into(),
                severity: RiskSeverity::Critical,
                value: 1.0,
                timestamp_secs: unix_secs_now(),
                source: None,
                details: None,
            },
        );
        let score = scorer.get_score("did:agentmesh:test");
        assert!(score.total_score < 850);
        assert_eq!(scorer.get_high_risk_agents(900).len(), 1);
    }

    #[test]
    fn spiffe_identity_issues_valid_svid() {
        let mut identity =
            SPIFFEIdentity::create("did:agentmesh:test", "test", "agentmesh.local", None);
        let svid = identity.issue_svid(1, SvidType::X509);
        assert!(svid.is_valid());
        assert!(identity.get_valid_svid().is_some());
    }

    #[test]
    fn jwk_roundtrip_restores_identity() {
        let identity = AgentIdentity::generate("jwk-agent", vec!["search".into()]).unwrap();
        let jwk = identity.to_jwk(true);
        let restored = AgentIdentity::from_jwk(&jwk).unwrap();
        assert_eq!(restored.did, identity.did);
        assert_eq!(restored.capabilities, identity.capabilities);
        let payload = b"hello";
        assert!(restored.verify(payload, &restored.sign(payload)));
    }

    #[test]
    fn mtls_verifier_matches_spiffe_identity() {
        let mut spiffe =
            SPIFFEIdentity::create("did:agentmesh:test", "test", "agentmesh.local", None);
        let svid = spiffe.issue_svid(1, SvidType::X509);
        let verifier = MTLSIdentityVerifier;
        assert!(verifier.verify(
            &MTLSConfig {
                require_client_certificate: true,
                allowed_trust_domains: vec!["agentmesh.local".into()],
                expected_agent_did: Some("did:agentmesh:test".into()),
            },
            &spiffe,
            &svid
        ));
    }

    #[test]
    fn software_keystore_roundtrip() {
        let identity = AgentIdentity::generate("stored", vec!["read".into()]).unwrap();
        let store = SoftwareKeyStore::new();
        store.store(&identity).unwrap();
        let restored = store.get(&identity.did).unwrap().unwrap();
        assert_eq!(restored.did, identity.did);
        assert_eq!(store.list().unwrap(), vec![identity.did.clone()]);
    }

    #[test]
    fn key_rotation_preserves_did() {
        let identity = AgentIdentity::generate("rotate-me", vec!["read".into()]).unwrap();
        let manager = KeyRotationManager::new();
        let rotated = manager.rotate(&identity);
        assert_eq!(rotated.did, identity.did);
        assert_ne!(
            rotated.public_key.to_bytes().to_vec(),
            identity.public_key.to_bytes().to_vec()
        );
        assert_eq!(manager.history_for(&identity.did).len(), 1);
    }

    #[test]
    fn namespace_manager_requires_capability() {
        let manager = NamespaceManager::new();
        manager.add_rule(NamespaceRule {
            namespace_prefix: "finance/".into(),
            required_capability: "finance:read".into(),
        });
        assert!(manager.is_allowed("public/data", &[]));
        assert!(!manager.is_allowed("finance/reports", &["reports:read".into()]));
        assert!(manager.is_allowed("finance/reports", &["finance:read".into()]));
    }

    #[test]
    fn revocation_list_marks_subjects() {
        let list = RevocationList::new();
        list.revoke("did:agentmesh:test", "incident");
        assert!(list.is_revoked("did:agentmesh:test"));
    }
}
