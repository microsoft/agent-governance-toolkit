// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trust-plane interoperability primitives layered on top of the core trust manager.

use crate::identity::{AgentIdentity, PublicIdentity};
use crate::identity_support::UserContext;
use crate::trust::TrustManager;
use crate::types::TrustTier;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn capability_matches(granted: &str, requested: &str) -> bool {
    granted == "*"
        || granted == requested
        || granted
            .strip_suffix(":*")
            .map(|prefix| requested.starts_with(&format!("{prefix}:")))
            .unwrap_or(false)
        || requested.starts_with(&format!("{granted}:"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub grant_id: String,
    pub capability: String,
    pub action: String,
    pub resource: String,
    pub qualifier: Option<String>,
    pub granted_to: String,
    pub granted_by: String,
    pub resource_ids: Vec<String>,
    pub conditions: HashMap<String, String>,
    pub granted_at_secs: u64,
    pub expires_at_secs: Option<u64>,
    pub active: bool,
    pub revoked_at_secs: Option<u64>,
}

impl CapabilityGrant {
    pub fn parse_capability(capability: &str) -> Result<(String, String, Option<String>), String> {
        let parts = capability.split(':').collect::<Vec<_>>();
        if parts.len() < 2 {
            return Err(format!("invalid capability '{capability}'"));
        }
        Ok((
            parts[0].to_string(),
            parts[1].to_string(),
            parts.get(2).map(|value| (*value).to_string()),
        ))
    }

    pub fn create(
        capability: &str,
        granted_to: &str,
        granted_by: &str,
        resource_ids: Vec<String>,
    ) -> Result<Self, String> {
        let (action, resource, qualifier) = Self::parse_capability(capability)?;
        Ok(Self {
            grant_id: format!("grant_{:012x}", rand::random::<u64>()),
            capability: capability.to_string(),
            action,
            resource,
            qualifier,
            granted_to: granted_to.to_string(),
            granted_by: granted_by.to_string(),
            resource_ids,
            conditions: HashMap::new(),
            granted_at_secs: unix_secs_now(),
            expires_at_secs: None,
            active: true,
            revoked_at_secs: None,
        })
    }

    pub fn is_valid(&self) -> bool {
        self.active
            && self
                .expires_at_secs
                .map(|expires_at| unix_secs_now() < expires_at)
                .unwrap_or(true)
    }

    pub fn matches(&self, requested: &str, resource_id: Option<&str>) -> bool {
        (self.is_valid()
            && capability_matches(&self.capability, requested)
            && self.resource_ids.is_empty())
            || (self.is_valid()
                && capability_matches(&self.capability, requested)
                && resource_id
                    .map(|resource| self.resource_ids.iter().any(|entry| entry == resource))
                    .unwrap_or(false))
    }

    pub fn revoke(&mut self) {
        self.active = false;
        self.revoked_at_secs = Some(unix_secs_now());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityScope {
    pub agent_did: String,
    pub grants: Vec<CapabilityGrant>,
    pub denied: Vec<String>,
}

impl CapabilityScope {
    pub fn new(agent_did: &str) -> Self {
        Self {
            agent_did: agent_did.to_string(),
            grants: Vec::new(),
            denied: Vec::new(),
        }
    }

    pub fn add_grant(&mut self, grant: CapabilityGrant) -> Result<(), String> {
        if grant.granted_to != self.agent_did {
            return Err("grant is for a different agent".to_string());
        }
        self.grants.push(grant);
        Ok(())
    }

    pub fn has_capability(&self, capability: &str, resource_id: Option<&str>) -> bool {
        !self
            .denied
            .iter()
            .any(|denied| capability_matches(denied, capability))
            && self
                .grants
                .iter()
                .any(|grant| grant.matches(capability, resource_id))
    }

    pub fn get_capabilities(&self) -> Vec<String> {
        let mut capabilities = self
            .grants
            .iter()
            .filter(|grant| grant.is_valid())
            .map(|grant| grant.capability.clone())
            .collect::<Vec<_>>();
        capabilities.sort();
        capabilities.dedup();
        capabilities
    }

    pub fn filter_capabilities(&self, requested: &[String]) -> Vec<String> {
        requested
            .iter()
            .filter(|capability| self.has_capability(capability, None))
            .cloned()
            .collect()
    }

    pub fn deny(&mut self, capability: &str) {
        if !self.denied.iter().any(|entry| entry == capability) {
            self.denied.push(capability.to_string());
        }
    }

    pub fn revoke_all(&mut self) -> usize {
        let mut count = 0;
        for grant in &mut self.grants {
            if grant.active {
                grant.revoke();
                count += 1;
            }
        }
        count
    }
}

pub struct CapabilityRegistry {
    scopes: Mutex<HashMap<String, CapabilityScope>>,
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        Self {
            scopes: Mutex::new(HashMap::new()),
        }
    }

    pub fn scope_for(&self, agent_did: &str) -> CapabilityScope {
        self.scopes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(agent_did.to_string())
            .or_insert_with(|| CapabilityScope::new(agent_did))
            .clone()
    }

    pub fn grant(
        &self,
        granted_to: &str,
        granted_by: &str,
        capability: &str,
        resource_ids: Vec<String>,
    ) -> Result<CapabilityGrant, String> {
        let grant = CapabilityGrant::create(capability, granted_to, granted_by, resource_ids)?;
        let mut scopes = self.scopes.lock().unwrap_or_else(|e| e.into_inner());
        scopes
            .entry(granted_to.to_string())
            .or_insert_with(|| CapabilityScope::new(granted_to))
            .add_grant(grant.clone())?;
        Ok(grant)
    }

    pub fn has_capability(
        &self,
        agent_did: &str,
        capability: &str,
        resource_id: Option<&str>,
    ) -> bool {
        self.scopes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(agent_did)
            .map(|scope| scope.has_capability(capability, resource_id))
            .unwrap_or(false)
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeChallenge {
    pub challenge_id: String,
    pub nonce: String,
    pub issued_at_secs: u64,
    pub expires_in_seconds: u64,
}

impl HandshakeChallenge {
    pub fn generate() -> Self {
        Self {
            challenge_id: format!("challenge_{:016x}", rand::random::<u64>()),
            nonce: hex(&rand::random::<[u8; 32]>()),
            issued_at_secs: unix_secs_now(),
            expires_in_seconds: 30,
        }
    }

    pub fn is_expired(&self) -> bool {
        unix_secs_now().saturating_sub(self.issued_at_secs) > self.expires_in_seconds
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub challenge_id: String,
    pub response_nonce: String,
    pub agent_did: String,
    pub capabilities: Vec<String>,
    pub trust_score: u32,
    pub signature_hex: String,
    pub public_key_hex: String,
    pub user_context: Option<UserContext>,
    pub timestamp_secs: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeTrustLevel {
    VerifiedPartner,
    Trusted,
    Standard,
    Untrusted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResult {
    pub verified: bool,
    pub peer_did: String,
    pub peer_name: Option<String>,
    pub trust_score: u32,
    pub trust_level: HandshakeTrustLevel,
    pub capabilities: Vec<String>,
    pub user_context: Option<UserContext>,
    pub handshake_started_secs: u64,
    pub handshake_completed_secs: u64,
    pub latency_ms: u64,
    pub rejection_reason: Option<String>,
}

impl HandshakeResult {
    pub fn success(
        peer_did: &str,
        trust_score: u32,
        capabilities: Vec<String>,
        started_at_secs: u64,
        user_context: Option<UserContext>,
    ) -> Self {
        let completed = unix_secs_now();
        let trust_level = match TrustTier::from_score(trust_score) {
            TrustTier::VerifiedPartner => HandshakeTrustLevel::VerifiedPartner,
            TrustTier::Trusted => HandshakeTrustLevel::Trusted,
            TrustTier::Standard => HandshakeTrustLevel::Standard,
            TrustTier::Probationary | TrustTier::Untrusted => HandshakeTrustLevel::Untrusted,
        };
        Self {
            verified: true,
            peer_did: peer_did.to_string(),
            peer_name: None,
            trust_score,
            trust_level,
            capabilities,
            user_context,
            handshake_started_secs: started_at_secs,
            handshake_completed_secs: completed,
            latency_ms: completed.saturating_sub(started_at_secs) * 1000,
            rejection_reason: None,
        }
    }

    pub fn failure(peer_did: &str, started_at_secs: u64, reason: &str) -> Self {
        let completed = unix_secs_now();
        Self {
            verified: false,
            peer_did: peer_did.to_string(),
            peer_name: None,
            trust_score: 0,
            trust_level: HandshakeTrustLevel::Untrusted,
            capabilities: Vec::new(),
            user_context: None,
            handshake_started_secs: started_at_secs,
            handshake_completed_secs: completed,
            latency_ms: completed.saturating_sub(started_at_secs) * 1000,
            rejection_reason: Some(reason.to_string()),
        }
    }
}

pub struct TrustHandshake {
    agent_did: String,
    identity: Option<AgentIdentity>,
    trust_manager: Option<Arc<TrustManager>>,
    peers: Mutex<HashMap<String, PublicIdentity>>,
    pending: Mutex<HashMap<String, HandshakeChallenge>>,
}

impl TrustHandshake {
    pub fn new(
        agent_did: &str,
        identity: Option<AgentIdentity>,
        trust_manager: Option<Arc<TrustManager>>,
    ) -> Self {
        Self {
            agent_did: agent_did.to_string(),
            identity,
            trust_manager,
            peers: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_peer(&self, identity: &AgentIdentity) {
        self.peers.lock().unwrap_or_else(|e| e.into_inner()).insert(
            identity.did.clone(),
            PublicIdentity {
                did: identity.did.clone(),
                public_key: identity.public_key.to_bytes().to_vec(),
                capabilities: identity.capabilities.clone(),
            },
        );
    }

    pub fn issue_challenge(&self, peer_did: &str) -> HandshakeChallenge {
        let challenge = HandshakeChallenge::generate();
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(peer_did.to_string(), challenge.clone());
        challenge
    }

    pub fn create_response(
        &self,
        peer_identity: &AgentIdentity,
        challenge: &HandshakeChallenge,
        trust_score: u32,
        user_context: Option<UserContext>,
    ) -> HandshakeResponse {
        let payload = format!("{}:{}", challenge.challenge_id, challenge.nonce);
        let signature = peer_identity.sign(payload.as_bytes());
        HandshakeResponse {
            challenge_id: challenge.challenge_id.clone(),
            response_nonce: challenge.nonce.clone(),
            agent_did: peer_identity.did.clone(),
            capabilities: peer_identity.capabilities.clone(),
            trust_score,
            signature_hex: hex(&signature),
            public_key_hex: hex(&peer_identity.public_key.to_bytes()),
            user_context,
            timestamp_secs: unix_secs_now(),
        }
    }

    pub fn verify_response(
        &self,
        response: &HandshakeResponse,
        required_trust_score: u32,
        required_capabilities: &[String],
    ) -> HandshakeResult {
        let started = unix_secs_now();
        let challenge = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&response.agent_did);
        let Some(challenge) = challenge else {
            return HandshakeResult::failure(&response.agent_did, started, "no pending challenge");
        };
        if challenge.is_expired()
            || challenge.challenge_id != response.challenge_id
            || challenge.nonce != response.response_nonce
        {
            return HandshakeResult::failure(
                &response.agent_did,
                started,
                "challenge mismatch or expiration",
            );
        }
        let Some(identity) = self
            .peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&response.agent_did)
            .cloned()
        else {
            return HandshakeResult::failure(&response.agent_did, started, "peer not registered");
        };
        let payload = format!("{}:{}", challenge.challenge_id, challenge.nonce);
        let signature = response
            .signature_hex
            .as_bytes()
            .chunks(2)
            .filter_map(|chunk| std::str::from_utf8(chunk).ok())
            .filter_map(|chunk| u8::from_str_radix(chunk, 16).ok())
            .collect::<Vec<_>>();
        if !identity.verify(payload.as_bytes(), &signature) {
            return HandshakeResult::failure(
                &response.agent_did,
                started,
                "signature verification failed",
            );
        }
        if response.trust_score < required_trust_score {
            return HandshakeResult::failure(
                &response.agent_did,
                started,
                "trust score below threshold",
            );
        }
        if !required_capabilities.iter().all(|required| {
            response
                .capabilities
                .iter()
                .any(|cap| capability_matches(cap, required))
        }) {
            return HandshakeResult::failure(
                &response.agent_did,
                started,
                "required capabilities missing",
            );
        }
        HandshakeResult::success(
            &response.agent_did,
            response.trust_score,
            response.capabilities.clone(),
            started,
            response.user_context.clone(),
        )
    }

    pub fn verify_registered_peer(
        &self,
        peer_did: &str,
        required_trust_score: u32,
        required_capabilities: &[String],
    ) -> HandshakeResult {
        let started = unix_secs_now();
        let Some(identity) = self
            .peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(peer_did)
            .cloned()
        else {
            return HandshakeResult::failure(peer_did, started, "peer not registered");
        };
        let trust_score = self
            .trust_manager
            .as_ref()
            .map(|manager| manager.get_trust_score(peer_did).score)
            .unwrap_or(500);
        if trust_score < required_trust_score {
            return HandshakeResult::failure(peer_did, started, "trust score below threshold");
        }
        if !required_capabilities.iter().all(|required| {
            identity
                .capabilities
                .iter()
                .any(|cap| capability_matches(cap, required))
        }) {
            return HandshakeResult::failure(peer_did, started, "required capabilities missing");
        }
        HandshakeResult::success(
            peer_did,
            trust_score,
            identity.capabilities.clone(),
            started,
            None,
        )
    }

    pub fn agent_did(&self) -> &str {
        &self.agent_did
    }

    pub fn has_local_identity(&self) -> bool {
        self.identity.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_did: String,
    pub peer_name: Option<String>,
    pub protocol: String,
    pub trust_score: u32,
    pub trust_verified: bool,
    pub last_verified_secs: Option<u64>,
    pub capabilities: Vec<String>,
    pub endpoint: Option<String>,
}

pub struct TrustBridge {
    pub agent_did: String,
    pub default_trust_threshold: u32,
    peers: Mutex<HashMap<String, PeerInfo>>,
    handshake: TrustHandshake,
}

impl TrustBridge {
    pub fn new(
        agent_did: &str,
        identity: Option<AgentIdentity>,
        trust_manager: Option<Arc<TrustManager>>,
    ) -> Self {
        Self {
            agent_did: agent_did.to_string(),
            default_trust_threshold: 700,
            peers: Mutex::new(HashMap::new()),
            handshake: TrustHandshake::new(agent_did, identity, trust_manager),
        }
    }

    pub fn register_peer(&self, identity: &AgentIdentity, protocol: &str) {
        self.handshake.register_peer(identity);
        self.peers.lock().unwrap_or_else(|e| e.into_inner()).insert(
            identity.did.clone(),
            PeerInfo {
                peer_did: identity.did.clone(),
                peer_name: None,
                protocol: protocol.to_string(),
                trust_score: 0,
                trust_verified: false,
                last_verified_secs: None,
                capabilities: identity.capabilities.clone(),
                endpoint: None,
            },
        );
    }

    pub fn verify_peer(
        &self,
        peer_did: &str,
        protocol: &str,
        required_trust_score: Option<u32>,
        required_capabilities: &[String],
    ) -> HandshakeResult {
        let result = self.handshake.verify_registered_peer(
            peer_did,
            required_trust_score.unwrap_or(self.default_trust_threshold),
            required_capabilities,
        );
        if result.verified {
            self.peers.lock().unwrap_or_else(|e| e.into_inner()).insert(
                peer_did.to_string(),
                PeerInfo {
                    peer_did: peer_did.to_string(),
                    peer_name: result.peer_name.clone(),
                    protocol: protocol.to_string(),
                    trust_score: result.trust_score,
                    trust_verified: true,
                    last_verified_secs: Some(unix_secs_now()),
                    capabilities: result.capabilities.clone(),
                    endpoint: None,
                },
            );
        }
        result
    }

    pub fn is_peer_trusted(&self, peer_did: &str, required_score: Option<u32>) -> bool {
        self.peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(peer_did)
            .map(|peer| {
                peer.trust_verified
                    && peer.trust_score >= required_score.unwrap_or(self.default_trust_threshold)
            })
            .unwrap_or(false)
    }

    pub fn get_peer(&self, peer_did: &str) -> Option<PeerInfo> {
        self.peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(peer_did)
            .cloned()
    }

    pub fn get_trusted_peers(&self, min_score: Option<u32>) -> Vec<PeerInfo> {
        self.peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|peer| {
                peer.trust_verified
                    && peer.trust_score >= min_score.unwrap_or(self.default_trust_threshold)
            })
            .cloned()
            .collect()
    }

    pub fn revoke_peer_trust(&self, peer_did: &str) -> bool {
        if let Some(peer) = self
            .peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(peer_did)
        {
            peer.trust_verified = false;
            peer.trust_score = 0;
            return true;
        }
        false
    }
}

pub struct ProtocolBridge {
    pub agent_did: String,
    pub trust_bridge: TrustBridge,
    pub supported_protocols: Vec<String>,
}

impl ProtocolBridge {
    pub fn new(
        agent_did: &str,
        identity: Option<AgentIdentity>,
        trust_manager: Option<Arc<TrustManager>>,
    ) -> Self {
        Self {
            agent_did: agent_did.to_string(),
            trust_bridge: TrustBridge::new(agent_did, identity, trust_manager),
            supported_protocols: vec!["a2a".into(), "mcp".into(), "iatp".into(), "acp".into()],
        }
    }

    pub fn translate(&self, message: &Value, from_protocol: &str, to_protocol: &str) -> Value {
        if from_protocol == "a2a" && to_protocol == "mcp" {
            let task_type = message
                .get("task_type")
                .and_then(Value::as_str)
                .unwrap_or("execute");
            let parameters = message
                .get("parameters")
                .cloned()
                .unwrap_or(Value::Object(Default::default()));
            serde_json::json!({
                "method": "tools/call",
                "params": { "name": task_type, "arguments": parameters }
            })
        } else if from_protocol == "mcp" && to_protocol == "a2a" {
            let params = message
                .get("params")
                .cloned()
                .unwrap_or(Value::Object(Default::default()));
            serde_json::json!({
                "task_type": params.get("name").and_then(Value::as_str).unwrap_or("execute"),
                "parameters": params.get("arguments").cloned().unwrap_or(Value::Object(Default::default()))
            })
        } else {
            message.clone()
        }
    }

    pub fn add_verification_footer(
        &self,
        content: &str,
        trust_score: u32,
        agent_did: &str,
    ) -> String {
        format!(
            "{content}\n\n> Verified by AgentMesh (Trust Score: {trust_score}/1000)\n> Agent: {agent_did}\n"
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedAgentCard {
    pub peer_did: String,
    pub peer_name: Option<String>,
    pub trust_score: u32,
    pub capabilities: Vec<String>,
    pub protocol: String,
    pub issuer_did: String,
    pub issued_at_secs: u64,
    pub metadata: HashMap<String, String>,
}

impl TrustedAgentCard {
    pub fn from_handshake_result(
        issuer_did: &str,
        protocol: &str,
        result: &HandshakeResult,
    ) -> Self {
        Self {
            peer_did: result.peer_did.clone(),
            peer_name: result.peer_name.clone(),
            trust_score: result.trust_score,
            capabilities: result.capabilities.clone(),
            protocol: protocol.to_string(),
            issuer_did: issuer_did.to_string(),
            issued_at_secs: unix_secs_now(),
            metadata: HashMap::new(),
        }
    }
}

pub struct CardRegistry {
    cards: Mutex<HashMap<String, TrustedAgentCard>>,
}

impl CardRegistry {
    pub fn new() -> Self {
        Self {
            cards: Mutex::new(HashMap::new()),
        }
    }

    pub fn put(&self, card: TrustedAgentCard) {
        self.cards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(card.peer_did.clone(), card);
    }

    pub fn get(&self, peer_did: &str) -> Option<TrustedAgentCard> {
        self.cards
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(peer_did)
            .cloned()
    }
}

impl Default for CardRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_registry_tracks_grants_and_denies() {
        let registry = CapabilityRegistry::new();
        registry
            .grant(
                "did:agentmesh:peer",
                "did:agentmesh:root",
                "read:data",
                Vec::new(),
            )
            .unwrap();
        assert!(registry.has_capability("did:agentmesh:peer", "read:data", None));
        assert!(!registry.has_capability("did:agentmesh:peer", "write:data", None));
    }

    #[test]
    fn trust_handshake_verifies_registered_peer() {
        let peer = AgentIdentity::generate("peer", vec!["data.read".into()]).unwrap();
        let trust = Arc::new(TrustManager::with_defaults());
        trust.set_trust(&peer.did, 750);
        let handshake = TrustHandshake::new("did:agentmesh:self", None, Some(trust));
        handshake.register_peer(&peer);
        let result = handshake.verify_registered_peer(&peer.did, 700, &["data.read".into()]);
        assert!(result.verified);
        assert_eq!(result.trust_level, HandshakeTrustLevel::Trusted);
    }

    #[test]
    fn trust_bridge_records_verified_peer() {
        let peer = AgentIdentity::generate("peer", vec!["data.read".into()]).unwrap();
        let trust = Arc::new(TrustManager::with_defaults());
        trust.set_trust(&peer.did, 900);
        let bridge = TrustBridge::new("did:agentmesh:self", None, Some(trust));
        bridge.register_peer(&peer, "mcp");
        let result = bridge.verify_peer(&peer.did, "mcp", Some(700), &["data.read".into()]);
        assert!(result.verified);
        assert!(bridge.is_peer_trusted(&peer.did, Some(700)));
        assert_eq!(bridge.get_trusted_peers(None).len(), 1);
    }

    #[test]
    fn protocol_bridge_translates_between_a2a_and_mcp() {
        let bridge = ProtocolBridge::new("did:agentmesh:self", None, None);
        let a2a = serde_json::json!({
            "task_type": "search.web",
            "parameters": { "query": "agentmesh" }
        });
        let mcp = bridge.translate(&a2a, "a2a", "mcp");
        assert_eq!(mcp["method"], "tools/call");
        let a2a_roundtrip = bridge.translate(&mcp, "mcp", "a2a");
        assert_eq!(a2a_roundtrip["task_type"], "search.web");
    }

    #[test]
    fn card_registry_stores_handshake_cards() {
        let result = HandshakeResult::success(
            "did:agentmesh:peer",
            800,
            vec!["search.web".into()],
            unix_secs_now(),
            None,
        );
        let card = TrustedAgentCard::from_handshake_result("did:agentmesh:self", "mcp", &result);
        let registry = CardRegistry::new();
        registry.put(card);
        assert_eq!(registry.get("did:agentmesh:peer").unwrap().protocol, "mcp");
    }
}
