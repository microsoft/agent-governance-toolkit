// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Session authentication for MCP traffic.

use crate::mcp::clock::{Clock, NonceGenerator};
use crate::mcp::error::McpError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Persisted MCP session metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpSession {
    pub id: String,
    pub agent_id: String,
    pub issued_at_secs: u64,
    pub expires_at_secs: u64,
    pub token_digest: String,
}

/// Result of issuing a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpIssuedSession {
    pub token: String,
    pub session: McpSession,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionTokenPayload {
    sid: String,
    aid: String,
    exp: u64,
}

/// Session storage seam.
pub trait McpSessionStore: Send + Sync {
    fn get(&self, id: &str) -> Result<Option<McpSession>, McpError>;
    fn set(&self, session: McpSession) -> Result<(), McpError>;
    fn delete(&self, id: &str) -> Result<(), McpError>;
    fn insert_if_below_limit(
        &self,
        session: McpSession,
        concurrent_limit: usize,
        now_secs: u64,
    ) -> Result<bool, McpError>;
}

/// In-memory session storage for defaults and tests.
#[derive(Debug, Default)]
pub struct InMemorySessionStore {
    sessions: Mutex<HashMap<String, McpSession>>,
}

impl McpSessionStore for InMemorySessionStore {
    fn get(&self, id: &str) -> Result<Option<McpSession>, McpError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| McpError::store("session", "session store lock poisoned"))?;
        Ok(sessions.get(id).cloned())
    }

    fn set(&self, session: McpSession) -> Result<(), McpError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| McpError::store("session", "session store lock poisoned"))?;
        sessions.insert(session.id.clone(), session);
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<(), McpError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| McpError::store("session", "session store lock poisoned"))?;
        sessions.remove(id);
        Ok(())
    }

    fn insert_if_below_limit(
        &self,
        session: McpSession,
        concurrent_limit: usize,
        now_secs: u64,
    ) -> Result<bool, McpError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| McpError::store("session", "session store lock poisoned"))?;
        sessions.retain(|_, existing| existing.expires_at_secs > now_secs);
        let active_sessions = sessions
            .values()
            .filter(|existing| existing.agent_id == session.agent_id)
            .count();
        if active_sessions >= concurrent_limit {
            return Ok(false);
        }
        sessions.insert(session.id.clone(), session);
        Ok(true)
    }
}

/// HMAC-signed session authenticator with TTL and concurrency enforcement.
#[derive(Clone)]
pub struct McpSessionAuthenticator {
    secret: Vec<u8>,
    clock: Arc<dyn Clock>,
    nonce_generator: Arc<dyn NonceGenerator>,
    store: Arc<dyn McpSessionStore>,
    ttl: Duration,
    concurrent_limit: usize,
}

impl McpSessionAuthenticator {
    pub fn new(
        secret: Vec<u8>,
        clock: Arc<dyn Clock>,
        nonce_generator: Arc<dyn NonceGenerator>,
        store: Arc<dyn McpSessionStore>,
        ttl: Duration,
        concurrent_limit: usize,
    ) -> Result<Self, McpError> {
        if secret.is_empty() {
            return Err(McpError::InvalidConfig("session secret must not be empty"));
        }
        if ttl.is_zero() {
            return Err(McpError::InvalidConfig("session ttl must be > 0"));
        }
        if concurrent_limit == 0 {
            return Err(McpError::InvalidConfig(
                "concurrent session limit must be > 0",
            ));
        }
        Ok(Self {
            secret,
            clock,
            nonce_generator,
            store,
            ttl,
            concurrent_limit,
        })
    }

    pub fn issue_session(&self, agent_id: &str) -> Result<McpIssuedSession, McpError> {
        let now = unix_secs(self.clock.now())?;
        let session_id = self.nonce_generator.generate()?;
        let expires_at_secs = now
            .checked_add(self.ttl.as_secs())
            .ok_or(McpError::InvalidConfig("session ttl overflow"))?;
        let payload = SessionTokenPayload {
            sid: session_id.clone(),
            aid: agent_id.to_string(),
            exp: expires_at_secs,
        };
        let encoded_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
        let signature = self.sign(&encoded_payload)?;
        let token = format!("{encoded_payload}.{signature}");
        let session = McpSession {
            id: session_id,
            agent_id: agent_id.to_string(),
            issued_at_secs: now,
            expires_at_secs,
            token_digest: sha256_hex(&token),
        };
        if !self
            .store
            .insert_if_below_limit(session.clone(), self.concurrent_limit, now)?
        {
            return Err(McpError::SessionLimitExceeded {
                agent_id: agent_id.to_string(),
                limit: self.concurrent_limit,
            });
        }
        Ok(McpIssuedSession { token, session })
    }

    pub fn authenticate(&self, token: &str, agent_id: &str) -> Result<McpSession, McpError> {
        let (encoded_payload, signature) =
            token.split_once('.').ok_or(McpError::InvalidTokenFormat)?;
        self.verify_signature(encoded_payload, signature)?;
        let payload: SessionTokenPayload = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(encoded_payload)
                .map_err(|_| McpError::InvalidTokenFormat)?,
        )?;
        if payload.aid != agent_id {
            return Err(McpError::AccessDenied {
                reason: "session token does not match requested agent".to_string(),
            });
        }
        let now = unix_secs(self.clock.now())?;
        if payload.exp <= now {
            self.store.delete(&payload.sid)?;
            return Err(McpError::SessionExpired);
        }
        let session = self
            .store
            .get(&payload.sid)?
            .ok_or_else(|| McpError::AccessDenied {
                reason: "unknown session".to_string(),
            })?;
        if session.agent_id != payload.aid || session.expires_at_secs != payload.exp {
            return Err(McpError::AccessDenied {
                reason: "session metadata mismatch".to_string(),
            });
        }
        Ok(session)
    }

    pub fn revoke(&self, session_id: &str) -> Result<(), McpError> {
        self.store.delete(session_id)
    }
    fn sign(&self, payload: &str) -> Result<String, McpError> {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| McpError::InvalidHmacKey)?;
        mac.update(payload.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    fn verify_signature(&self, payload: &str, signature: &str) -> Result<(), McpError> {
        let provided = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| McpError::InvalidSignature)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| McpError::InvalidHmacKey)?;
        mac.update(payload.as_bytes());
        mac.verify_slice(&provided)
            .map_err(|_| McpError::InvalidSignature)
    }
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unix_secs(time: SystemTime) -> Result<u64, McpError> {
    Ok(time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| McpError::AccessDenied {
            reason: "system clock before unix epoch".to_string(),
        })?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::clock::{DeterministicNonceGenerator, FixedClock};
    use std::time::SystemTime;

    #[test]
    fn issues_and_authenticates_sessions() {
        let auth = McpSessionAuthenticator::new(
            b"session-secret".to_vec(),
            Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH)),
            Arc::new(DeterministicNonceGenerator::from_values(vec![
                "session-1".into()
            ])),
            Arc::new(InMemorySessionStore::default()),
            Duration::from_secs(60),
            1,
        )
        .unwrap();
        let issued = auth.issue_session("did:agentmesh:test").unwrap();
        let session = auth
            .authenticate(&issued.token, "did:agentmesh:test")
            .unwrap();
        assert_eq!(session.id, "session-1");
    }

    #[test]
    fn enforces_concurrent_limit() {
        let auth = McpSessionAuthenticator::new(
            b"session-secret".to_vec(),
            Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH)),
            Arc::new(DeterministicNonceGenerator::from_values(vec![
                "s1".into(),
                "s2".into(),
            ])),
            Arc::new(InMemorySessionStore::default()),
            Duration::from_secs(60),
            1,
        )
        .unwrap();
        auth.issue_session("did:agentmesh:test").unwrap();
        assert!(matches!(
            auth.issue_session("did:agentmesh:test"),
            Err(McpError::SessionLimitExceeded { .. })
        ));
    }
}
