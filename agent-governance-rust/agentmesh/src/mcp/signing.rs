// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Message signing and replay protection for MCP traffic.

use crate::mcp::clock::{Clock, NonceGenerator};
use crate::mcp::error::McpError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Signed MCP message envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpSignedMessage {
    pub payload: String,
    pub timestamp_secs: u64,
    pub nonce: String,
    pub signature: String,
}

/// Replay-detection nonce store.
pub trait McpNonceStore: Send + Sync {
    fn reserve(&self, nonce: String, expires_at_secs: u64, now_secs: u64)
        -> Result<bool, McpError>;
    fn cleanup(&self, now_secs: u64) -> Result<(), McpError>;
}

/// In-memory nonce store.
#[derive(Debug, Default)]
pub struct InMemoryNonceStore {
    nonces: Mutex<HashMap<String, u64>>,
}

impl McpNonceStore for InMemoryNonceStore {
    fn reserve(
        &self,
        nonce: String,
        expires_at_secs: u64,
        now_secs: u64,
    ) -> Result<bool, McpError> {
        let mut nonces = self
            .nonces
            .lock()
            .map_err(|_| McpError::store("nonce", "nonce store lock poisoned"))?;
        nonces.retain(|_, expires_at| *expires_at > now_secs);
        if nonces.contains_key(&nonce) {
            return Ok(false);
        }
        nonces.insert(nonce, expires_at_secs);
        Ok(true)
    }

    fn cleanup(&self, now_secs: u64) -> Result<(), McpError> {
        let mut nonces = self
            .nonces
            .lock()
            .map_err(|_| McpError::store("nonce", "nonce store lock poisoned"))?;
        nonces.retain(|_, expires_at| *expires_at > now_secs);
        Ok(())
    }
}

/// HMAC-SHA256 signer with timestamp validation and nonce replay protection.
#[derive(Clone)]
pub struct McpMessageSigner {
    secret: Vec<u8>,
    clock: Arc<dyn Clock>,
    nonce_generator: Arc<dyn NonceGenerator>,
    nonce_store: Arc<dyn McpNonceStore>,
    timestamp_tolerance: Duration,
    nonce_ttl: Duration,
}

impl McpMessageSigner {
    pub fn new(
        secret: Vec<u8>,
        clock: Arc<dyn Clock>,
        nonce_generator: Arc<dyn NonceGenerator>,
        nonce_store: Arc<dyn McpNonceStore>,
        timestamp_tolerance: Duration,
        nonce_ttl: Duration,
    ) -> Result<Self, McpError> {
        if secret.is_empty() {
            return Err(McpError::InvalidConfig(
                "message signing secret must not be empty",
            ));
        }
        if timestamp_tolerance.is_zero() || nonce_ttl.is_zero() {
            return Err(McpError::InvalidConfig("tolerances must be > 0"));
        }
        Ok(Self {
            secret,
            clock,
            nonce_generator,
            nonce_store,
            timestamp_tolerance,
            nonce_ttl,
        })
    }

    pub fn sign(&self, payload: impl Into<String>) -> Result<McpSignedMessage, McpError> {
        let payload = payload.into();
        let timestamp_secs = unix_secs(self.clock.now())?;
        let nonce = self.nonce_generator.generate()?;
        let signature = self.sign_fields(timestamp_secs, &nonce, &payload)?;
        Ok(McpSignedMessage {
            payload,
            timestamp_secs,
            nonce,
            signature,
        })
    }

    pub fn verify(&self, message: &McpSignedMessage) -> Result<(), McpError> {
        let now = unix_secs(self.clock.now())?;
        self.nonce_store.cleanup(now)?;
        if now.abs_diff(message.timestamp_secs) > self.timestamp_tolerance.as_secs() {
            return Err(McpError::AccessDenied {
                reason: "message timestamp outside tolerance".to_string(),
            });
        }
        let provided = URL_SAFE_NO_PAD
            .decode(&message.signature)
            .map_err(|_| McpError::InvalidSignature)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| McpError::InvalidHmacKey)?;
        mac.update(
            signature_input(message.timestamp_secs, &message.nonce, &message.payload).as_bytes(),
        );
        mac.verify_slice(&provided)
            .map_err(|_| McpError::InvalidSignature)?;
        let expires_at_secs = now
            .checked_add(self.nonce_ttl.as_secs())
            .ok_or(McpError::InvalidConfig("nonce ttl overflow"))?;
        if !self
            .nonce_store
            .reserve(message.nonce.clone(), expires_at_secs, now)?
        {
            return Err(McpError::ReplayDetected);
        }
        Ok(())
    }

    fn sign_fields(
        &self,
        timestamp_secs: u64,
        nonce: &str,
        payload: &str,
    ) -> Result<String, McpError> {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| McpError::InvalidHmacKey)?;
        mac.update(signature_input(timestamp_secs, nonce, payload).as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }
}

fn signature_input(timestamp_secs: u64, nonce: &str, payload: &str) -> String {
    format!("{timestamp_secs}:{nonce}:{payload}")
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
    fn signs_and_verifies_messages() {
        let signer = McpMessageSigner::new(
            b"message-secret".to_vec(),
            Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH)),
            Arc::new(DeterministicNonceGenerator::from_values(vec!["n1".into()])),
            Arc::new(InMemoryNonceStore::default()),
            Duration::from_secs(60),
            Duration::from_secs(120),
        )
        .unwrap();
        let message = signer.sign("payload").unwrap();
        signer.verify(&message).unwrap();
    }

    #[test]
    fn rejects_replayed_messages() {
        let signer = McpMessageSigner::new(
            b"message-secret".to_vec(),
            Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH)),
            Arc::new(DeterministicNonceGenerator::from_values(vec!["n1".into()])),
            Arc::new(InMemoryNonceStore::default()),
            Duration::from_secs(60),
            Duration::from_secs(120),
        )
        .unwrap();
        let message = signer.sign("payload").unwrap();
        signer.verify(&message).unwrap();
        assert!(matches!(
            signer.verify(&message),
            Err(McpError::ReplayDetected)
        ));
    }
}
