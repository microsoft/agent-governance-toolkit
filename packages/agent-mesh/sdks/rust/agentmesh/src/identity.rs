// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Ed25519-based agent identity with DID support.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// An agent's cryptographic identity (Ed25519 key pair + DID).
pub struct AgentIdentity {
    /// Decentralised identifier, e.g. `did:agentmesh:my-agent`.
    pub did: String,
    /// Ed25519 public key.
    pub public_key: VerifyingKey,
    /// Capabilities declared by this agent.
    pub capabilities: Vec<String>,
    signing_key: SigningKey,
}

impl AgentIdentity {
    /// Generate a new Ed25519-based identity for the given agent.
    pub fn generate(agent_id: &str, capabilities: Vec<String>) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        Ok(Self {
            did: format!("did:agentmesh:{}", agent_id),
            public_key,
            capabilities,
            signing_key,
        })
    }

    /// Sign arbitrary data with the agent's private key.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.signing_key.sign(data).to_bytes().to_vec()
    }

    /// Verify a signature against data using this identity's public key.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let sig_bytes: [u8; 64] = signature.try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        self.public_key.verify(data, &sig).is_ok()
    }

    /// Serialise the public portion of the identity to JSON.
    pub fn to_json(&self) -> Result<String, IdentityError> {
        let public = PublicIdentity {
            did: self.did.clone(),
            public_key: self.public_key.to_bytes().to_vec(),
            capabilities: self.capabilities.clone(),
        };
        serde_json::to_string(&public).map_err(IdentityError::Serialization)
    }

    /// Deserialise a public identity from JSON.
    ///
    /// The returned identity can verify signatures but cannot sign.
    pub fn from_json(json: &str) -> Result<PublicIdentity, IdentityError> {
        serde_json::from_str(json).map_err(IdentityError::Serialization)
    }
}

/// The public (verifiable) portion of an agent identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub did: String,
    pub public_key: Vec<u8>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl PublicIdentity {
    /// Verify a signature using this public identity.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        if self.public_key.len() != 32 || signature.len() != 64 {
            return false;
        }
        let key_bytes: [u8; 32] = self.public_key.as_slice().try_into().unwrap();
        let sig_bytes: [u8; 64] = signature.try_into().unwrap();
        if let Ok(verifying_key) = VerifyingKey::from_bytes(&key_bytes) {
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            verifying_key.verify(data, &sig).is_ok()
        } else {
            false
        }
    }
}

/// Errors returned by identity operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("serialization error: {0}")]
    Serialization(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_did() {
        let id = AgentIdentity::generate("test-agent", vec!["data.read".into()]).unwrap();
        assert_eq!(id.did, "did:agentmesh:test-agent");
        assert_eq!(id.capabilities, vec!["data.read"]);
    }

    #[test]
    fn test_sign_and_verify() {
        let id = AgentIdentity::generate("signer", vec![]).unwrap();
        let data = b"hello world";
        let sig = id.sign(data);
        assert!(id.verify(data, &sig));
        assert!(!id.verify(b"wrong data", &sig));
    }

    #[test]
    fn test_json_roundtrip() {
        let id = AgentIdentity::generate("json-agent", vec!["cap1".into()]).unwrap();
        let json = id.to_json().unwrap();
        let public = AgentIdentity::from_json(&json).unwrap();
        assert_eq!(public.did, "did:agentmesh:json-agent");
        assert_eq!(public.capabilities, vec!["cap1"]);

        // Public identity can verify signatures
        let sig = id.sign(b"payload");
        assert!(public.verify(b"payload", &sig));
    }

    #[test]
    fn test_bad_signature_rejected() {
        let id = AgentIdentity::generate("agent", vec![]).unwrap();
        assert!(!id.verify(b"data", &[0u8; 64]));
        assert!(!id.verify(b"data", &[0u8; 32])); // wrong length
    }

    #[test]
    fn test_multiple_identities_different_dids() {
        let id1 = AgentIdentity::generate("agent-1", vec![]).unwrap();
        let id2 = AgentIdentity::generate("agent-2", vec![]).unwrap();
        assert_ne!(id1.did, id2.did);
    }

    #[test]
    fn test_multiple_identities_different_key_pairs() {
        let id1 = AgentIdentity::generate("agent-a", vec![]).unwrap();
        let id2 = AgentIdentity::generate("agent-b", vec![]).unwrap();
        assert_ne!(id1.public_key.to_bytes(), id2.public_key.to_bytes());
    }

    #[test]
    fn test_sign_empty_data() {
        let id = AgentIdentity::generate("empty-signer", vec![]).unwrap();
        let sig = id.sign(b"");
        assert_eq!(sig.len(), 64);
        assert!(id.verify(b"", &sig));
    }

    #[test]
    fn test_cross_identity_verification_fails() {
        let id1 = AgentIdentity::generate("signer-1", vec![]).unwrap();
        let id2 = AgentIdentity::generate("signer-2", vec![]).unwrap();
        let sig = id1.sign(b"test data");
        // id2 should NOT verify a signature produced by id1
        assert!(!id2.verify(b"test data", &sig));
    }

    #[test]
    fn test_public_identity_from_json_verifies_signatures() {
        let id = AgentIdentity::generate("json-verify", vec!["read".into()]).unwrap();
        let json = id.to_json().unwrap();
        let public = AgentIdentity::from_json(&json).unwrap();
        let data = b"important payload";
        let sig = id.sign(data);
        assert!(public.verify(data, &sig));
        // Should fail with wrong data
        assert!(!public.verify(b"wrong data", &sig));
    }

    #[test]
    fn test_invalid_json_returns_error() {
        let result = AgentIdentity::from_json("not valid json {{{");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::Serialization(_)
        ));
    }

    #[test]
    fn test_public_identity_empty_public_key_rejects() {
        let public = PublicIdentity {
            did: "did:agentmesh:test".to_string(),
            public_key: vec![], // empty
            capabilities: vec![],
        };
        assert!(!public.verify(b"data", &[0u8; 64]));
    }

    #[test]
    fn test_capabilities_roundtrip_json() {
        let caps = vec![
            "data.read".to_string(),
            "data.write".to_string(),
            "admin".to_string(),
        ];
        let id = AgentIdentity::generate("cap-agent", caps.clone()).unwrap();
        let json = id.to_json().unwrap();
        let public = AgentIdentity::from_json(&json).unwrap();
        assert_eq!(public.capabilities, caps);
    }

    #[test]
    fn test_did_format() {
        let id = AgentIdentity::generate("my-agent", vec![]).unwrap();
        assert!(id.did.starts_with("did:agentmesh:"));
        assert_eq!(id.did, "did:agentmesh:my-agent");
    }
}
