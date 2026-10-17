// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Message signing and replay protection for MCP traffic.
//!
//! Signatures use the shared agent-os MCP message v2 canonical encoding: a
//! compact JSON array `["agent-os:mcp-message:v2", nonce, timestamp, sender,
//! payload]` with UTF-8 output, JSON `null` for an absent sender (distinct
//! from an empty string), and microsecond UTC timestamps. The Python signer
//! (`agent_os.mcp_message_signer`) emits identical bytes; see
//! `docs/security/canonical-signing-v2.md` and #4199.

use crate::mcp::clock::{Clock, NonceGenerator};
use crate::mcp::error::McpError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Signed MCP message envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpSignedMessage {
    pub payload: String,
    pub timestamp_us: u64,
    pub nonce: String,
    pub sender_id: Option<String>,
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

    pub fn sign(
        &self,
        payload: impl Into<String>,
        sender_id: Option<&str>,
    ) -> Result<McpSignedMessage, McpError> {
        let payload = payload.into();
        let timestamp_us = unix_us(self.clock.now())?;
        let nonce = self.nonce_generator.generate()?;
        let signature = self.sign_fields(timestamp_us, &nonce, sender_id, &payload)?;
        Ok(McpSignedMessage {
            payload,
            timestamp_us,
            nonce,
            sender_id: sender_id.map(str::to_string),
            signature,
        })
    }

    pub fn verify(&self, message: &McpSignedMessage) -> Result<(), McpError> {
        let now_us = unix_us(self.clock.now())?;
        let now_secs = now_us / 1_000_000;
        self.nonce_store.cleanup(now_secs)?;
        if now_us.abs_diff(message.timestamp_us) > self.timestamp_tolerance.as_micros() as u64 {
            return Err(McpError::AccessDenied {
                reason: "message timestamp outside tolerance".to_string(),
            });
        }
        let provided = STANDARD
            .decode(&message.signature)
            .map_err(|_| McpError::InvalidSignature)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| McpError::InvalidHmacKey)?;
        let canonical = signature_input(
            message.timestamp_us,
            &message.nonce,
            message.sender_id.as_deref(),
            &message.payload,
        );
        mac.update(canonical.as_bytes());
        mac.verify_slice(&provided)
            .map_err(|_| McpError::InvalidSignature)?;
        let expires_at_secs = now_secs
            .checked_add(self.nonce_ttl.as_secs())
            .ok_or(McpError::InvalidConfig("nonce ttl overflow"))?;
        if !self
            .nonce_store
            .reserve(message.nonce.clone(), expires_at_secs, now_secs)?
        {
            return Err(McpError::ReplayDetected);
        }
        Ok(())
    }

    fn sign_fields(
        &self,
        timestamp_us: u64,
        nonce: &str,
        sender_id: Option<&str>,
        payload: &str,
    ) -> Result<String, McpError> {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| McpError::InvalidHmacKey)?;
        let canonical = signature_input(timestamp_us, nonce, sender_id, payload);
        mac.update(canonical.as_bytes());
        Ok(STANDARD.encode(mac.finalize().into_bytes()))
    }
}

/// Shared agent-os MCP message v2 canonical representation (see #4132 and
/// #4199): a compact JSON array with the fixed domain marker first. JSON
/// arrays and string escaping make the framing unambiguous, so no two
/// distinct field tuples can produce the same HMAC input. `sender_id=None`
/// encodes as JSON `null`, distinct from an empty string. The timestamp is
/// microsecond UTC, placed inside the array.
fn signature_input(
    timestamp_us: u64,
    nonce: &str,
    sender_id: Option<&str>,
    payload: &str,
) -> String {
    let mut out = String::with_capacity(nonce.len() + payload.len() + 128);
    out.push_str("[\"agent-os:mcp-message:v2\",");
    write_json_string(&mut out, nonce);
    out.push(',');
    write_json_string(&mut out, &format_rfc3339_utc_micros(timestamp_us));
    out.push(',');
    match sender_id {
        None => out.push_str("null"),
        Some(sender) => write_json_string(&mut out, sender),
    }
    out.push(',');
    write_json_string(&mut out, payload);
    out.push(']');
    out
}

/// Write a JSON string literal using the same escaping as Python's
/// `json.dumps(..., ensure_ascii=False)`: only quotes, backslashes, and
/// control characters are escaped, so both SDKs emit identical bytes.
fn write_json_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Format microsecond Unix time as UTC RFC 3339 with exactly six fractional
/// digits and a `+00:00` offset, matching Python's
/// `datetime.isoformat(timespec="microseconds")` after `astimezone(UTC)`.
fn format_rfc3339_utc_micros(timestamp_us: u64) -> String {
    let secs = (timestamp_us / 1_000_000) as i64;
    let micros = timestamp_us % 1_000_000;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}+00:00")
}

/// Convert days since the Unix epoch to a civil UTC date (proleptic
/// Gregorian). Algorithm by Howard Hinnant, public domain.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn unix_us(time: SystemTime) -> Result<u64, McpError> {
    Ok(time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| McpError::AccessDenied {
            reason: "system clock before unix epoch".to_string(),
        })?
        .as_micros() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::clock::{DeterministicNonceGenerator, FixedClock};
    use std::time::SystemTime;

    fn signer_with(clock: Arc<dyn Clock>, nonces: Vec<String>) -> McpMessageSigner {
        McpMessageSigner::new(
            b"message-secret".to_vec(),
            clock,
            Arc::new(DeterministicNonceGenerator::from_values(nonces)),
            Arc::new(InMemoryNonceStore::default()),
            Duration::from_secs(60),
            Duration::from_secs(120),
        )
        .unwrap()
    }

    #[test]
    fn signs_and_verifies_messages() {
        let signer = signer_with(
            Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH)),
            vec!["n1".into()],
        );
        let message = signer.sign("payload", None).unwrap();
        signer.verify(&message).unwrap();
    }

    #[test]
    fn rejects_replayed_messages() {
        let signer = signer_with(
            Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH)),
            vec!["n1".into()],
        );
        let message = signer.sign("payload", None).unwrap();
        signer.verify(&message).unwrap();
        assert!(matches!(
            signer.verify(&message),
            Err(McpError::ReplayDetected)
        ));
    }

    /// Shared key and timestamps of the cross-SDK vector set. The Python SDK
    /// asserts the identical vectors (see
    /// docs/security/canonical-signing-v2.md).
    const VECTOR_SECRET: &[u8] = b"mcp-sig-v2-cross-sdk-vector-key-000001";
    const TS_A_US: u64 = 1_700_000_000_123_456;
    const TS_B_US: u64 = 1_700_000_000_999_999;

    fn vector_clock(timestamp_us: u64) -> Arc<dyn Clock> {
        Arc::new(FixedClock::new(
            SystemTime::UNIX_EPOCH + Duration::from_micros(timestamp_us),
        ))
    }

    fn vector_signer(nonce: &str, timestamp_us: u64) -> McpMessageSigner {
        McpMessageSigner::new(
            VECTOR_SECRET.to_vec(),
            vector_clock(timestamp_us),
            Arc::new(DeterministicNonceGenerator::from_values(vec![
                nonce.to_string()
            ])),
            Arc::new(InMemoryNonceStore::default()),
            Duration::from_secs(60),
            Duration::from_secs(120),
        )
        .unwrap()
    }

    #[test]
    fn matches_python_v2_shared_vectors() {
        let cases: [(&str, Option<&str>, &str, u64, &str); 9] = [
            (
                "n",
                None,
                "x:y",
                TS_A_US,
                "ulKQJ88YmF6olg4ML3ekYf7vTA2jh7m434nn/bh59ns=",
            ),
            (
                "n:x",
                None,
                "y",
                TS_A_US,
                "4LV3y6oukPpuK7KicYSjmRejFuDmA2q2NiDgocNtUZs=",
            ),
            (
                "a|b",
                Some("s|t"),
                "p|q",
                TS_A_US,
                "JYCranEAW75tG9xotPxrynub4VUm1JJ04Pn5jrwPknc=",
            ),
            (
                "நி",
                None,
                "🚀 {\"json\":[1,2]}",
                TS_A_US,
                "OfjfnaSRytNHOrwwVGIjfVI9+KshmVKThfmw+ZJILDE=",
            ),
            (
                "n",
                Some(""),
                "hello",
                TS_A_US,
                "VFK/y1V5v3BpfZ92s+XbfBDpcJ37hC7obDb5qGAhDU4=",
            ),
            (
                "n",
                None,
                "hello",
                TS_A_US,
                "jNdf63ZaaLmvYOoPhwKDDwYjZOXgImRYAyFsny+UK5I=",
            ),
            (
                "q\"uote\\slash",
                Some("a\u{0001}b"),
                "line\n\u{0000}end",
                TS_A_US,
                "RMaggh8DnjNCnfsfMmC41aOUSl5z0rvj+U+pMp6PMK4=",
            ),
            (
                "n",
                None,
                "[\"agent-os:mcp-message:v2\",\"x\",\"2023-11-14T22:13:20.123456+00:00\",null,\"y\"]",
                TS_A_US,
                "z449mTVpVmzBmacGaEUecnunNGj49iOevfdpBeqyqPk=",
            ),
            (
                "n",
                Some("agent-1"),
                "hello",
                TS_B_US,
                "VdH7Z13r4EVkC8PZsl7qrnu9Na/vDEyzvKjyCU2SuWE=",
            ),
        ];
        for (nonce, sender, payload, timestamp_us, expected) in cases {
            let signer = vector_signer(nonce, timestamp_us);
            let message = signer.sign(payload, sender).unwrap();
            assert_eq!(message.timestamp_us, timestamp_us);
            assert_eq!(
                message.signature, expected,
                "vector mismatch for nonce {nonce:?}"
            );
        }
    }

    #[test]
    fn rejects_signature_field_reframing() {
        let signer = vector_signer("n", TS_A_US);
        let signed = signer.sign("x:y", None).unwrap();
        assert_eq!(
            signed.signature,
            "ulKQJ88YmF6olg4ML3ekYf7vTA2jh7m434nn/bh59ns="
        );
        let reframed = McpSignedMessage {
            payload: "y".to_string(),
            timestamp_us: signed.timestamp_us,
            nonce: "n:x".to_string(),
            sender_id: signed.sender_id.clone(),
            signature: signed.signature.clone(),
        };
        assert!(matches!(
            signer.verify(&reframed),
            Err(McpError::InvalidSignature)
        ));
    }

    /// JSON `null` (absent sender) and an empty-string sender are distinct
    /// encodings, so a relay cannot flip a signed message between "no
    /// sender" and "empty sender" without breaking the MAC. Each signer
    /// signs once, so the single-value deterministic nonce generators never
    /// run dry.
    #[test]
    fn null_and_empty_sender_are_distinct() {
        let absent = vector_signer("n", TS_A_US).sign("payload", None).unwrap();
        let empty = vector_signer("n", TS_A_US)
            .sign("payload", Some(""))
            .unwrap();
        assert_ne!(absent.signature, empty.signature);
    }

    #[test]
    fn formats_timestamps_like_python_isoformat() {
        assert_eq!(
            format_rfc3339_utc_micros(TS_A_US),
            "2023-11-14T22:13:20.123456+00:00"
        );
        assert_eq!(
            format_rfc3339_utc_micros(TS_B_US),
            "2023-11-14T22:13:20.999999+00:00"
        );
        assert_eq!(
            format_rfc3339_utc_micros(0),
            "1970-01-01T00:00:00.000000+00:00"
        );
    }
}
