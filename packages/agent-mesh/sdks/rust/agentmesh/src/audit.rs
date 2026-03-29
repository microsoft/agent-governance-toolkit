// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Append-only hash-chain audit log with SHA-256 integrity verification.

use crate::types::{AuditEntry, AuditFilter};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Append-only hash-chained audit logger.
///
/// Each entry's hash covers `seq|timestamp|agent_id|action|decision|prev_hash`,
/// creating a tamper-evident chain from the genesis entry.
pub struct AuditLogger {
    entries: Mutex<Vec<AuditEntry>>,
}

impl AuditLogger {
    /// Create an empty audit logger.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    /// Append a new entry to the audit chain and return it.
    pub fn log(&self, agent_id: &str, action: &str, decision: &str) -> AuditEntry {
        let mut entries = self.entries.lock().unwrap();
        let seq = entries.len() as u64;
        let prev_hash = entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_default();
        let timestamp = iso8601_now();

        let hash_input = format!(
            "{}|{}|{}|{}|{}|{}",
            seq, timestamp, agent_id, action, decision, prev_hash
        );
        let hash = sha256_hex(&hash_input);

        let entry = AuditEntry {
            seq,
            timestamp,
            agent_id: agent_id.to_string(),
            action: action.to_string(),
            decision: decision.to_string(),
            previous_hash: prev_hash,
            hash,
        };

        entries.push(entry.clone());
        entry
    }

    /// Verify the integrity of the entire hash chain.
    ///
    /// Returns `true` if every entry's hash is correct and linked to the
    /// previous entry's hash.
    pub fn verify(&self) -> bool {
        let entries = self.entries.lock().unwrap();
        for (i, entry) in entries.iter().enumerate() {
            let expected_prev = if i == 0 {
                String::new()
            } else {
                entries[i - 1].hash.clone()
            };
            if entry.previous_hash != expected_prev {
                return false;
            }
            let hash_input = format!(
                "{}|{}|{}|{}|{}|{}",
                entry.seq,
                entry.timestamp,
                entry.agent_id,
                entry.action,
                entry.decision,
                entry.previous_hash
            );
            if entry.hash != sha256_hex(&hash_input) {
                return false;
            }
        }
        true
    }

    /// Return all audit entries.
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().unwrap().clone()
    }

    /// Return entries matching the given filter.
    pub fn get_entries(&self, filter: &AuditFilter) -> Vec<AuditEntry> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| {
                if let Some(ref id) = filter.agent_id {
                    if e.agent_id != *id {
                        return false;
                    }
                }
                if let Some(ref action) = filter.action {
                    if e.action != *action {
                        return false;
                    }
                }
                if let Some(ref decision) = filter.decision {
                    if e.decision != *decision {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex_encode(&result)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn iso8601_now() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch → civil date (Howard Hinnant algorithm)
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d_val = doy - (153 * mp + 2) / 5 + 1;
    let m_val = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_val = if m_val <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y_val, m_val, d_val, hours, minutes, seconds
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_and_verify() {
        let logger = AuditLogger::new();
        logger.log("agent-1", "data.read", "allow");
        logger.log("agent-1", "shell:rm", "deny");
        logger.log("agent-2", "deploy.prod", "requires_approval");
        assert!(logger.verify());
        assert_eq!(logger.entries().len(), 3);
    }

    #[test]
    fn test_genesis_has_empty_prev_hash() {
        let logger = AuditLogger::new();
        let entry = logger.log("agent-1", "test", "allow");
        assert!(entry.previous_hash.is_empty());
    }

    #[test]
    fn test_chain_links() {
        let logger = AuditLogger::new();
        let e1 = logger.log("a", "action1", "allow");
        let e2 = logger.log("a", "action2", "deny");
        assert_eq!(e2.previous_hash, e1.hash);
    }

    #[test]
    fn test_tamper_detection() {
        let logger = AuditLogger::new();
        logger.log("agent-1", "data.read", "allow");
        logger.log("agent-1", "data.write", "allow");

        // Tamper with the first entry
        {
            let mut entries = logger.entries.lock().unwrap();
            entries[0].action = "tampered".to_string();
        }
        assert!(!logger.verify());
    }

    #[test]
    fn test_filter() {
        let logger = AuditLogger::new();
        logger.log("agent-1", "data.read", "allow");
        logger.log("agent-2", "data.write", "deny");
        logger.log("agent-1", "shell:ls", "deny");

        let filter = AuditFilter {
            agent_id: Some("agent-1".to_string()),
            ..Default::default()
        };
        let filtered = logger.get_entries(&filter);
        assert_eq!(filtered.len(), 2);

        let filter = AuditFilter {
            decision: Some("deny".to_string()),
            ..Default::default()
        };
        let filtered = logger.get_entries(&filter);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_sha256_not_placeholder() {
        let hash = sha256_hex("test");
        // SHA-256 of "test" is a known value
        assert_eq!(hash.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(
            hash,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }
}
