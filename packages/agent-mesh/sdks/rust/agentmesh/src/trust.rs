// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trust scoring engine — tracks per-agent trust scores on a 0–1000 scale
//! across five tiers, with optional JSON persistence.

use crate::identity::AgentIdentity;
use crate::types::{TrustScore, TrustTier};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for the trust manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfig {
    /// Score assigned to unknown agents (default: 500).
    pub initial_score: u32,
    /// Minimum score required to be considered trusted.
    pub threshold: u32,
    /// Points added on a successful interaction (default: 10).
    pub reward: u32,
    /// Points removed on a failed interaction (default: 50).
    pub penalty: u32,
    /// Optional path for JSON persistence.
    pub persist_path: Option<String>,
    /// Per-hour decay multiplier applied to trust scores (default: 0.95).
    pub decay_rate: f64,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            initial_score: 500,
            threshold: 500,
            reward: 10,
            penalty: 50,
            persist_path: None,
            decay_rate: 0.95,
        }
    }
}

/// Internal per-agent state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentState {
    agent_id: String,
    score: u32,
    interactions: u64,
    #[serde(default = "epoch_now")]
    last_update: u64,
}

/// Manages trust scores for a set of agents.
///
/// Thread-safe — can be shared across threads via `Arc<TrustManager>`.
pub struct TrustManager {
    config: TrustConfig,
    agents: RwLock<HashMap<String, AgentState>>,
}

impl TrustManager {
    /// Create a new trust manager with the given configuration.
    pub fn new(config: TrustConfig) -> Self {
        let manager = Self {
            config,
            agents: RwLock::new(HashMap::new()),
        };
        manager.load_from_disk();
        manager
    }

    /// Create a trust manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(TrustConfig::default())
    }

    /// Get the current trust score for an agent.
    ///
    /// Returns the default score if the agent is unknown.
    /// Decay is applied based on time elapsed since the last update.
    pub fn get_trust_score(&self, agent_id: &str) -> TrustScore {
        let agents = self.agents.read().unwrap_or_else(|e| e.into_inner());
        match agents.get(agent_id) {
            Some(state) => {
                let decayed = self.apply_decay(state.score, state.last_update);
                TrustScore {
                    agent_id: state.agent_id.clone(),
                    score: decayed,
                    tier: TrustTier::from_score(decayed),
                    interactions: state.interactions,
                }
            }
            None => TrustScore {
                agent_id: agent_id.to_string(),
                score: self.config.initial_score,
                tier: TrustTier::from_score(self.config.initial_score),
                interactions: 0,
            },
        }
    }

    /// Check whether an agent meets the trust threshold.
    pub fn is_trusted(&self, agent_id: &str) -> bool {
        self.get_trust_score(agent_id).score >= self.config.threshold
    }

    /// Record a successful interaction (increases trust score).
    pub fn record_success(&self, agent_id: &str) {
        let mut agents = self.agents.write().unwrap_or_else(|e| e.into_inner());
        let now = epoch_now();
        let state = agents
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentState {
                agent_id: agent_id.to_string(),
                score: self.config.initial_score,
                interactions: 0,
                last_update: now,
            });
        state.score = self.apply_decay(state.score, state.last_update);
        state.score = (state.score + self.config.reward).min(1000);
        state.interactions += 1;
        state.last_update = now;
        drop(agents);
        self.save_to_disk();
    }

    /// Record a failed or suspicious interaction (decreases trust score).
    pub fn record_failure(&self, agent_id: &str) {
        let mut agents = self.agents.write().unwrap_or_else(|e| e.into_inner());
        let now = epoch_now();
        let state = agents
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentState {
                agent_id: agent_id.to_string(),
                score: self.config.initial_score,
                interactions: 0,
                last_update: now,
            });
        state.score = self.apply_decay(state.score, state.last_update);
        state.score = state.score.saturating_sub(self.config.penalty);
        state.interactions += 1;
        state.last_update = now;
        drop(agents);
        self.save_to_disk();
    }

    /// Set the trust score directly for an agent.
    pub fn set_trust(&self, agent_id: &str, score: u32) {
        let mut agents = self.agents.write().unwrap_or_else(|e| e.into_inner());
        let now = epoch_now();
        let state = agents
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentState {
                agent_id: agent_id.to_string(),
                score: self.config.initial_score,
                interactions: 0,
                last_update: now,
            });
        state.score = score.min(1000);
        state.last_update = now;
        drop(agents);
        self.save_to_disk();
    }

    /// Return trust scores for all tracked agents.
    pub fn all_agents(&self) -> Vec<TrustScore> {
        self.agents
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|s| {
                let decayed = self.apply_decay(s.score, s.last_update);
                TrustScore {
                    agent_id: s.agent_id.clone(),
                    score: decayed,
                    tier: TrustTier::from_score(decayed),
                    interactions: s.interactions,
                }
            })
            .collect()
    }

    /// Verify a peer agent's identity via challenge-response.
    ///
    /// Generates a random 32-byte challenge, asks the peer to sign it,
    /// then verifies the signature against the peer's public key.
    pub fn verify_peer(&self, _peer_id: &str, peer_identity: &AgentIdentity) -> bool {
        let mut challenge = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge);
        let signature = peer_identity.sign(&challenge);
        peer_identity.verify(&challenge, &signature)
    }

    /// Apply time-based decay to a raw score.
    fn apply_decay(&self, score: u32, last_update: u64) -> u32 {
        let now = epoch_now();
        if now <= last_update {
            return score;
        }
        let hours_elapsed = (now - last_update) as f64 / 3600.0;
        let decayed = (score as f64) * self.config.decay_rate.powf(hours_elapsed);
        (decayed.round() as u32).min(1000)
    }

    /// Best-effort load from persistence file.
    fn load_from_disk(&self) {
        if let Some(path) = &self.config.persist_path {
            if let Ok(data) = std::fs::read_to_string(path) {
                if let Ok(states) = serde_json::from_str::<Vec<AgentState>>(&data) {
                    let mut agents = self.agents.write().unwrap_or_else(|e| e.into_inner());
                    for state in states {
                        agents.insert(state.agent_id.clone(), state);
                    }
                }
            }
        }
    }

    /// Best-effort save to persistence file.
    fn save_to_disk(&self) {
        if let Some(path) = &self.config.persist_path {
            let agents = self.agents.read().unwrap_or_else(|e| e.into_inner());
            let states: Vec<&AgentState> = agents.values().collect();
            if let Ok(json) = serde_json::to_string(&states) {
                let _ = std::fs::write(path, json);
            }
        }
    }
}

fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_score() {
        let tm = TrustManager::with_defaults();
        let score = tm.get_trust_score("agent-1");
        assert_eq!(score.score, 500);
        assert_eq!(score.tier, TrustTier::Standard);
        assert_eq!(score.interactions, 0);
    }

    #[test]
    fn test_record_success_increases_score() {
        let tm = TrustManager::with_defaults();
        tm.record_success("agent-1");
        let score = tm.get_trust_score("agent-1");
        assert_eq!(score.score, 510);
        assert_eq!(score.interactions, 1);
    }

    #[test]
    fn test_record_failure_decreases_score() {
        let tm = TrustManager::with_defaults();
        tm.record_success("agent-1"); // 510
        tm.record_failure("agent-1"); // 510 - 50 = 460
        let score = tm.get_trust_score("agent-1");
        assert_eq!(score.score, 460);
        assert_eq!(score.tier, TrustTier::Probationary);
    }

    #[test]
    fn test_score_capped_at_1000() {
        let config = TrustConfig {
            initial_score: 990,
            reward: 20,
            ..TrustConfig::default()
        };
        let tm = TrustManager::new(config);
        tm.record_success("agent-1");
        assert_eq!(tm.get_trust_score("agent-1").score, 1000);
    }

    #[test]
    fn test_score_floor_at_zero() {
        let config = TrustConfig {
            initial_score: 30,
            penalty: 100,
            ..TrustConfig::default()
        };
        let tm = TrustManager::new(config);
        tm.record_failure("agent-1");
        assert_eq!(tm.get_trust_score("agent-1").score, 0);
    }

    #[test]
    fn test_trust_tiers() {
        assert_eq!(TrustTier::from_score(950), TrustTier::VerifiedPartner);
        assert_eq!(TrustTier::from_score(750), TrustTier::Trusted);
        assert_eq!(TrustTier::from_score(600), TrustTier::Standard);
        assert_eq!(TrustTier::from_score(400), TrustTier::Probationary);
        assert_eq!(TrustTier::from_score(100), TrustTier::Untrusted);
    }

    #[test]
    fn test_is_trusted() {
        let config = TrustConfig {
            initial_score: 500,
            threshold: 500,
            ..TrustConfig::default()
        };
        let tm = TrustManager::new(config);
        assert!(tm.is_trusted("new-agent"));
        tm.record_failure("new-agent"); // 450
        assert!(!tm.is_trusted("new-agent"));
    }

    #[test]
    fn test_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        let path_str = path.to_str().unwrap().to_string();

        // Write
        {
            let config = TrustConfig {
                persist_path: Some(path_str.clone()),
                ..TrustConfig::default()
            };
            let tm = TrustManager::new(config);
            tm.record_success("agent-a");
            tm.record_success("agent-a");
        }

        // Read back
        {
            let config = TrustConfig {
                persist_path: Some(path_str),
                ..TrustConfig::default()
            };
            let tm = TrustManager::new(config);
            assert_eq!(tm.get_trust_score("agent-a").score, 520);
        }
    }

    #[test]
    fn test_decay_rate_default() {
        let config = TrustConfig::default();
        assert!((config.decay_rate - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_decay_no_elapsed_time() {
        let tm = TrustManager::with_defaults();
        tm.record_success("agent-1");
        // Immediately reading — negligible time elapsed → score should
        // remain essentially unchanged.
        let score = tm.get_trust_score("agent-1").score;
        assert_eq!(score, 510);
    }

    #[test]
    fn test_decay_applied_over_time() {
        let tm = TrustManager::with_defaults();
        // Manually insert an agent with a known score and an old timestamp.
        {
            let mut agents = tm.agents.write().unwrap();
            agents.insert(
                "old-agent".to_string(),
                AgentState {
                    agent_id: "old-agent".to_string(),
                    score: 1000,
                    interactions: 5,
                    last_update: epoch_now() - 3600, // 1 hour ago
                },
            );
        }
        let score = tm.get_trust_score("old-agent");
        // After 1 hour with decay_rate 0.95: 1000 * 0.95 = 950
        assert_eq!(score.score, 950);
    }

    #[test]
    fn test_decay_multiple_hours() {
        let tm = TrustManager::with_defaults();
        {
            let mut agents = tm.agents.write().unwrap();
            agents.insert(
                "stale-agent".to_string(),
                AgentState {
                    agent_id: "stale-agent".to_string(),
                    score: 1000,
                    interactions: 1,
                    last_update: epoch_now() - 7200, // 2 hours ago
                },
            );
        }
        let score = tm.get_trust_score("stale-agent");
        // 1000 * 0.95^2 = 902.5 → 903 (rounded)
        assert_eq!(score.score, 903);
    }

    #[test]
    fn test_decay_disabled_when_rate_is_one() {
        let config = TrustConfig {
            decay_rate: 1.0,
            ..TrustConfig::default()
        };
        let tm = TrustManager::new(config);
        {
            let mut agents = tm.agents.write().unwrap();
            agents.insert(
                "stable".to_string(),
                AgentState {
                    agent_id: "stable".to_string(),
                    score: 800,
                    interactions: 1,
                    last_update: epoch_now() - 36000, // 10 hours ago
                },
            );
        }
        assert_eq!(tm.get_trust_score("stable").score, 800);
    }

    #[test]
    fn test_verify_peer_valid_identity() {
        let tm = TrustManager::with_defaults();
        let peer =
            crate::identity::AgentIdentity::generate("peer-agent", vec!["cap".into()]).unwrap();
        assert!(tm.verify_peer("peer-agent", &peer));
    }
}
