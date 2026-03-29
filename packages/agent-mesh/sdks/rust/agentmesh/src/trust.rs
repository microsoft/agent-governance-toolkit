// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trust scoring engine — tracks per-agent trust scores on a 0–1000 scale
//! across five tiers, with optional JSON persistence.

use crate::types::{TrustScore, TrustTier};
use std::collections::HashMap;
use std::sync::RwLock;

/// Configuration for the trust manager.
#[derive(Debug, Clone)]
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
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            initial_score: 500,
            threshold: 500,
            reward: 10,
            penalty: 50,
            persist_path: None,
        }
    }
}

/// Internal per-agent state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AgentState {
    agent_id: String,
    score: u32,
    interactions: u64,
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
    pub fn get_trust_score(&self, agent_id: &str) -> TrustScore {
        let agents = self.agents.read().unwrap();
        match agents.get(agent_id) {
            Some(state) => TrustScore {
                agent_id: state.agent_id.clone(),
                score: state.score,
                tier: TrustTier::from_score(state.score),
                interactions: state.interactions,
            },
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
        let mut agents = self.agents.write().unwrap();
        let state = agents
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentState {
                agent_id: agent_id.to_string(),
                score: self.config.initial_score,
                interactions: 0,
            });
        state.score = (state.score + self.config.reward).min(1000);
        state.interactions += 1;
        drop(agents);
        self.save_to_disk();
    }

    /// Record a failed or suspicious interaction (decreases trust score).
    pub fn record_failure(&self, agent_id: &str) {
        let mut agents = self.agents.write().unwrap();
        let state = agents
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentState {
                agent_id: agent_id.to_string(),
                score: self.config.initial_score,
                interactions: 0,
            });
        state.score = state.score.saturating_sub(self.config.penalty);
        state.interactions += 1;
        drop(agents);
        self.save_to_disk();
    }

    /// Set the trust score directly for an agent.
    pub fn set_trust(&self, agent_id: &str, score: u32) {
        let mut agents = self.agents.write().unwrap();
        let state = agents
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentState {
                agent_id: agent_id.to_string(),
                score: self.config.initial_score,
                interactions: 0,
            });
        state.score = score.min(1000);
        drop(agents);
        self.save_to_disk();
    }

    /// Return trust scores for all tracked agents.
    pub fn all_agents(&self) -> Vec<TrustScore> {
        self.agents
            .read()
            .unwrap()
            .values()
            .map(|s| TrustScore {
                agent_id: s.agent_id.clone(),
                score: s.score,
                tier: TrustTier::from_score(s.score),
                interactions: s.interactions,
            })
            .collect()
    }

    /// Best-effort load from persistence file.
    fn load_from_disk(&self) {
        if let Some(path) = &self.config.persist_path {
            if let Ok(data) = std::fs::read_to_string(path) {
                if let Ok(states) = serde_json::from_str::<Vec<AgentState>>(&data) {
                    let mut agents = self.agents.write().unwrap();
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
            let agents = self.agents.read().unwrap();
            let states: Vec<&AgentState> = agents.values().collect();
            if let Ok(json) = serde_json::to_string(&states) {
                let _ = std::fs::write(path, json);
            }
        }
    }
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
}
