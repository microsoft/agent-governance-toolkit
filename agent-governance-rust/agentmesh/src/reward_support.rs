// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Reward and learning primitives layered on top of trust and governance signals.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

fn reward_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionType {
    PolicyCompliance,
    ResourceEfficiency,
    OutputQuality,
    SecurityPosture,
    CollaborationHealth,
}

impl DimensionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PolicyCompliance => "policy_compliance",
            Self::ResourceEfficiency => "resource_efficiency",
            Self::OutputQuality => "output_quality",
            Self::SecurityPosture => "security_posture",
            Self::CollaborationHealth => "collaboration_health",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardSignal {
    pub dimension: DimensionType,
    pub value: f64,
    pub source: String,
    pub details: Option<String>,
    pub trace_id: Option<String>,
    pub timestamp_secs: u64,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardDimension {
    pub name: String,
    pub score: f64,
    pub signal_count: u32,
    pub positive_signals: u32,
    pub negative_signals: u32,
    pub previous_score: Option<f64>,
    pub trend: String,
    pub updated_at_secs: u64,
}

impl RewardDimension {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            score: 50.0,
            signal_count: 0,
            positive_signals: 0,
            negative_signals: 0,
            previous_score: None,
            trend: "stable".to_string(),
            updated_at_secs: reward_now(),
        }
    }

    pub fn add_signal(&mut self, signal: &RewardSignal) {
        self.signal_count += 1;
        if signal.value >= 0.5 {
            self.positive_signals += 1;
        } else {
            self.negative_signals += 1;
        }
        self.previous_score = Some(self.score);
        self.score = (self.score * 0.9) + (signal.value * 100.0 * 0.1);
        self.trend = match self.previous_score {
            Some(previous) if self.score - previous > 5.0 => "improving".to_string(),
            Some(previous) if self.score - previous < -5.0 => "degrading".to_string(),
            _ => "stable".to_string(),
        };
        self.updated_at_secs = reward_now();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardTrustScore {
    pub agent_did: String,
    pub total_score: u32,
    pub tier: String,
    pub dimensions: HashMap<String, RewardDimension>,
    pub calculated_at_secs: u64,
    pub previous_score: Option<u32>,
    pub score_change: i32,
}

impl RewardTrustScore {
    pub fn new(agent_did: &str) -> Self {
        let mut score = Self {
            agent_did: agent_did.to_string(),
            total_score: 500,
            tier: "standard".to_string(),
            dimensions: HashMap::new(),
            calculated_at_secs: reward_now(),
            previous_score: None,
            score_change: 0,
        };
        score.update_tier();
        score
    }

    pub fn update(&mut self, new_score: u32, dimensions: HashMap<String, RewardDimension>) {
        self.previous_score = Some(self.total_score);
        self.total_score = new_score.min(1000);
        self.score_change = self.total_score as i32 - self.previous_score.unwrap_or(0) as i32;
        self.dimensions = dimensions;
        self.calculated_at_secs = reward_now();
        self.update_tier();
    }

    fn update_tier(&mut self) {
        self.tier = match self.total_score {
            900..=1000 => "verified_partner",
            700..=899 => "trusted",
            500..=699 => "standard",
            300..=499 => "probationary",
            _ => "untrusted",
        }
        .to_string();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardConfig {
    pub update_interval_seconds: u64,
    pub revocation_threshold: u32,
    pub warning_threshold: u32,
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            update_interval_seconds: 30,
            revocation_threshold: 200,
            warning_threshold: 400,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRewardState {
    pub agent_did: String,
    pub trust_score: RewardTrustScore,
    pub dimensions: HashMap<String, RewardDimension>,
    pub recent_signals: Vec<RewardSignal>,
    pub score_history: Vec<(u64, u32)>,
    pub last_updated_secs: u64,
    pub revoked: bool,
    pub revocation_reason: Option<String>,
}

impl AgentRewardState {
    pub fn new(agent_did: &str) -> Self {
        Self {
            agent_did: agent_did.to_string(),
            trust_score: RewardTrustScore::new(agent_did),
            dimensions: HashMap::new(),
            recent_signals: Vec::new(),
            score_history: Vec::new(),
            last_updated_secs: reward_now(),
            revoked: false,
            revocation_reason: None,
        }
    }
}

pub struct RewardEngine {
    config: RewardConfig,
    agents: Mutex<HashMap<String, AgentRewardState>>,
}

impl RewardEngine {
    pub fn new(config: Option<RewardConfig>) -> Self {
        Self {
            config: config.unwrap_or_default(),
            agents: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_agent_score(&self, agent_did: &str) -> RewardTrustScore {
        self.get_or_create_state(agent_did).trust_score.clone()
    }

    pub fn record_signal(
        &self,
        agent_did: &str,
        dimension: DimensionType,
        value: f64,
        source: &str,
        details: Option<&str>,
    ) {
        let mut agents = self.agents.lock().unwrap_or_else(|e| e.into_inner());
        let state = agents
            .entry(agent_did.to_string())
            .or_insert_with(|| AgentRewardState::new(agent_did));
        let signal = RewardSignal {
            dimension,
            value: value.clamp(0.0, 1.0),
            source: source.to_string(),
            details: details.map(|d| d.to_string()),
            trace_id: None,
            timestamp_secs: reward_now(),
            weight: 1.0,
        };
        state.recent_signals.push(signal.clone());
        state
            .dimensions
            .entry(dimension.as_str().to_string())
            .or_insert_with(|| RewardDimension::new(dimension.as_str()))
            .add_signal(&signal);
        self.recalculate_locked(state);
    }

    pub fn record_policy_compliance(
        &self,
        agent_did: &str,
        compliant: bool,
        policy_name: Option<&str>,
    ) {
        self.record_signal(
            agent_did,
            DimensionType::PolicyCompliance,
            if compliant { 1.0 } else { 0.0 },
            "policy_engine",
            policy_name,
        );
    }

    pub fn record_resource_usage(
        &self,
        agent_did: &str,
        tokens_used: u32,
        tokens_budget: u32,
        compute_ms: u32,
        compute_budget_ms: u32,
    ) {
        let token_efficiency = (tokens_budget as f64 / tokens_used.max(1) as f64).min(1.0);
        let compute_efficiency = (compute_budget_ms as f64 / compute_ms.max(1) as f64).min(1.0);
        self.record_signal(
            agent_did,
            DimensionType::ResourceEfficiency,
            (token_efficiency + compute_efficiency) / 2.0,
            "resource_monitor",
            None,
        );
    }

    pub fn record_output_quality(
        &self,
        agent_did: &str,
        accepted: bool,
        consumer: &str,
        reason: Option<&str>,
    ) {
        self.record_signal(
            agent_did,
            DimensionType::OutputQuality,
            if accepted { 1.0 } else { 0.0 },
            &format!("consumer:{consumer}"),
            reason,
        );
    }

    pub fn record_security_event(&self, agent_did: &str, within_boundary: bool, event_type: &str) {
        self.record_signal(
            agent_did,
            DimensionType::SecurityPosture,
            if within_boundary { 1.0 } else { 0.0 },
            "security_monitor",
            Some(event_type),
        );
    }

    pub fn record_collaboration(&self, agent_did: &str, handoff_successful: bool, peer_did: &str) {
        self.record_signal(
            agent_did,
            DimensionType::CollaborationHealth,
            if handoff_successful { 1.0 } else { 0.0 },
            &format!("collaboration:{peer_did}"),
            None,
        );
    }

    fn get_or_create_state(&self, agent_did: &str) -> AgentRewardState {
        self.agents
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(agent_did.to_string())
            .or_insert_with(|| AgentRewardState::new(agent_did))
            .clone()
    }

    fn recalculate_locked(&self, state: &mut AgentRewardState) {
        let dimension_average = if state.dimensions.is_empty() {
            50.0
        } else {
            state.dimensions.values().map(|dim| dim.score).sum::<f64>()
                / state.dimensions.len() as f64
        };
        let new_score = (dimension_average * 10.0).round() as u32;
        state
            .trust_score
            .update(new_score, state.dimensions.clone());
        state
            .score_history
            .push((reward_now(), state.trust_score.total_score));
        state.last_updated_secs = reward_now();
        if state.trust_score.total_score < self.config.revocation_threshold {
            state.revoked = true;
            state.revocation_reason = Some("reward score below revocation threshold".to_string());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEvent {
    pub agent_did: String,
    pub event_type: String,
    pub severity_weight: f64,
    pub timestamp_secs: u64,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionEdge {
    pub from_did: String,
    pub to_did: String,
    pub interaction_count: u32,
}

impl InteractionEdge {
    pub fn weight(&self) -> f64 {
        (self.interaction_count as f64 / 100.0).min(1.0)
    }
}

pub struct NetworkTrustEngine {
    scores: Mutex<HashMap<String, f64>>,
    edges: Mutex<HashMap<(String, String), InteractionEdge>>,
}

impl NetworkTrustEngine {
    pub fn new() -> Self {
        Self {
            scores: Mutex::new(HashMap::new()),
            edges: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_score(&self, agent_did: &str) -> f64 {
        *self
            .scores
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(agent_did)
            .unwrap_or(&500.0)
    }

    pub fn record_interaction(&self, from_did: &str, to_did: &str) {
        let key = (from_did.to_string(), to_did.to_string());
        let mut edges = self.edges.lock().unwrap_or_else(|e| e.into_inner());
        edges
            .entry(key)
            .and_modify(|edge| edge.interaction_count += 1)
            .or_insert_with(|| InteractionEdge {
                from_did: from_did.to_string(),
                to_did: to_did.to_string(),
                interaction_count: 1,
            });
    }

    pub fn process_trust_event(&self, event: TrustEvent) -> HashMap<String, f64> {
        let mut deltas = HashMap::new();
        {
            let mut scores = self.scores.lock().unwrap_or_else(|e| e.into_inner());
            let direct = event.severity_weight * 100.0;
            let entry = scores.entry(event.agent_did.clone()).or_insert(500.0);
            *entry = (*entry - direct).max(0.0);
            deltas.insert(event.agent_did.clone(), -direct);
        }
        let edges = self.edges.lock().unwrap_or_else(|e| e.into_inner()).clone();
        for ((from, to), edge) in edges {
            if from == event.agent_did || to == event.agent_did {
                let peer = if from == event.agent_did { to } else { from };
                let propagated = event.severity_weight * edge.weight() * 30.0;
                let mut scores = self.scores.lock().unwrap_or_else(|e| e.into_inner());
                let entry = scores.entry(peer.clone()).or_insert(500.0);
                *entry = (*entry - propagated).max(0.0);
                deltas.insert(peer, -propagated);
            }
        }
        deltas
    }
}

impl Default for NetworkTrustEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantInfo {
    pub agent_did: String,
    pub trust_score: u32,
    pub delegation_depth: u32,
    pub contribution_weight: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardPool {
    pub total_reward: f64,
    pub task_id: String,
    pub participants: Vec<ParticipantInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardAllocation {
    pub agent_did: String,
    pub amount: f64,
    pub percentage: f64,
    pub strategy_used: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionResult {
    pub task_id: String,
    pub strategy: String,
    pub allocations: Vec<RewardAllocation>,
    pub total_distributed: f64,
}

pub trait RewardStrategy: Send + Sync {
    fn distribute(&self, pool: &RewardPool) -> DistributionResult;
}

pub struct EqualSplitStrategy;

impl RewardStrategy for EqualSplitStrategy {
    fn distribute(&self, pool: &RewardPool) -> DistributionResult {
        let n = pool.participants.len();
        if n == 0 {
            return DistributionResult {
                task_id: pool.task_id.clone(),
                strategy: "equal".to_string(),
                allocations: Vec::new(),
                total_distributed: 0.0,
            };
        }
        let share = pool.total_reward / n as f64;
        DistributionResult {
            task_id: pool.task_id.clone(),
            strategy: "equal".to_string(),
            allocations: pool
                .participants
                .iter()
                .map(|participant| RewardAllocation {
                    agent_did: participant.agent_did.clone(),
                    amount: share,
                    percentage: 100.0 / n as f64,
                    strategy_used: "equal".to_string(),
                })
                .collect(),
            total_distributed: pool.total_reward,
        }
    }
}

pub struct TrustWeightedStrategy;

impl RewardStrategy for TrustWeightedStrategy {
    fn distribute(&self, pool: &RewardPool) -> DistributionResult {
        let total_trust = pool
            .participants
            .iter()
            .map(|p| p.trust_score as f64)
            .sum::<f64>();
        let allocations = pool
            .participants
            .iter()
            .map(|participant| {
                let share = if total_trust > 0.0 {
                    participant.trust_score as f64 / total_trust
                } else {
                    0.0
                };
                RewardAllocation {
                    agent_did: participant.agent_did.clone(),
                    amount: pool.total_reward * share,
                    percentage: share * 100.0,
                    strategy_used: "trust_weighted".to_string(),
                }
            })
            .collect::<Vec<_>>();
        DistributionResult {
            task_id: pool.task_id.clone(),
            strategy: "trust_weighted".to_string(),
            total_distributed: allocations.iter().map(|item| item.amount).sum(),
            allocations,
        }
    }
}

pub struct HierarchicalStrategy {
    pub decay_factor: f64,
}

impl Default for HierarchicalStrategy {
    fn default() -> Self {
        Self { decay_factor: 0.7 }
    }
}

impl RewardStrategy for HierarchicalStrategy {
    fn distribute(&self, pool: &RewardPool) -> DistributionResult {
        let weights = pool
            .participants
            .iter()
            .map(|participant| self.decay_factor.powi(participant.delegation_depth as i32))
            .collect::<Vec<_>>();
        let total_weight = weights.iter().sum::<f64>();
        let allocations = pool
            .participants
            .iter()
            .zip(weights.iter())
            .map(|(participant, weight)| {
                let share = if total_weight > 0.0 {
                    weight / total_weight
                } else {
                    0.0
                };
                RewardAllocation {
                    agent_did: participant.agent_did.clone(),
                    amount: pool.total_reward * share,
                    percentage: share * 100.0,
                    strategy_used: "hierarchical".to_string(),
                }
            })
            .collect::<Vec<_>>();
        DistributionResult {
            task_id: pool.task_id.clone(),
            strategy: "hierarchical".to_string(),
            total_distributed: allocations.iter().map(|item| item.amount).sum(),
            allocations,
        }
    }
}

pub struct ContributionWeightedStrategy;

impl RewardStrategy for ContributionWeightedStrategy {
    fn distribute(&self, pool: &RewardPool) -> DistributionResult {
        let total_weight = pool
            .participants
            .iter()
            .map(|participant| participant.contribution_weight.unwrap_or(0.0))
            .sum::<f64>();
        let allocations = pool
            .participants
            .iter()
            .map(|participant| {
                let weight = participant.contribution_weight.unwrap_or(0.0);
                let share = if total_weight > 0.0 {
                    weight / total_weight
                } else {
                    0.0
                };
                RewardAllocation {
                    agent_did: participant.agent_did.clone(),
                    amount: pool.total_reward * share,
                    percentage: share * 100.0,
                    strategy_used: "contribution".to_string(),
                }
            })
            .collect::<Vec<_>>();
        DistributionResult {
            task_id: pool.task_id.clone(),
            strategy: "contribution".to_string(),
            total_distributed: allocations.iter().map(|item| item.amount).sum(),
            allocations,
        }
    }
}

pub struct RewardDistributor {
    default_strategy: String,
    strategies: HashMap<String, Box<dyn RewardStrategy>>,
}

impl RewardDistributor {
    pub fn new(default_strategy: Option<&str>) -> Self {
        let mut strategies: HashMap<String, Box<dyn RewardStrategy>> = HashMap::new();
        strategies.insert("equal".to_string(), Box::new(EqualSplitStrategy));
        strategies.insert(
            "trust_weighted".to_string(),
            Box::new(TrustWeightedStrategy),
        );
        strategies.insert(
            "hierarchical".to_string(),
            Box::new(HierarchicalStrategy::default()),
        );
        strategies.insert(
            "contribution".to_string(),
            Box::new(ContributionWeightedStrategy),
        );
        Self {
            default_strategy: default_strategy.unwrap_or("trust_weighted").to_string(),
            strategies,
        }
    }

    pub fn register_strategy(&mut self, name: &str, strategy: Box<dyn RewardStrategy>) {
        self.strategies.insert(name.to_string(), strategy);
    }

    pub fn distribute(
        &self,
        pool: &RewardPool,
        strategy_name: Option<&str>,
    ) -> Result<DistributionResult, String> {
        let strategy = self
            .strategies
            .get(strategy_name.unwrap_or(&self.default_strategy))
            .ok_or_else(|| "unknown reward strategy".to_string())?;
        Ok(strategy.distribute(pool))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reward_engine_tracks_dimensions() {
        let engine = RewardEngine::new(None);
        engine.record_policy_compliance("did:mesh:agent", true, Some("baseline"));
        engine.record_security_event("did:mesh:agent", false, "boundary breach");
        let score = engine.get_agent_score("did:mesh:agent");
        assert!(score.dimensions.contains_key("policy_compliance"));
        assert!(score.dimensions.contains_key("security_posture"));
    }

    #[test]
    fn network_trust_engine_propagates() {
        let engine = NetworkTrustEngine::new();
        engine.record_interaction("a", "b");
        let deltas = engine.process_trust_event(TrustEvent {
            agent_did: "a".into(),
            event_type: "policy_violation".into(),
            severity_weight: 0.8,
            timestamp_secs: reward_now(),
            details: None,
        });
        assert!(deltas.contains_key("a"));
        assert!(deltas.contains_key("b"));
    }

    #[test]
    fn reward_distributor_supports_trust_weighted() {
        let distributor = RewardDistributor::new(None);
        let result = distributor
            .distribute(
                &RewardPool {
                    total_reward: 100.0,
                    task_id: "task-1".into(),
                    participants: vec![
                        ParticipantInfo {
                            agent_did: "a".into(),
                            trust_score: 800,
                            delegation_depth: 0,
                            contribution_weight: None,
                        },
                        ParticipantInfo {
                            agent_did: "b".into(),
                            trust_score: 200,
                            delegation_depth: 1,
                            contribution_weight: None,
                        },
                    ],
                },
                Some("trust_weighted"),
            )
            .unwrap();
        assert_eq!(result.allocations.len(), 2);
        assert!(result.allocations[0].amount > result.allocations[1].amount);
    }
}
