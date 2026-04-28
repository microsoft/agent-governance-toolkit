// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Control-plane and resilience primitives for kill switches, SLOs, and circuit breaking.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

fn control_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchReason {
    PolicyViolation,
    SecurityIncident,
    OperatorRequest,
    ErrorBudgetExhausted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchEvent {
    pub active: bool,
    pub reason: KillSwitchReason,
    pub message: Option<String>,
    pub timestamp_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchScope {
    Global,
    Agent(String),
    Capability(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchDecision {
    pub allowed: bool,
    pub scope: Option<KillSwitchScope>,
    pub event: Option<KillSwitchEvent>,
}

pub struct KillSwitch {
    state: Mutex<Option<KillSwitchEvent>>,
}

impl KillSwitch {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }

    pub fn activate(&self, reason: KillSwitchReason, message: Option<&str>) -> KillSwitchEvent {
        let event = KillSwitchEvent {
            active: true,
            reason,
            message: message.map(|value| value.to_string()),
            timestamp_secs: control_now(),
        };
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = Some(event.clone());
        event
    }

    pub fn clear(&self, reason: KillSwitchReason, message: Option<&str>) -> KillSwitchEvent {
        let event = KillSwitchEvent {
            active: false,
            reason,
            message: message.map(|value| value.to_string()),
            timestamp_secs: control_now(),
        };
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = Some(event.clone());
        event
    }

    pub fn is_active(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|event| event.active)
            .unwrap_or(false)
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

pub struct KillSwitchRegistry {
    switches: Mutex<HashMap<KillSwitchScope, KillSwitch>>,
    history: Mutex<Vec<(KillSwitchScope, KillSwitchEvent)>>,
}

impl KillSwitchRegistry {
    pub fn new() -> Self {
        Self {
            switches: Mutex::new(HashMap::new()),
            history: Mutex::new(Vec::new()),
        }
    }

    fn with_switch<T>(&self, scope: &KillSwitchScope, op: impl FnOnce(&KillSwitch) -> T) -> T {
        let mut switches = self.switches.lock().unwrap_or_else(|e| e.into_inner());
        let switch_ref = switches
            .entry(scope.clone())
            .or_insert_with(KillSwitch::new);
        op(switch_ref)
    }

    pub fn activate(
        &self,
        scope: KillSwitchScope,
        reason: KillSwitchReason,
        message: Option<&str>,
    ) -> KillSwitchEvent {
        let event = self.with_switch(&scope, |kill_switch| kill_switch.activate(reason, message));
        self.history
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((scope, event.clone()));
        event
    }

    pub fn clear(
        &self,
        scope: KillSwitchScope,
        reason: KillSwitchReason,
        message: Option<&str>,
    ) -> KillSwitchEvent {
        let event = self.with_switch(&scope, |kill_switch| kill_switch.clear(reason, message));
        self.history
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((scope, event.clone()));
        event
    }

    pub fn decision_for(
        &self,
        agent_id: Option<&str>,
        capability: Option<&str>,
    ) -> KillSwitchDecision {
        let scopes = [
            KillSwitchScope::Global,
            agent_id
                .map(|id| KillSwitchScope::Agent(id.to_string()))
                .unwrap_or_else(|| KillSwitchScope::Agent(String::new())),
            capability
                .map(|value| KillSwitchScope::Capability(value.to_string()))
                .unwrap_or_else(|| KillSwitchScope::Capability(String::new())),
        ];
        for scope in scopes
            .into_iter()
            .filter(|scope| !matches!(scope, KillSwitchScope::Agent(value) if value.is_empty()))
            .filter(
                |scope| !matches!(scope, KillSwitchScope::Capability(value) if value.is_empty()),
            )
        {
            let maybe_event = self.with_switch(&scope, |kill_switch| {
                if kill_switch.is_active() {
                    kill_switch
                        .state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone()
                } else {
                    None
                }
            });
            if let Some(event) = maybe_event {
                return KillSwitchDecision {
                    allowed: false,
                    scope: Some(scope),
                    event: Some(event),
                };
            }
        }
        KillSwitchDecision {
            allowed: true,
            scope: None,
            event: None,
        }
    }

    pub fn history(&self) -> Vec<(KillSwitchScope, KillSwitchEvent)> {
        self.history
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl Default for KillSwitchRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceLevelObjective {
    pub name: String,
    pub target_percentage: f64,
    pub window_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBudget {
    pub objective: ServiceLevelObjective,
    pub consumed_percentage: f64,
}

impl ErrorBudget {
    pub fn remaining_percentage(&self) -> f64 {
        (100.0 - self.consumed_percentage).max(0.0)
    }

    pub fn exhausted(&self) -> bool {
        self.consumed_percentage >= (100.0 - self.objective.target_percentage)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectiveEvaluation {
    pub objective: ServiceLevelObjective,
    pub total_events: usize,
    pub successful_events: usize,
    pub budget: ErrorBudget,
    pub status: HealthStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealthReport {
    pub generated_at_secs: u64,
    pub overall_status: HealthStatus,
    pub evaluations: Vec<ObjectiveEvaluation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRecord {
    pub incident_id: String,
    pub objective_name: String,
    pub started_at_secs: u64,
    pub status: HealthStatus,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

pub struct SloEngine {
    evaluations: Mutex<Vec<(u64, bool)>>,
}

impl SloEngine {
    pub fn new() -> Self {
        Self {
            evaluations: Mutex::new(Vec::new()),
        }
    }

    pub fn record(&self, success: bool) {
        self.evaluations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((control_now(), success));
    }

    pub fn evaluate(&self, objective: &ServiceLevelObjective) -> ErrorBudget {
        let cutoff = control_now().saturating_sub(objective.window_seconds);
        let evaluations = self.evaluations.lock().unwrap_or_else(|e| e.into_inner());
        Self::budget_from_evaluations(objective, &evaluations, cutoff)
    }

    pub fn health_status(&self, objective: &ServiceLevelObjective) -> HealthStatus {
        let budget = self.evaluate(objective);
        if budget.exhausted() {
            HealthStatus::Unhealthy
        } else if budget.consumed_percentage > (100.0 - objective.target_percentage) / 2.0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }

    pub fn evaluate_objective(&self, objective: &ServiceLevelObjective) -> ObjectiveEvaluation {
        let cutoff = control_now().saturating_sub(objective.window_seconds);
        let evaluations = self.evaluations.lock().unwrap_or_else(|e| e.into_inner());
        let within_window = evaluations
            .iter()
            .filter(|(timestamp, _)| *timestamp >= cutoff)
            .collect::<Vec<_>>();
        let successful_events = within_window.iter().filter(|(_, success)| *success).count();
        let total_events = within_window.len();
        let budget = Self::budget_from_evaluations(objective, &evaluations, cutoff);
        let status = if budget.exhausted() {
            HealthStatus::Unhealthy
        } else if budget.consumed_percentage > (100.0 - objective.target_percentage) / 2.0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };
        ObjectiveEvaluation {
            objective: objective.clone(),
            total_events,
            successful_events,
            budget,
            status,
        }
    }

    pub fn evaluate_all(&self, objectives: &[ServiceLevelObjective]) -> ServiceHealthReport {
        let evaluations = objectives
            .iter()
            .map(|objective| self.evaluate_objective(objective))
            .collect::<Vec<_>>();
        let overall_status = if evaluations
            .iter()
            .any(|evaluation| evaluation.status == HealthStatus::Unhealthy)
        {
            HealthStatus::Unhealthy
        } else if evaluations
            .iter()
            .any(|evaluation| evaluation.status == HealthStatus::Degraded)
        {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };
        ServiceHealthReport {
            generated_at_secs: control_now(),
            overall_status,
            evaluations,
        }
    }

    pub fn incident_for(&self, objective: &ServiceLevelObjective) -> Option<IncidentRecord> {
        let evaluation = self.evaluate_objective(objective);
        (evaluation.status != HealthStatus::Healthy).then(|| IncidentRecord {
            incident_id: format!("incident_{:012x}", rand::random::<u64>()),
            objective_name: objective.name.clone(),
            started_at_secs: control_now(),
            status: evaluation.status,
            summary: format!(
                "objective '{}' is {:?} with {:.2}% budget consumed",
                objective.name, evaluation.status, evaluation.budget.consumed_percentage
            ),
        })
    }

    fn budget_from_evaluations(
        objective: &ServiceLevelObjective,
        evaluations: &[(u64, bool)],
        cutoff: u64,
    ) -> ErrorBudget {
        let within_window = evaluations
            .iter()
            .filter(|(timestamp, _)| *timestamp >= cutoff)
            .collect::<Vec<_>>();
        let total = within_window.len().max(1) as f64;
        let failures = within_window
            .iter()
            .filter(|(_, success)| !*success)
            .count() as f64;
        ErrorBudget {
            objective: objective.clone(),
            consumed_percentage: (failures / total) * 100.0,
        }
    }
}

impl Default for SloEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    failure_threshold: usize,
    window_size: usize,
    recovery_successes: usize,
    state: Mutex<CircuitState>,
    history: Mutex<VecDeque<bool>>,
    consecutive_recovery_successes: Mutex<usize>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: usize, window_size: usize) -> Self {
        Self::with_recovery(failure_threshold, window_size, 1)
    }

    pub fn with_recovery(
        failure_threshold: usize,
        window_size: usize,
        recovery_successes: usize,
    ) -> Self {
        Self {
            failure_threshold,
            window_size: window_size.max(1),
            recovery_successes: recovery_successes.max(1),
            state: Mutex::new(CircuitState::Closed),
            history: Mutex::new(VecDeque::new()),
            consecutive_recovery_successes: Mutex::new(0),
        }
    }

    pub fn record(&self, success: bool) {
        let mut history = self.history.lock().unwrap_or_else(|e| e.into_inner());
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut recovery_successes = self
            .consecutive_recovery_successes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match *state {
            CircuitState::Open if success => {
                *recovery_successes = 1;
                *state = CircuitState::HalfOpen;
                return;
            }
            CircuitState::HalfOpen
                if success && *recovery_successes + 1 >= self.recovery_successes =>
            {
                *recovery_successes = 0;
                *state = CircuitState::Closed;
                history.clear();
                return;
            }
            CircuitState::HalfOpen if success => {
                *recovery_successes += 1;
                return;
            }
            CircuitState::HalfOpen => {
                *recovery_successes = 0;
                *state = CircuitState::Open;
                return;
            }
            _ => {}
        }
        history.push_back(success);
        while history.len() > self.window_size {
            history.pop_front();
        }
        let failures = history.iter().filter(|result| !**result).count();
        if failures >= self.failure_threshold {
            *recovery_successes = 0;
            *state = CircuitState::Open;
        } else {
            *state = CircuitState::Closed;
        }
    }

    pub fn allow(&self) -> bool {
        !matches!(
            *self.state.lock().unwrap_or_else(|e| e.into_inner()),
            CircuitState::Open
        )
    }

    pub fn state(&self) -> CircuitState {
        *self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_switch_toggles() {
        let kill_switch = KillSwitch::new();
        kill_switch.activate(KillSwitchReason::SecurityIncident, Some("breach"));
        assert!(kill_switch.is_active());
        kill_switch.clear(KillSwitchReason::OperatorRequest, Some("resolved"));
        assert!(!kill_switch.is_active());
    }

    #[test]
    fn kill_switch_registry_blocks_scoped_requests() {
        let registry = KillSwitchRegistry::new();
        registry.activate(
            KillSwitchScope::Agent("did:mesh:agent-1".into()),
            KillSwitchReason::PolicyViolation,
            Some("deny until review"),
        );

        let decision = registry.decision_for(Some("did:mesh:agent-1"), None);
        assert!(!decision.allowed);
        assert!(matches!(decision.scope, Some(KillSwitchScope::Agent(_))));
    }

    #[test]
    fn slo_engine_reports_health() {
        let engine = SloEngine::new();
        for _ in 0..8 {
            engine.record(true);
        }
        for _ in 0..2 {
            engine.record(false);
        }
        let objective = ServiceLevelObjective {
            name: "availability".into(),
            target_percentage: 99.0,
            window_seconds: 3600,
        };
        let budget = engine.evaluate(&objective);
        assert!(budget.consumed_percentage > 0.0);
    }

    #[test]
    fn slo_engine_builds_service_report() {
        let engine = SloEngine::new();
        for _ in 0..9 {
            engine.record(true);
        }
        engine.record(false);
        let objective = ServiceLevelObjective {
            name: "availability".into(),
            target_percentage: 99.0,
            window_seconds: 3600,
        };
        let report = engine.evaluate_all(&[objective]);
        assert_eq!(report.evaluations.len(), 1);
    }

    #[test]
    fn error_budget_exhausts_when_consumed_budget_hits_threshold() {
        let budget = ErrorBudget {
            objective: ServiceLevelObjective {
                name: "availability".into(),
                target_percentage: 99.0,
                window_seconds: 3600,
            },
            consumed_percentage: 1.0,
        };
        assert!(budget.exhausted());
    }

    #[test]
    fn circuit_breaker_opens_after_failures() {
        let breaker = CircuitBreaker::new(3, 5);
        breaker.record(false);
        breaker.record(false);
        breaker.record(false);
        assert_eq!(breaker.state(), CircuitState::Open);
        assert!(!breaker.allow());
    }

    #[test]
    fn circuit_breaker_recovers_after_half_open_successes() {
        let breaker = CircuitBreaker::with_recovery(2, 4, 2);
        breaker.record(false);
        breaker.record(false);
        assert_eq!(breaker.state(), CircuitState::Open);
        breaker.record(true);
        assert_eq!(breaker.state(), CircuitState::HalfOpen);
        breaker.record(true);
        assert_eq!(breaker.state(), CircuitState::Closed);
    }
}
