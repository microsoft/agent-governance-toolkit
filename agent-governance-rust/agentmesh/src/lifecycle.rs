// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Agent lifecycle management -- an eight-state model tracking an agent from
//! provisioning through decommissioning.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// The eight lifecycle states an agent can occupy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LifecycleState {
    /// Agent is being provisioned (initial state).
    Provisioning,
    /// Agent is fully operational.
    Active,
    /// Agent is temporarily suspended.
    Suspended,
    /// Agent credentials are being rotated.
    Rotating,
    /// Agent is running in a degraded mode.
    Degraded,
    /// Agent has been quarantined due to policy violations or anomalies.
    Quarantined,
    /// Agent is in the process of being decommissioned.
    Decommissioning,
    /// Agent has been permanently decommissioned (terminal state).
    Decommissioned,
}

/// A recorded lifecycle transition event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleEvent {
    /// State before the transition.
    pub from: LifecycleState,
    /// State after the transition.
    pub to: LifecycleState,
    /// Human-readable reason for the transition.
    pub reason: String,
    /// Who or what initiated the transition.
    pub initiated_by: String,
    /// Unix timestamp (seconds) when the transition occurred.
    pub timestamp: u64,
}

/// Manages the lifecycle of a single agent.
pub struct LifecycleManager {
    agent_id: String,
    state: LifecycleState,
    events: Vec<LifecycleEvent>,
}

impl LifecycleManager {
    /// Create a new lifecycle manager for the given agent.
    ///
    /// The initial state is [`LifecycleState::Provisioning`].
    pub fn new(agent_id: &str) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            state: LifecycleState::Provisioning,
            events: Vec::new(),
        }
    }

    /// Return the current lifecycle state.
    pub fn state(&self) -> LifecycleState {
        self.state
    }

    /// Return the agent identifier.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Return all recorded lifecycle events.
    pub fn events(&self) -> &[LifecycleEvent] {
        &self.events
    }

    /// Return the most recently recorded lifecycle event, or `None` if the
    /// manager has not transitioned yet.
    pub fn last_event(&self) -> Option<&LifecycleEvent> {
        self.events.last()
    }

    /// Attempt to transition the agent to `to`.
    ///
    /// On success the new [`LifecycleEvent`] is appended to the event log
    /// and can be retrieved via [`Self::last_event`] or [`Self::events`].
    /// Returns an error message describing why the transition is not
    /// allowed otherwise.
    pub fn transition(
        &mut self,
        to: LifecycleState,
        reason: &str,
        initiated_by: &str,
    ) -> Result<(), String> {
        if !self.can_transition(to) {
            return Err(format!(
                "invalid transition from {:?} to {:?}",
                self.state, to
            ));
        }

        let event = LifecycleEvent {
            from: self.state,
            to,
            reason: reason.to_string(),
            initiated_by: initiated_by.to_string(),
            timestamp: epoch_now(),
        };
        self.state = to;
        self.events.push(event);
        Ok(())
    }

    /// Check whether transitioning from the current state to `to` is valid.
    pub fn can_transition(&self, to: LifecycleState) -> bool {
        allowed_transitions(self.state).contains(&to)
    }

    /// Convenience: transition to [`LifecycleState::Active`].
    pub fn activate(&mut self, reason: &str) -> Result<(), String> {
        self.transition(LifecycleState::Active, reason, "system")
    }

    /// Convenience: transition to [`LifecycleState::Suspended`].
    pub fn suspend(&mut self, reason: &str) -> Result<(), String> {
        self.transition(LifecycleState::Suspended, reason, "system")
    }

    /// Convenience: transition to [`LifecycleState::Quarantined`].
    pub fn quarantine(&mut self, reason: &str) -> Result<(), String> {
        self.transition(LifecycleState::Quarantined, reason, "system")
    }

    /// Convenience: transition to [`LifecycleState::Decommissioning`].
    pub fn decommission(&mut self, reason: &str) -> Result<(), String> {
        self.transition(LifecycleState::Decommissioning, reason, "system")
    }
}

/// Return the set of states reachable from `from`.
fn allowed_transitions(from: LifecycleState) -> &'static [LifecycleState] {
    use LifecycleState::*;
    match from {
        Provisioning => &[Active],
        Active => &[Suspended, Rotating, Degraded, Decommissioning],
        Suspended => &[Active, Decommissioning],
        Rotating => &[Active],
        Degraded => &[Active, Quarantined, Decommissioning],
        Quarantined => &[Active, Decommissioning],
        Decommissioning => &[Decommissioned],
        Decommissioned => &[],
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
    fn test_initial_state_is_provisioning() {
        let mgr = LifecycleManager::new("agent-1");
        assert_eq!(mgr.state(), LifecycleState::Provisioning);
        assert_eq!(mgr.agent_id(), "agent-1");
        assert!(mgr.events().is_empty());
    }

    #[test]
    fn test_activate_from_provisioning() {
        let mut mgr = LifecycleManager::new("agent-1");
        mgr.activate("initial activation").unwrap();
        let event = mgr.last_event().expect("activate recorded an event");
        assert_eq!(event.from, LifecycleState::Provisioning);
        assert_eq!(event.to, LifecycleState::Active);
        assert_eq!(event.reason, "initial activation");
        assert_eq!(mgr.state(), LifecycleState::Active);
    }

    #[test]
    fn test_suspend_from_active() {
        let mut mgr = LifecycleManager::new("agent-1");
        mgr.activate("boot").unwrap();
        mgr.suspend("maintenance window").unwrap();
        let event = mgr.last_event().expect("suspend recorded an event");
        assert_eq!(event.from, LifecycleState::Active);
        assert_eq!(event.to, LifecycleState::Suspended);
        assert_eq!(mgr.state(), LifecycleState::Suspended);
    }

    #[test]
    fn test_reactivate_from_suspended() {
        let mut mgr = LifecycleManager::new("agent-1");
        mgr.activate("boot").unwrap();
        mgr.suspend("pause").unwrap();
        mgr.activate("resume").unwrap();
        let event = mgr.last_event().expect("activate recorded an event");
        assert_eq!(event.from, LifecycleState::Suspended);
        assert_eq!(event.to, LifecycleState::Active);
    }

    #[test]
    fn test_quarantine_from_degraded() {
        let mut mgr = LifecycleManager::new("agent-1");
        mgr.activate("boot").unwrap();
        mgr.transition(LifecycleState::Degraded, "high error rate", "monitor")
            .unwrap();
        mgr.quarantine("policy violation detected").unwrap();
        let event = mgr.last_event().expect("quarantine recorded an event");
        assert_eq!(event.from, LifecycleState::Degraded);
        assert_eq!(event.to, LifecycleState::Quarantined);
    }

    #[test]
    fn test_last_event_is_none_before_any_transition() {
        let mgr = LifecycleManager::new("agent-1");
        assert!(mgr.last_event().is_none());
    }

    #[test]
    fn test_decommission_flow() {
        let mut mgr = LifecycleManager::new("agent-1");
        mgr.activate("boot").unwrap();
        mgr.decommission("end of life").unwrap();
        assert_eq!(mgr.state(), LifecycleState::Decommissioning);

        mgr.transition(LifecycleState::Decommissioned, "cleanup done", "system")
            .unwrap();
        assert_eq!(mgr.state(), LifecycleState::Decommissioned);
    }

    #[test]
    fn test_decommissioned_is_terminal() {
        let mut mgr = LifecycleManager::new("agent-1");
        mgr.activate("boot").unwrap();
        mgr.decommission("bye").unwrap();
        mgr.transition(LifecycleState::Decommissioned, "done", "system")
            .unwrap();

        let result = mgr.activate("try again");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("invalid transition from Decommissioned"));
    }

    #[test]
    fn test_invalid_transition_from_provisioning() {
        let mut mgr = LifecycleManager::new("agent-1");
        let result = mgr.suspend("not allowed");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_transition_returns_descriptive_error() {
        let mut mgr = LifecycleManager::new("agent-1");
        let err = mgr.suspend("nope").unwrap_err();
        assert!(err.contains("Provisioning"));
        assert!(err.contains("Suspended"));
    }

    #[test]
    fn test_can_transition_returns_true_for_valid() {
        let mut mgr = LifecycleManager::new("agent-1");
        assert!(mgr.can_transition(LifecycleState::Active));
        assert!(!mgr.can_transition(LifecycleState::Suspended));

        mgr.activate("boot").unwrap();
        assert!(mgr.can_transition(LifecycleState::Suspended));
        assert!(mgr.can_transition(LifecycleState::Rotating));
        assert!(mgr.can_transition(LifecycleState::Degraded));
        assert!(mgr.can_transition(LifecycleState::Decommissioning));
        assert!(!mgr.can_transition(LifecycleState::Quarantined));
    }

    #[test]
    fn test_rotating_returns_to_active() {
        let mut mgr = LifecycleManager::new("agent-1");
        mgr.activate("boot").unwrap();
        mgr.transition(LifecycleState::Rotating, "key rotation", "security")
            .unwrap();
        assert_eq!(mgr.state(), LifecycleState::Rotating);

        mgr.activate("rotation complete").unwrap();
        assert_eq!(mgr.state(), LifecycleState::Active);
    }

    #[test]
    fn test_event_history_records_all_transitions() {
        let mut mgr = LifecycleManager::new("agent-1");
        mgr.activate("boot").unwrap();
        mgr.suspend("pause").unwrap();
        mgr.activate("resume").unwrap();

        let events = mgr.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].to, LifecycleState::Active);
        assert_eq!(events[1].to, LifecycleState::Suspended);
        assert_eq!(events[2].to, LifecycleState::Active);
    }

    #[test]
    fn test_event_timestamps_are_monotonic() {
        let mut mgr = LifecycleManager::new("agent-1");
        mgr.activate("boot").unwrap();
        mgr.suspend("pause").unwrap();
        mgr.activate("resume").unwrap();

        let events = mgr.events();
        for window in events.windows(2) {
            assert!(window[1].timestamp >= window[0].timestamp);
        }
    }

    #[test]
    fn test_lifecycle_state_serde_roundtrip() {
        let state = LifecycleState::Quarantined;
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: LifecycleState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn test_lifecycle_event_serde_roundtrip() {
        let event = LifecycleEvent {
            from: LifecycleState::Active,
            to: LifecycleState::Suspended,
            reason: "maintenance".to_string(),
            initiated_by: "admin".to_string(),
            timestamp: 1700000000,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: LifecycleEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.from, event.from);
        assert_eq!(deserialized.to, event.to);
        assert_eq!(deserialized.reason, event.reason);
    }

    #[test]
    fn test_quarantined_can_reactivate() {
        let mut mgr = LifecycleManager::new("agent-1");
        mgr.activate("boot").unwrap();
        mgr.transition(LifecycleState::Degraded, "issues", "monitor")
            .unwrap();
        mgr.quarantine("violation").unwrap();
        mgr.activate("cleared").unwrap();
        assert_eq!(mgr.state(), LifecycleState::Active);
    }

    #[test]
    fn test_quarantined_can_decommission() {
        let mut mgr = LifecycleManager::new("agent-1");
        mgr.activate("boot").unwrap();
        mgr.transition(LifecycleState::Degraded, "issues", "monitor")
            .unwrap();
        mgr.quarantine("violation").unwrap();
        mgr.decommission("permanent removal").unwrap();
        assert_eq!(mgr.state(), LifecycleState::Decommissioning);
    }
}
