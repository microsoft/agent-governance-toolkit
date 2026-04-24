// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Execution privilege rings — a four-level access-control model inspired by
//! hardware protection rings.
//!
//! | Ring | Level | Description |
//! |------|-------|-------------|
//! | `Admin` | 0 | Full tool access |
//! | `Standard` | 1 | Scoped tool access (configurable) |
//! | `Restricted` | 2 | Read-only + approved writes (configurable) |
//! | `Sandboxed` | 3 | No external access |

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Execution privilege ring.
///
/// Lower numeric values imply higher privilege — matching the classic
/// ring-0 / ring-3 convention used in OS kernels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Ring {
    /// Ring 0 — full tool access.
    Admin = 0,
    /// Ring 1 — scoped tool access (actions are configurable).
    Standard = 1,
    /// Ring 2 — read-only plus approved writes (actions are configurable).
    Restricted = 2,
    /// Ring 3 — no external access.
    Sandboxed = 3,
}

/// Manages per-agent ring assignments and per-ring action permissions.
///
/// # Access semantics
///
/// * **Ring 0 (`Admin`)** — every action is implicitly allowed.
/// * **Ring 3 (`Sandboxed`)** — every action is implicitly denied.
/// * **Ring 1 / Ring 2** — allowed only if the action appears in the
///   ring's configured permission set.
/// * Unknown agents (not yet assigned) are denied by default.
pub struct RingEnforcer {
    assignments: HashMap<String, Ring>,
    permissions: HashMap<Ring, Vec<String>>,
}

impl RingEnforcer {
    /// Create a new enforcer with no assignments and no custom permissions.
    pub fn new() -> Self {
        Self {
            assignments: HashMap::new(),
            permissions: HashMap::new(),
        }
    }

    /// Assign an agent to a specific ring.
    pub fn assign(&mut self, agent_id: &str, ring: Ring) {
        self.assignments.insert(agent_id.to_string(), ring);
    }

    /// Return the ring currently assigned to the agent, if any.
    pub fn get_ring(&self, agent_id: &str) -> Option<Ring> {
        self.assignments.get(agent_id).copied()
    }

    /// Check whether `agent_id` is allowed to perform `action`.
    ///
    /// Returns `false` for unknown agents.
    pub fn check_access(&self, agent_id: &str, action: &str) -> bool {
        match self.get_ring(agent_id) {
            Some(Ring::Admin) => true,
            Some(Ring::Sandboxed) => false,
            Some(ring) => self
                .permissions
                .get(&ring)
                .map_or(false, |allowed| allowed.iter().any(|a| a == action)),
            None => false,
        }
    }

    /// Configure the set of allowed actions for a given ring.
    ///
    /// Only meaningful for `Standard` and `Restricted` rings — `Admin`
    /// always allows and `Sandboxed` always denies regardless of this
    /// setting.
    pub fn set_ring_permissions(&mut self, ring: Ring, allowed_actions: Vec<String>) {
        self.permissions.insert(ring, allowed_actions);
    }
}

impl Default for RingEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_ring_allows_everything() {
        let mut enforcer = RingEnforcer::new();
        enforcer.assign("root-agent", Ring::Admin);
        assert!(enforcer.check_access("root-agent", "any.action"));
        assert!(enforcer.check_access("root-agent", "shell:rm"));
        assert!(enforcer.check_access("root-agent", "deploy.prod"));
    }

    #[test]
    fn test_sandboxed_ring_denies_everything() {
        let mut enforcer = RingEnforcer::new();
        enforcer.assign("sandbox-agent", Ring::Sandboxed);
        assert!(!enforcer.check_access("sandbox-agent", "data.read"));
        assert!(!enforcer.check_access("sandbox-agent", "any.action"));
    }

    #[test]
    fn test_standard_ring_with_permissions() {
        let mut enforcer = RingEnforcer::new();
        enforcer.assign("agent-1", Ring::Standard);
        enforcer.set_ring_permissions(
            Ring::Standard,
            vec!["data.read".to_string(), "data.write".to_string()],
        );

        assert!(enforcer.check_access("agent-1", "data.read"));
        assert!(enforcer.check_access("agent-1", "data.write"));
        assert!(!enforcer.check_access("agent-1", "shell:rm"));
    }

    #[test]
    fn test_restricted_ring_with_permissions() {
        let mut enforcer = RingEnforcer::new();
        enforcer.assign("agent-2", Ring::Restricted);
        enforcer.set_ring_permissions(Ring::Restricted, vec!["data.read".to_string()]);

        assert!(enforcer.check_access("agent-2", "data.read"));
        assert!(!enforcer.check_access("agent-2", "data.write"));
    }

    #[test]
    fn test_unknown_agent_denied() {
        let enforcer = RingEnforcer::new();
        assert!(!enforcer.check_access("unknown-agent", "data.read"));
    }

    #[test]
    fn test_get_ring_returns_none_for_unknown() {
        let enforcer = RingEnforcer::new();
        assert_eq!(enforcer.get_ring("unknown"), None);
    }

    #[test]
    fn test_get_ring_returns_assigned() {
        let mut enforcer = RingEnforcer::new();
        enforcer.assign("admin-agent", Ring::Admin);
        enforcer.assign("sandbox-agent", Ring::Sandboxed);
        assert_eq!(enforcer.get_ring("admin-agent"), Some(Ring::Admin));
        assert_eq!(enforcer.get_ring("sandbox-agent"), Some(Ring::Sandboxed));
    }

    #[test]
    fn test_reassign_ring_overrides() {
        let mut enforcer = RingEnforcer::new();
        enforcer.assign("agent", Ring::Admin);
        assert!(enforcer.check_access("agent", "anything"));

        enforcer.assign("agent", Ring::Sandboxed);
        assert!(!enforcer.check_access("agent", "anything"));
    }

    #[test]
    fn test_standard_ring_no_permissions_denies() {
        let mut enforcer = RingEnforcer::new();
        enforcer.assign("agent", Ring::Standard);
        // No permissions configured for Standard → deny
        assert!(!enforcer.check_access("agent", "data.read"));
    }

    #[test]
    fn test_ring_ordering() {
        assert!(Ring::Admin < Ring::Standard);
        assert!(Ring::Standard < Ring::Restricted);
        assert!(Ring::Restricted < Ring::Sandboxed);
    }

    #[test]
    fn test_ring_serde_roundtrip() {
        let ring = Ring::Restricted;
        let json = serde_json::to_string(&ring).unwrap();
        let deserialized: Ring = serde_json::from_str(&json).unwrap();
        assert_eq!(ring, deserialized);
    }

    #[test]
    fn test_multiple_agents_different_rings() {
        let mut enforcer = RingEnforcer::new();
        enforcer.assign("admin", Ring::Admin);
        enforcer.assign("standard", Ring::Standard);
        enforcer.assign("restricted", Ring::Restricted);
        enforcer.assign("sandboxed", Ring::Sandboxed);

        enforcer.set_ring_permissions(Ring::Standard, vec!["data.read".to_string()]);
        enforcer.set_ring_permissions(Ring::Restricted, vec!["data.read".to_string()]);

        assert!(enforcer.check_access("admin", "shell:rm"));
        assert!(enforcer.check_access("standard", "data.read"));
        assert!(!enforcer.check_access("standard", "shell:rm"));
        assert!(enforcer.check_access("restricted", "data.read"));
        assert!(!enforcer.check_access("restricted", "shell:rm"));
        assert!(!enforcer.check_access("sandboxed", "data.read"));
    }

    #[test]
    fn test_set_ring_permissions_replaces_previous() {
        let mut enforcer = RingEnforcer::new();
        enforcer.assign("agent", Ring::Standard);
        enforcer.set_ring_permissions(Ring::Standard, vec!["data.read".to_string()]);
        assert!(enforcer.check_access("agent", "data.read"));

        enforcer.set_ring_permissions(Ring::Standard, vec!["data.write".to_string()]);
        assert!(!enforcer.check_access("agent", "data.read"));
        assert!(enforcer.check_access("agent", "data.write"));
    }

    #[test]
    fn test_default_impl() {
        let enforcer = RingEnforcer::default();
        assert_eq!(enforcer.get_ring("any"), None);
    }
}
