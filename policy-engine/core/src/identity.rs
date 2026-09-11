// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Policy input digest retained by AGT.
//!
//! The embedded engine exposed `action_identity`, a SHA-256 over the
//! canonical JSON form of a policy input document. The agent-hooks
//! contract owns context identity now and offers
//! `agent_hooks::context_identity`, but that function takes an
//! `AgentContext` and projects a different preimage, so it is not a drop
//! in replacement for callers holding a policy input `JsonValue`.
//!
//! This keeps the original digest available for one deprecation cycle.
//! New code should take identity from the agent-hooks context instead.

use agent_control_spec::{canonical_json, JsonValue};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// SHA-256 over the canonical JSON encoding of `value`, prefixed
/// `sha256:`.
///
/// Deprecated. Context identity is owned by the agent-hooks contract in
/// AGENT-HOOKS-0.1 section 10. Use `agent_hooks::context_identity` with
/// the `AgentContext` the host already holds.
#[deprecated(
    since = "0.3.2-beta.0",
    note = "context identity is owned by agent-hooks; use agent_hooks::context_identity"
)]
pub fn action_identity(value: &JsonValue) -> Result<String, serde_json::Error> {
    let canonical = canonical_json(value)?;
    let digest = Sha256::digest(canonical.as_bytes());
    let mut hex = String::with_capacity(71);
    hex.push_str("sha256:");
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    #[allow(deprecated)]
    fn identity_is_stable_under_key_reordering() {
        let ordered = json!({"a": 1, "b": 2});
        let reordered = json!({"b": 2, "a": 1});
        assert_eq!(
            action_identity(&ordered).unwrap(),
            action_identity(&reordered).unwrap()
        );
    }

    #[test]
    #[allow(deprecated)]
    fn identity_distinguishes_value_types() {
        let numeric = json!({"amount": 10});
        let string = json!({"amount": "10"});
        assert_ne!(
            action_identity(&numeric).unwrap(),
            action_identity(&string).unwrap()
        );
    }

    #[test]
    #[allow(deprecated)]
    fn identity_is_sha256_prefixed() {
        let identity = action_identity(&json!({})).unwrap();
        assert!(identity.starts_with("sha256:"));
        assert_eq!(identity.len(), 71);
    }
}
