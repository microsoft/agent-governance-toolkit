// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `check` subcommand — evaluate a request against a policy and reflect the decision
//! in the process exit code.
//!
//! Mirrors the toolkit's existing `check-policy` surface (Python openshell skill):
//! reads `--policy <file>` and `--input <json>`, prints a one-line JSON result to
//! stdout, and exits `0` when the action is allowed, `1` when it is not. Genuine input
//! errors (malformed `--input`, missing `action`, unreadable/invalid policy) are
//! fail-closed: `error:` on stderr with exit `2` — never a default-allow.

use std::collections::HashMap;

use agentmesh::policy::PolicyEngine;
use agentmesh::types::PolicyDecision;

use crate::error::CliError;

/// The `--input` JSON request: an action plus optional rule-matching context.
#[derive(serde::Deserialize)]
struct CheckInput {
    action: String,
    #[serde(default)]
    context: Option<HashMap<String, serde_yaml::Value>>,
}

/// Returns the intended process exit code: 0 if allowed, 1 if not allowed.
/// Input/policy errors are returned as a `CliError` with exit code 2.
pub fn run(policy: &str, input: &str) -> Result<i32, CliError> {
    let request: CheckInput = serde_json::from_str(input)
        .map_err(|err| CliError::usage(format!("invalid --input JSON: {err}")))?;

    let engine = PolicyEngine::new();
    engine
        .load_from_file(policy)
        .map_err(|err| CliError::usage(format!("invalid policy '{policy}': {err}")))?;

    let decision = engine.evaluate(&request.action, request.context.as_ref());
    let (allowed, label, detail) = match &decision {
        PolicyDecision::Allow => (true, "allow", None),
        PolicyDecision::Deny(reason) => (false, "deny", Some(reason.clone())),
        PolicyDecision::RequiresApproval(reason) => {
            (false, "requires_approval", Some(reason.clone()))
        }
        PolicyDecision::RateLimited { retry_after_secs } => (
            false,
            "rate_limited",
            Some(format!("retry_after_secs={retry_after_secs}")),
        ),
    };

    let result = serde_json::json!({
        "allowed": allowed,
        "action": request.action,
        "decision": label,
        "detail": detail,
    });
    println!(
        "{}",
        serde_json::to_string(&result)
            .map_err(|err| CliError::failure(format!("failed to serialize output: {err}")))?
    );

    Ok(if allowed { 0 } else { 1 })
}
