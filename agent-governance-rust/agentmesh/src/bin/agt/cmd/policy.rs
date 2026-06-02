// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `policy` subcommand handlers — thin consumers of `agentmesh::policy::PolicyEngine`.
//!
//! Fail-closed: any parse/validation/IO error returns `Err(CliError)` which `main`
//! maps to a non-zero exit and a structured stderr message. `explain` reports the
//! decision (including a deny) and exits 0 when inputs are valid — a deny is a result,
//! not a CLI failure.

use std::collections::HashMap;

use agentmesh::policy::PolicyEngine;
use agentmesh::types::PolicyDecision;

use crate::cli::{Format, PolicyCommand};
use crate::error::CliError;

pub fn run(cmd: PolicyCommand) -> Result<(), CliError> {
    match cmd {
        PolicyCommand::Validate { path } => validate(&path),
        PolicyCommand::Explain {
            path,
            action,
            context,
            format,
        } => explain(&path, &action, context.as_deref(), format),
    }
}

/// Load a policy file, mapping any `PolicyError` to a fail-closed CLI error.
fn load(path: &str) -> Result<PolicyEngine, CliError> {
    let engine = PolicyEngine::new();
    engine
        .load_from_file(path)
        .map_err(|err| CliError::failure(format!("invalid policy '{path}': {err}")))?;
    Ok(engine)
}

fn validate(path: &str) -> Result<(), CliError> {
    load(path)?;
    println!("valid: {path}");
    Ok(())
}

fn explain(
    path: &str,
    action: &str,
    context: Option<&str>,
    format: Format,
) -> Result<(), CliError> {
    let engine = load(path)?;

    let context_map: Option<HashMap<String, serde_yaml::Value>> = match context {
        Some(raw) => Some(
            serde_json::from_str(raw)
                .map_err(|err| CliError::failure(format!("invalid --context JSON: {err}")))?,
        ),
        None => None,
    };

    let decision = engine.evaluate(action, context_map.as_ref());
    let (label, detail) = describe(&decision);

    match format {
        Format::Text => {
            println!("action: {action}");
            println!("decision: {label}");
            if let Some(detail) = detail {
                println!("detail: {detail}");
            }
        }
        Format::Json => {
            let obj = serde_json::json!({
                "action": action,
                "decision": label,
                "detail": detail,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&obj).map_err(|err| CliError::failure(format!(
                    "failed to serialize output: {err}"
                )))?
            );
        }
    }

    Ok(())
}

/// Map a `PolicyDecision` to a stable label and optional detail string.
fn describe(decision: &PolicyDecision) -> (&'static str, Option<String>) {
    match decision {
        PolicyDecision::Allow => ("allow", None),
        PolicyDecision::Deny(reason) => ("deny", Some(reason.clone())),
        PolicyDecision::RequiresApproval(reason) => ("requires_approval", Some(reason.clone())),
        PolicyDecision::RateLimited { retry_after_secs } => (
            "rate_limited",
            Some(format!("retry_after_secs={retry_after_secs}")),
        ),
    }
}
