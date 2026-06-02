// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `trust` subcommand handlers.
//!
//! The library's `TrustManager` persistence is **best-effort and silent**: it ignores
//! `..` paths, swallows write IO errors, and treats a corrupt store as empty; the
//! on-disk type (`AgentState`) is private. Fail-closed semantics therefore cannot be
//! delegated to the library. This handler enforces them in
//! the CLI layer, using only the public `TrustManager` API:
//!
//! 1. reject `..` store paths before any library call;
//! 2. pre-validate an existing store parses as a JSON array (refuse, don't clobber);
//! 3. range-check the score (reject `> 1000`, no silent clamp);
//! 4. read-back-verify after `set` via a fresh `TrustManager` + `all_agents()`.

use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path};

use agentmesh::trust::{TrustConfig, TrustManager};

use crate::cli::{Format, TrustCommand};
use crate::error::CliError;

/// Maximum trust score. The library clamps to this silently; the CLI rejects above it.
const MAX_SCORE: u32 = 1000;

pub fn run(cmd: TrustCommand) -> Result<(), CliError> {
    match cmd {
        TrustCommand::Show {
            agent_id,
            store,
            format,
        } => show(&agent_id, &store, format),
        TrustCommand::Set {
            agent_id,
            score,
            store,
        } => set(&agent_id, score, &store),
    }
}

/// Reject store paths containing `..` (the library silently skips them).
fn reject_parentdir(store: &str) -> Result<(), CliError> {
    if Path::new(store)
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(CliError::failure(format!(
            "store path '{store}' must not contain '..'"
        )));
    }
    Ok(())
}

/// If the store file exists, confirm it parses as a JSON array; a missing file is a
/// valid empty store. Catches gross corruption before the library loads it (and, on
/// `set`, before it would be overwritten).
fn validate_store_shape(store: &str) -> Result<(), CliError> {
    match fs::read_to_string(store) {
        Ok(data) => {
            let value: serde_json::Value = serde_json::from_str(&data).map_err(|err| {
                CliError::failure(format!("corrupt trust store '{store}': {err}"))
            })?;
            if value.is_array() {
                Ok(())
            } else {
                Err(CliError::failure(format!(
                    "corrupt trust store '{store}': expected a JSON array"
                )))
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(CliError::failure(format!(
            "cannot read trust store '{store}': {err}"
        ))),
    }
}

fn manager(store: &str) -> TrustManager {
    TrustManager::new(TrustConfig {
        persist_path: Some(store.to_string()),
        ..Default::default()
    })
}

fn show(agent_id: &str, store: &str, format: Format) -> Result<(), CliError> {
    reject_parentdir(store)?;
    validate_store_shape(store)?;

    let score = manager(store).get_trust_score(agent_id);
    match format {
        Format::Text => {
            println!("agent: {}", score.agent_id);
            println!("score: {}", score.score);
            println!("tier: {:?}", score.tier);
            println!("interactions: {}", score.interactions);
        }
        Format::Json => {
            let out = serde_json::to_string_pretty(&score)
                .map_err(|err| CliError::failure(format!("failed to serialize output: {err}")))?;
            println!("{out}");
        }
    }
    Ok(())
}

fn set(agent_id: &str, score: u32, store: &str) -> Result<(), CliError> {
    reject_parentdir(store)?;
    if score > MAX_SCORE {
        return Err(CliError::failure(format!(
            "score {score} out of range (0..={MAX_SCORE})"
        )));
    }
    // Refuse to overwrite a corrupt store.
    validate_store_shape(store)?;

    manager(store).set_trust(agent_id, score);

    // Read-back verify: the library's save is best-effort/silent, so confirm the value
    // actually landed by loading a fresh manager from the same path.
    let persisted = manager(store)
        .all_agents()
        .into_iter()
        .find(|s| s.agent_id == agent_id);
    match persisted {
        Some(s) if s.score == score => {
            println!("set {agent_id} = {score}");
            Ok(())
        }
        _ => Err(CliError::failure(format!(
            "failed to persist trust score for '{agent_id}' to '{store}' (write not confirmed)"
        ))),
    }
}
