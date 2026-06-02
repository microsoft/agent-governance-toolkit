// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `audit` subcommand handlers.
//!
//! These read a serialized audit log — the JSON array of `AuditEntry` produced by
//! `agentmesh::audit::AuditLogger::export_json` — and re-emit it. Fail-closed: a
//! missing or malformed file exits 1 with a structured error.
//!
//! Limitation: the CLI does NOT re-verify the audit hash chain. `AuditLogger::verify`
//! operates on in-memory state and the hashing is private, so `tail`/`export` treat the
//! file as serialized transport only; it does not re-verify the hash chain.

use std::fs;

use agentmesh::types::AuditEntry;

use crate::cli::{AuditCommand, AuditFormat};
use crate::error::CliError;

pub fn run(cmd: AuditCommand) -> Result<(), CliError> {
    match cmd {
        AuditCommand::Tail { path, limit } => tail(&path, limit),
        AuditCommand::Export { path, format } => export(&path, format),
    }
}

/// Read and deserialize an audit log file, mapping IO/parse errors to fail-closed.
fn load(path: &str) -> Result<Vec<AuditEntry>, CliError> {
    let data = fs::read_to_string(path)
        .map_err(|err| CliError::failure(format!("cannot read audit file '{path}': {err}")))?;
    serde_json::from_str::<Vec<AuditEntry>>(&data)
        .map_err(|err| CliError::failure(format!("invalid audit log '{path}': {err}")))
}

fn tail(path: &str, limit: usize) -> Result<(), CliError> {
    let entries = load(path)?;
    if entries.is_empty() {
        println!("no entries");
        return Ok(());
    }
    // Bounded: `saturating_sub` makes a limit larger than the log a no-op clamp.
    let start = entries.len().saturating_sub(limit);
    for entry in &entries[start..] {
        println!(
            "{seq}\t{ts}\t{agent}\t{action}\t{decision}",
            seq = entry.seq,
            ts = entry.timestamp,
            agent = entry.agent_id,
            action = entry.action,
            decision = entry.decision,
        );
    }
    Ok(())
}

fn export(path: &str, format: AuditFormat) -> Result<(), CliError> {
    let entries = load(path)?;
    match format {
        AuditFormat::Json => {
            let out = serde_json::to_string_pretty(&entries)
                .map_err(|err| CliError::failure(format!("failed to serialize output: {err}")))?;
            println!("{out}");
        }
        AuditFormat::Ndjson => {
            for entry in &entries {
                let line = serde_json::to_string(entry).map_err(|err| {
                    CliError::failure(format!("failed to serialize output: {err}"))
                })?;
                println!("{line}");
            }
        }
    }
    Ok(())
}
