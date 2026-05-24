// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! clap (derive) command surface for the `agt` operator CLI.

use clap::{Parser, Subcommand, ValueEnum};

/// Operator CLI for the Agent Governance Toolkit (check, policy, audit, trust).
#[derive(Parser, Debug)]
#[command(name = "agt", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Evaluate a request against a policy; exit code reflects the decision.
    Check {
        /// Path to the policy YAML file.
        #[arg(long)]
        policy: String,
        /// JSON request object: {"action": "<str>", "context"?: {<obj>}}.
        #[arg(long)]
        input: String,
    },
    /// Policy operations (validate, explain).
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Audit log operations (tail, export).
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Trust store operations (show, set).
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum TrustCommand {
    /// Show an agent's trust score from a file-backed store.
    Show {
        /// Agent identifier.
        agent_id: String,
        /// Path to the JSON trust store file.
        #[arg(long)]
        store: String,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Set an agent's trust score (0..=1000) in a file-backed store.
    Set {
        /// Agent identifier.
        agent_id: String,
        /// Trust score in the range 0..=1000.
        score: u32,
        /// Path to the JSON trust store file.
        #[arg(long)]
        store: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuditCommand {
    /// Print the last N entries of a serialized audit log file.
    Tail {
        /// Path to a JSON audit log (the array produced by `AuditLogger::export_json`).
        path: String,
        /// Maximum number of trailing entries to print.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Read an audit log file and re-emit it as JSON or NDJSON.
    Export {
        /// Path to a JSON audit log file.
        path: String,
        /// Output format.
        #[arg(long, value_enum, default_value_t = AuditFormat::Json)]
        format: AuditFormat,
    },
}

/// Output format for `audit export`. Distinct from `Format` — an audit export is
/// always structured (JSON array or one JSON object per line), never free text.
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum AuditFormat {
    /// A single JSON array of entries.
    Json,
    /// Newline-delimited JSON — one entry object per line.
    Ndjson,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommand {
    /// Parse and validate a policy file; exit non-zero on schema/regex errors.
    Validate {
        /// Path to the policy YAML file.
        path: String,
    },
    /// Show the policy decision for a sample action and optional context.
    Explain {
        /// Path to the policy YAML file.
        path: String,
        /// The action to evaluate (e.g. `data.read`).
        #[arg(long)]
        action: String,
        /// Optional JSON object of context key/values matched against rule conditions.
        #[arg(long)]
        context: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
}

/// Output format for machine-readable subcommands.
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Format {
    /// Human-readable text (default).
    Text,
    /// A single JSON object.
    Json,
}
