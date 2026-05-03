// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use agentmesh::{AuditFilter, AuditLogger};

fn main() {
    let logger = AuditLogger::new();

    // Append entries to the tamper-evident hash chain.
    logger.log("agent-1", "data.read", "allow");
    logger.log("agent-1", "shell:rm", "deny");
    logger.log("agent-2", "deploy.prod", "requires_approval");

    // Query entries for one agent.
    let filter = AuditFilter {
        agent_id: Some("agent-1".to_string()),
        ..Default::default()
    };
    let agent_entries = logger.get_entries(&filter);
    println!("agent-1 entries: {}", agent_entries.len());

    // Verify the chain before exporting evidence.
    println!("audit chain valid: {}", logger.verify());
    println!("{}", logger.export_json());
}
