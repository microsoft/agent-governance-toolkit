// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use agentmesh::{AgentMeshClient, ClientOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy_yaml = r#"
version: "1.0"
agent: quickstart-agent
policies:
  - name: quickstart
    type: capability
    allowed_actions:
      - "data.read"
    denied_actions:
      - "shell:*"
"#;

    let client = AgentMeshClient::with_options(
        "quickstart-agent",
        ClientOptions {
            policy_yaml: Some(policy_yaml.to_string()),
            capabilities: vec!["data.read".to_string()],
            ..Default::default()
        },
    )?;

    for action in ["data.read", "shell:rm"] {
        let result = client.execute_with_governance(action, None);
        println!(
            "{action}: allowed={}, decision={:?}, trust_score={}",
            result.allowed, result.decision, result.trust_score.score
        );
    }

    Ok(())
}
