# PR Triage Spray Detection

This GitHub Action detects inauthentic contributor patterns, such as "credibility laundering."

Malicious actors (often using AI) sometimes submit a low-effort PR to a well-known project, get it merged, and then immediately file issues across multiple other repositories citing that merge as evidence of their "traction" or "credentials."

This action detects these coordinated network/spray patterns by analyzing the author's activity across a configurable list of repositories.

## Usage

```yaml
name: PR Triage
on:
  issues:
    types: [opened]
  pull_request:
    types: [opened]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: microsoft/agent-governance-toolkit/action/pr-triage@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          spray-threshold: 3
          check-credential-claims: true
          check-cross-repo-spray: true
          monitor-repos: |
            langflow-ai/langflow
            huggingface/smolagents
            camel-ai/camel
```

## Inputs

| Name | Description | Default |
|------|-------------|---------|
| `github-token` | **Required**. GitHub token for querying APIs. | N/A |
| `spray-threshold` | Flag if the user filed similar issues/PRs in X other repos this week. | `3` |
| `check-credential-claims` | Check if the body references merges in other repos. | `true` |
| `check-cross-repo-spray` | Check for cross repo spray patterns. | `true` |
| `monitor-repos` | Newline-separated list of repos to monitor. | `''` |
| `watchlist` | JSON list of known suspicious actors. | `'[]'` |

## Outputs

| Name | Description |
|------|-------------|
| `risk-level` | Calculated risk level (`LOW`, `MEDIUM`, `HIGH`). |
| `spray-detected` | Boolean indicating if a spray pattern was detected. |
| `findings` | JSON structure containing the full analysis. |

## Behavior

If the action determines the risk is `MEDIUM` or `HIGH`, it will automatically:
1. Post a comment on the Issue/PR outlining the suspicious behavior.
2. Apply the `needs-verification` label.
