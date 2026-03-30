# Agent Governance Verify — GitHub Action

A GitHub Action that runs governance verification and plugin validation from the
[Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

Add governance as a required CI check with minimal configuration.

## Quick Start

```yaml
- uses: microsoft/agent-governance-toolkit/action@v2
```

That's it — runs `agent-compliance verify` against your repo.

## Usage Examples

### Governance verification (OWASP ASI compliance)

```yaml
- name: Governance Check
  uses: microsoft/agent-governance-toolkit/action@v2
  with:
    command: governance-verify
    output-format: json
```

### Plugin manifest validation

```yaml
- name: Verify Plugin
  uses: microsoft/agent-governance-toolkit/action@v2
  with:
    command: marketplace-verify
    manifest-path: plugins/my-plugin/plugin.json
```

### Policy evaluation

```yaml
- name: Evaluate Policy
  uses: microsoft/agent-governance-toolkit/action@v2
  with:
    command: policy-evaluate
    policy-path: policies/
    context-json: '{"tool_name": "web_search", "agent_id": "agent-1"}'
```

### Full suite (all checks)

```yaml
- name: Full Governance Suite
  uses: microsoft/agent-governance-toolkit/action@v2
  with:
    command: all
    manifest-path: plugins/my-plugin/plugin.json
    policy-path: policies/
```

### Plugin marketplace PR workflow

```yaml
name: Plugin Governance
on:
  pull_request:
    paths: ['plugins/**']

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Verify plugin manifest
        uses: microsoft/agent-governance-toolkit/action@v2
        id: verify
        with:
          command: marketplace-verify
          manifest-path: plugins/${{ github.event.pull_request.title }}/plugin.json

      - name: Governance compliance
        uses: microsoft/agent-governance-toolkit/action@v2
        with:
          command: governance-verify
          output-format: json
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `command` | Verification to run: `governance-verify`, `marketplace-verify`, `policy-evaluate`, `all` | No | `governance-verify` |
| `policy-path` | Path to YAML policy file(s) | No | |
| `manifest-path` | Path to plugin manifest | No | |
| `context-json` | JSON evaluation context for `policy-evaluate` | No | |
| `output-format` | Output format: `text`, `json`, `badge` | No | `text` |
| `fail-on-warning` | Fail on warnings (not just errors) | No | `false` |
| `python-version` | Python version to use | No | `3.12` |
| `toolkit-version` | Toolkit version to install (default: latest) | No | |

## Outputs

| Output | Description |
|--------|-------------|
| `status` | `pass` or `fail` |
| `controls-passed` | Controls passed (governance-verify) |
| `controls-total` | Total controls checked (governance-verify) |
| `violations` | Violation count (policy-evaluate) |
| `output` | Full command output |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | One or more checks failed |
