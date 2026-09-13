# Agent Governance Verify — GitHub Action

A GitHub Action that runs governance verification and plugin validation from the
[Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

Add governance as a required CI check with minimal configuration.

## Quick Start

> **Breaking change (vNEXT):** `toolkit-version` is now **required**. Pin to an exact published release (e.g. `3.7.0`); wildcards, floating refs, post-releases (`.post1`), dev-releases (`.dev0`), and local-version identifiers (`+local`) are rejected. See [Accepted version syntax](#accepted-version-syntax) below. Consumers should pin this action to the major-tag they were already using (e.g. `@v3`) and bump `toolkit-version` as new releases ship.

```yaml
- uses: microsoft/agent-governance-toolkit/action@v2
  with:
    toolkit-version: "3.7.0"
```

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

The action installs the pinned OPA runtime used by native Rego policies.

```yaml
- name: Evaluate Policy
  uses: microsoft/agent-governance-toolkit/action@v2
  with:
    command: policy-evaluate
    policy-path: policies/manifest.yaml
    intervention-point: input
    context-json: '{"input": {"body": "Summarize the report"}}'
```

### Full suite (all checks)

```yaml
- name: Full Governance Suite
  uses: microsoft/agent-governance-toolkit/action@v2
  with:
    command: all
    manifest-path: plugins/my-plugin/plugin.json
    policy-path: policies/manifest.yaml
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
| `policy-path` | Path to a native ACS manifest | No | |
| `manifest-path` | Path to plugin manifest | No | |
| `intervention-point` | ACS intervention point for `policy-evaluate` | No | `pre_tool_call` |
| `context-json` | JSON snapshot for `policy-evaluate` | No | |
| `output-format` | Output format: `text`, `json`, `badge` | No | `text` |
| `fail-on-warning` | Fail on warnings (not just errors) | No | `false` |
| `python-version` | Python version to use | No | `3.12` |
| `toolkit-version` | Exact toolkit version to install (e.g. `3.7.0`) | **Yes** | |

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

## Accepted version syntax

The `toolkit-version` input is validated against this regex before installation:

```regex
^[0-9]+\.[0-9]+\.[0-9]+((a|b|rc)[0-9]+)?$
```

Accepted: `3.7.0`, `3.7.0a1`, `3.7.0b2`, `3.7.0rc1`.

Rejected (and why): `3.7.0.post1` / `3.7.0.dev0` (transient pre/post artifacts), `3.7.0+local` (PEP 440 local-version identifiers can override registry resolution under some pip resolvers), `3.7.*` / `>=3.7` (floating), `3.7.0; python_version > '3'` (environment markers), URL/VCS references, and anything else outside the regex above.
