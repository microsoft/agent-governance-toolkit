# Governance for GitHub-Based Plugin Marketplaces

⚠️ **IMPORTANT:** This is a SAMPLE integration example provided as a starting point.
You MUST review, customize, and extend these configurations for your specific
use case before deploying to production.

## Overview

This example demonstrates how to integrate the Agent Governance Toolkit into a
GitHub-based plugin marketplace. Plugins are contributed via pull requests,
validated automatically in CI, and promoted through environments (dev → staging →
production) only after passing governance checks.

The pattern enforces:

- **MCP server allowlists** — only approved servers may be referenced by plugins
- **Plugin type restrictions** — control which plugin categories are accepted
- **Signature requirements** — require Ed25519 signatures in production
- **Tool safety rules** — block dangerous tools and enforce token budgets
- **Batch evaluation** — scan all plugins on every PR for policy drift

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  Plugin Marketplace (GitHub)                  │
│                                                              │
│  contributor ──► Pull Request ──► CI Governance Pipeline      │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                   PR Workflow                          │  │
│  │                                                        │  │
│  │  ┌──────────────┐   ┌───────────────┐   ┌──────────┐  │  │
│  │  │   Validate   │──►│   Evaluate    │──►│  Verify  │  │  │
│  │  │   Manifest   │   │    Policy     │   │ Governance│  │  │
│  │  └──────────────┘   └───────────────┘   └──────────┘  │  │
│  │        │                    │                  │        │  │
│  │        ▼                    ▼                  ▼        │  │
│  │  plugin.json         marketplace-       governance     │  │
│  │  schema check        policy.yaml        attestation    │  │
│  │                      plugin-safety.yaml                │  │
│  └────────────────────────────────────────────────────────┘  │
│                              │                               │
│                    ┌─────────┴─────────┐                     │
│                    ▼                   ▼                      │
│              ✅ Compliant        ❌ Non-compliant             │
│              Merge + promote     Block PR                     │
│              to environment      with annotations             │
└──────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
examples/marketplace-governance/
├── README.md                              # This file
├── .github/
│   └── workflows/
│       └── plugin-governance.yml          # CI workflow for PR validation
├── policies/
│   ├── marketplace-policy.yaml            # MCP allowlist and plugin controls
│   └── plugin-safety.yaml                 # Tool restrictions and token budgets
└── plugins/
    ├── example-compliant/
    │   └── plugin.json                    # Passes all governance checks
    └── example-non-compliant/
        └── plugin.json                    # Uses a blocked MCP server
```

## Step-by-Step Integration Guide

### 1. Add Governance Policies to Your Repo

Copy the policy files from `policies/` into your marketplace repository:

```bash
cp -r policies/ your-marketplace/policies/
```

The two policy files serve different purposes:

| File | Purpose |
|------|---------|
| `marketplace-policy.yaml` | Controls which MCP servers, plugin types, and signing requirements are enforced |
| `plugin-safety.yaml` | Agent-level safety rules — tool restrictions, file access auditing, token budgets |

See the inline comments in each file for customization guidance.

### 2. Add the GitHub Action to Your PR Workflow

Copy `.github/workflows/plugin-governance.yml` into your repository. The workflow
triggers on pull requests that modify files under `plugins/` and runs three jobs:

1. **validate-manifest** — Checks that each changed plugin has a valid `plugin.json`
2. **evaluate-policy** — Evaluates all plugins against `marketplace-policy.yaml`
3. **governance-verify** — Runs the full governance attestation suite

```yaml
- uses: microsoft/agent-governance-toolkit/action@v2
  with:
    command: marketplace-verify
    manifest-path: plugins/my-plugin/plugin.json
```

### 3. Configure Marketplace Policy

Edit `policies/marketplace-policy.yaml` to match your marketplace:

- **MCP server allowlist** — Add the MCP servers your marketplace trusts
  (e.g., `code-search`, `ms-learn`, `playwright`). Any plugin referencing an
  unlisted server will be rejected.
- **Plugin types** — Restrict to the types you accept (`integration`, `agent`,
  `policy_template`, `validator`).
- **Signature requirements** — Set `require_signature: true` for production to
  enforce Ed25519 plugin signing.

### 4. Configure Plugin Safety Policy

Edit `policies/plugin-safety.yaml` to define agent-level safety rules:

- **Tool restrictions** — Block dangerous tools like `shell_exec`, `eval`, and
  `file_delete` to prevent destructive actions.
- **Audit rules** — Log sensitive operations (e.g., file access) without
  blocking them.
- **Token budgets** — Cap the maximum tokens per tool call to prevent runaway
  costs.

### 5. Add Pre-Commit Hooks for Local Feedback

Give plugin contributors fast local feedback before they push:

```bash
# Install the toolkit
pip install agent-governance-toolkit[full]

# Validate a single manifest
python -m agent_marketplace.cli_commands verify plugins/my-plugin/plugin.json

# Batch-evaluate all plugins against policy
python -m agent_marketplace.batch evaluate-batch plugins/ \
  --policy policies/marketplace-policy.yaml \
  --format text
```

You can wire this into a Git pre-commit hook or use [pre-commit](https://pre-commit.com/).

## Customization Points

| What | Where | Notes |
|------|-------|-------|
| Allowed MCP servers | `policies/marketplace-policy.yaml` → `mcp_servers.allowed` | Add/remove servers as your trust boundary changes |
| Blocked MCP servers | `policies/marketplace-policy.yaml` → `mcp_servers.blocked` | Use blocklist mode for open marketplaces |
| Plugin type restrictions | `policies/marketplace-policy.yaml` → `allowed_plugin_types` | Remove to allow all types |
| Signature enforcement | `policies/marketplace-policy.yaml` → `require_signature` | `false` for dev, `true` for production |
| Dangerous tool rules | `policies/plugin-safety.yaml` → `rules[]` | Add rules matching your security posture |
| Token budgets | `policies/plugin-safety.yaml` → `rules[]` | Adjust `max_tokens` per your cost tolerance |
| CI trigger paths | `.github/workflows/plugin-governance.yml` → `paths` | Narrow or widen the trigger scope |
| Toolkit version | Action input `toolkit-version` | Pin to a specific version for reproducibility |
| Output format | Action input `output-format` | `json` for machine-readable, `text` for human-readable |

## Related Tutorials

- [Tutorial 07 — MCP Security Gateway](../../docs/tutorials/07-mcp-security-gateway.md):
  Deep dive into MCP server allowlisting and tool-poisoning detection
- [Tutorial 10 — Plugin Marketplace](../../docs/tutorials/10-plugin-marketplace.md):
  End-to-end plugin lifecycle — discovery, installation, verification, and signing
- [Tutorial 18 — Compliance Verification](../../docs/tutorials/18-compliance-verification.md):
  Governance attestation and compliance evidence generation

## Related

- [Policies](../policies/) — Additional sample governance policies
- [Quickstart](../quickstart/) — One-file governed agents for popular frameworks
