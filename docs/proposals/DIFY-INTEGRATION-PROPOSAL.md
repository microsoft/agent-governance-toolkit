---
title: "Dify — AgentMesh Trust Layer Plugin"
last_reviewed: 2026-07-16
owner: agt-maintainers
---

# Dify — AgentMesh Trust Layer Plugin

**Submission:** [langgenius/dify#32079](https://github.com/langgenius/dify/pull/32079)
**Status:** Closed without merge. No public follow-up plugin submission was found.
**Type:** Historical integration proposal
**Date Submitted:** February 6, 2026

---

## Summary

The proposal added an AgentMesh trust extension to Dify for cryptographic
identity and trust verification. A Dify maintainer closed the pull request and
redirected the author to the separate plugin repository. The author stated that
a plugin submission would follow, but no public submission or marketplace
listing was found.

## 4 Tools Proposed

| Tool | Description |
|------|-------------|
| **verify_peer** | Verify another agent's identity and capabilities using Ed25519 cryptographic signatures |
| **verify_step** | Check if an agent is authorized to execute a specific workflow step |
| **get_identity** | Get this agent's cryptographic identity (DID + public key) to share with peers |
| **record_interaction** | Record success/failure to dynamically update trust scores |

## Why This Matters

In multi-agent workflows, agents need to verify "who" they're communicating with. This plugin provides:
- **Ed25519 cryptographic identity** (DIDs) for each agent
- **Trust scoring** (0.0–1.0) based on behavioral history
- **Capability-based access control** per workflow step
- **Full audit logging** of trust decisions

## Proposed Privacy & Data

- No personal user data collected
- Operates entirely locally within the Dify environment
- Agent DIDs generated locally via Ed25519
- Trust scores stored in-memory
- Audit logs stored in-memory, not persisted externally

## Links

- [Dify Plugins](https://github.com/langgenius/dify-plugins)
- [Agent Mesh](https://github.com/microsoft/agent-governance-toolkit)
- [Closed Dify Core Proposal](https://github.com/langgenius/dify/pull/32079)
