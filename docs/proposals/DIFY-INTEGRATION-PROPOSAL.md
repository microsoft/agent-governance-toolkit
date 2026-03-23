# Dify — AgentMesh Trust Layer Plugin

**Submission:** [langgenius/dify-plugins#2060](https://github.com/langgenius/dify-plugins/pull/2060)
**Status:** ✅ Shipped — Plugin merged (PR #2060), live on Dify Marketplace
**Type:** Plugin submission (Dify Marketplace)
**Date Submitted:** March 2, 2026

---

## Summary

AgentMesh Trust Layer plugin for Dify that provides cryptographic identity and trust verification for agent workflows. Submitted via the Dify plugin marketplace pipeline per @crazywoola's guidance (redirected from [langgenius/dify#32079](https://github.com/langgenius/dify/pull/32079)).

## 4 Tools Provided

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

## Privacy & Data

- No personal user data collected
- Operates entirely locally within the Dify environment
- Agent DIDs generated locally via Ed25519
- Trust scores stored in-memory
- Audit logs stored in-memory, not persisted externally

## Links

- [Dify Plugins](https://github.com/langgenius/dify-plugins)
- [Agent Mesh](https://github.com/microsoft/agent-governance-toolkit)
- [Plugin Source](https://github.com/microsoft/agent-governance-toolkit/tree/master/integrations/dify-plugin)
