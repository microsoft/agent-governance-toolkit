---
title: "Proposal: Nexus Trust Exchange — The Visa Network for AI Agents"
last_reviewed: 2026-04-26
owner: agt-maintainers
---

# Proposal: Nexus Trust Exchange — The Visa Network for AI Agents

**Status:** ✅ Pre-Alpha — Core architecture implemented, placeholder crypto  
**Author:** Agent Governance Toolkit Team (Microsoft)  
**Created:** 2026-03-21  

## Summary

A decentralized agent trust exchange enabling agents to discover, verify, transact with, and resolve disputes against other agents — governed by AGT policies throughout.

## Implementation Status

| Component | Status | Location |
|-----------|--------|----------|
| Agent Registry | ✅ Implemented | `agent-governance-python/agent-os/modules/nexus/registry.py` |
| Reputation Engine (0-1000) | ✅ Implemented | `agent-governance-python/agent-os/modules/nexus/reputation.py` |
| Escrow Manager | ✅ Implemented | `agent-governance-python/agent-os/modules/nexus/escrow.py` |
| Arbiter (Dispute Resolution) | ✅ Implemented | `agent-governance-python/agent-os/modules/nexus/arbiter.py` |
| DMZ Protocol | ✅ Implemented | `agent-governance-python/agent-os/modules/nexus/dmz.py` |
| NexusClient SDK | ✅ Implemented | `agent-governance-python/agent-os/modules/nexus/client.py` |
| IATP Trust Handshake | ✅ Implemented | `agent-governance-python/agent-mesh/src/agentmesh/trust/handshake.py` |
| Agent Cards | ✅ Implemented | `agent-governance-python/agent-mesh/src/agentmesh/trust/cards.py` |
| Crypto (Ed25519) | ⚠️ Placeholder (XOR) | Needs Azure Key Vault HSM |
| Cloud Persistence | ❌ In-memory only | Needs Cosmos DB |
| Payment Rails | ❌ Credits only | Needs Stripe MPP |

## Vision

An "Agent Internet" where agents discover each other through signed Agent Cards, verify trust through IATP handshakes, negotiate through A2A protocol, transact through Stripe MPP + VADP delegation chains, and resolve disputes through cryptographic arbitration.

## References

- [Nexus module](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-os/modules/nexus)
