# Hacker News Submission

## Title (max 80 chars)
Show HN: AgentMesh – Open-source governance platform for AI agent ecosystems

## URL
https://github.com/microsoft/agent-governance-toolkit

## Text (if self-post)

We're open-sourcing AgentMesh, a governance platform for multi-agent AI systems.

**The problem:** Non-human identities outnumber humans 40:1 in enterprises. AI agents are the fastest-growing, least-governed category. A2A and MCP give agents protocols to talk—but no trust layer.

**What AgentMesh does:**
- Identity: Cryptographic agent IDs with human sponsor accountability
- Trust: Protocol-native verification (A2A, MCP, IATP) with <200ms handshakes  
- Governance: Declarative policies with EU AI Act/SOC2/HIPAA mapping
- Reward: Continuous behavioral scoring (not static blocklists)

**Key insight:** Every other governance tool uses static rules. AgentMesh's Reward Engine scores actions across 5 dimensions and updates trust scores in real-time. When score drops, credentials auto-revoke.

**Quick start:**
```
pip install agentmesh-platform
agentmesh init --name my-agent --sponsor you@company.com
```

30 seconds to a governed agent with 15-min credential TTL, tamper-evident audit logs, and policy enforcement.

Built on agent-os-kernel (also open source). Apache 2.0.

Looking for feedback and design partners running multi-agent systems.

---

## Suggested comments to prepare

### On "Why not just use existing IAM?"
Traditional IAM was designed for humans: long-lived accounts, password resets, annual reviews. Agents are ephemeral, autonomous, delegate to sub-agents, and can escalate blast radius in seconds. Treating agents like service accounts misses the threat model.

### On "What's the network effect?"
An AgentMesh agent auto-rejects requests from unverified agents. The error includes: "Register at AgentMesh to establish handshake." Every deployment becomes a lead magnet for the network.

### On "How is this different from guardrails?"
Guardrails are static—blocklists, keyword filters. AgentMesh learns. The Reward Engine detects behavioral patterns and adjusts trust scores continuously. Static rules can't adapt to novel attacks.

### On "Does this add latency?"
Policy evaluation: <5ms. Trust handshake: <200ms. Credential validation: <1ms. Designed for real-time agent communication.

### On "Why open source?"
Trust infrastructure needs to be a public good. If you're going to trust your agents to a governance layer, you need to verify the code. Apache 2.0.
