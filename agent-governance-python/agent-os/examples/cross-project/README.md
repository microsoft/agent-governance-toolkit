# Cross-Project Example: Agent-OS + Agent-Mesh

Demonstrates how Agent-OS and Agent-Mesh work together for full-stack AI governance.

| Layer | Role | Project |
|-------|------|---------|
| **Local governance** | Policy enforcement, tool limits, content filtering, flight recording | [Agent-OS](https://github.com/microsoft/agent-governance-toolkit) |
| **Inter-agent governance** | Trust scoring, DID identity, capability verification, hash-chained audit | [Agent-Mesh](https://github.com/microsoft/agent-governance-toolkit) |

## Run

```bash
python cross_project_example.py
```

## What It Does

1. **Sets up Agent-Mesh** — registers two agents (Researcher, Writer) with DID identities
2. **Sets up Agent-OS** — configures local policies (tool limits, blocked patterns) per agent
3. **Researcher gathers data** — each tool call goes through the Agent-OS kernel gate
4. **Trust handshake** — Agent-Mesh verifies the Writer's identity and capabilities before delegation
5. **Writer produces report** — Agent-OS enforces content policies on the output
6. **Trust update** — Agent-Mesh updates trust scores based on the outcome
7. **Combined audit** — both layers report a unified governance summary

## Architecture

```
Agent-Mesh (inter-agent trust layer)
├── DID identity verification
├── Trust score management (5 dimensions)
├── Capability attestation
└── Hash-chained audit log

Agent-OS (local kernel for each agent)
├── Policy enforcement (blocked patterns, tool limits)
├── Content filtering (input + output)
├── Flight recorder (audit every action)
└── Signal handling (SIGSTOP, SIGKILL)
```

No external dependencies required — the example inlines the minimal core of both projects.
