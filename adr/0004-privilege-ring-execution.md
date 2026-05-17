# ADR-0004: Privilege Ring Execution Model

## Status

Accepted

## Context

Autonomous agents executing tool calls (file writes, API calls, database queries) need isolation boundaries. Without execution sandboxing, a compromised or misbehaving agent has the same privileges as the host process.

The sandboxing model must:

- Provide graduated isolation levels (not all agents need maximum isolation)
- Support multiple backends (Docker, ACA, process-level, hypervisor)
- Define blast radius before an incident, not after
- Be policy-driven (sandbox level determined by governance rules)

Options considered:

1. **Binary sandbox/no-sandbox**: Too coarse. Most agents need some isolation but not full containerization.
2. **OS-level process isolation only**: Lightweight but insufficient for network or filesystem restrictions.
3. **Privilege rings (graduated levels)**: Inspired by CPU privilege rings. Multiple isolation levels from in-process (ring 0) to full VM isolation (ring 3).

## Decision

Implement a privilege ring model with four levels:

| Ring | Isolation Level | Use Case |
|------|----------------|----------|
| 0 | In-process | Trusted, first-party agents with full access |
| 1 | Process-level | Semi-trusted agents with filesystem/network restrictions |
| 2 | Container-level | Untrusted agents in Docker/ACA sandbox with resource limits |
| 3 | VM/hypervisor | High-risk agents in full VM isolation |

The execution ring is determined by the governance policy. Each ring has a declared blast radius: the maximum set of resources the agent can touch, documented in the policy file.

Sandbox providers are pluggable: Docker, Azure Container Apps, process-level, and hypervisor backends implement a common interface.

## Consequences

- **Easier**: Graduated security posture (no "all or nothing" choice), blast radius is a policy config not a post-incident discovery, consistent interface across providers
- **Harder**: Multiple sandbox backends to maintain and test. Ring transitions (promoting/demoting an agent mid-session) add complexity. Performance overhead increases with ring level.

## References

- `agent-governance-python/agent-sandbox/src/agent_sandbox/`
- `agent-governance-python/agent-hypervisor/src/agent_hypervisor/`
- Issue #2185: Docker exec_run memory exhaustion (fixed with streaming output)
