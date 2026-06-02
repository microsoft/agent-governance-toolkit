<!-- BEGIN MICROSOFT SECURITY.MD V1.0.0 BLOCK -->

## Security

Microsoft takes the security of our software products and services seriously, which
includes all source code repositories in our GitHub organizations.

**Please do not report security vulnerabilities through public GitHub issues.**

For security reporting information, locations, contact information, and policies,
please review the latest guidance for Microsoft repositories at
[https://aka.ms/SECURITY.md](https://aka.ms/SECURITY.md).

<!-- END MICROSOFT SECURITY.MD BLOCK -->

## Threat Model

Agent governance tooling occupies a unique position in the security stack: it
sits between autonomous AI agents and the resources they access. Unlike
traditional middleware, the agents AGT governs can reason, adapt, and attempt
to circumvent controls. This creates threat categories that do not exist in
conventional software.

**Trust boundaries:**

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  AI Agent    │────▶│  AGT Policy     │────▶│  Protected       │
│  (untrusted) │     │  Engine         │     │  Resources       │
└──────────────┘     │  (trust anchor) │     └──────────────────┘
                     └─────────────────┘
                           │
                     ┌─────────────────┐
                     │  Audit Log      │
                     │  (tamper-proof) │
                     └─────────────────┘
```

**Key threat categories:**

| Category | Description | AGT mitigation |
|----------|-------------|----------------|
| Policy bypass | Agent crafts inputs that cause the policy engine to permit unauthorized actions | Deterministic evaluation with no LLM in the policy path; formal spec conformance tests |
| Identity spoofing | Agent presents forged credentials or DIDs to impersonate a higher-trust agent | Cryptographic identity verification via AgentMesh identity layer |
| Audit tampering | Attacker modifies or deletes audit records to hide policy violations | Append-only audit log with cryptographic chaining |
| Budget evasion | Agent manipulates cost inputs (NaN, negative values) to bypass spending limits | Input validation rejecting IEEE 754 special values (see advisory below) |
| Tool-call injection | Malicious MCP server returns tool results designed to manipulate agent behavior | MCP Security Gateway with allowlist/denylist enforcement |
| Supply chain compromise | Compromised dependency introduces backdoor into policy evaluation | SLSA build provenance, dependency review, weekly security audits |
| Privilege escalation via delegation | Agent delegates to a sub-agent that has broader permissions than the parent | Delegation chain verification with trust score attenuation |

**Operator guidance:**

- Run AGT's policy engine as a separate process or sidecar, not embedded in the
  agent's own process. This prevents a compromised agent from modifying policy
  evaluation logic.
- Enable audit logging to an external, append-only store. Agents should not have
  write access to their own audit logs.
- Use the MCP Security Gateway for any agent that calls external tools. Review
  tool server configurations before deployment.
- Pin AGT dependency versions and verify SLSA provenance attestations.

## Security Contact

To report a vulnerability, email **secure@microsoft.com**. You will receive acknowledgement
within 24 hours and a detailed response within 72 hours indicating next steps.

## Scope

The following components are in scope for security reports:

- **Policy engine** (agent_os): policy bypass, evaluation errors, deterministic guarantee violations
- **Identity layer** (agentmesh): DID/key material leaks, trust score manipulation, attestation forgery
- **Sandbox** (agent_sandbox): guest escape, host resource access, isolation boundary violations
- **Supply chain** (CI/CD, publishing): build tampering, dependency confusion, secret exposure
- **Compliance tooling** (agent_compliance): false negatives in security scanning

Out of scope:
- Denial of service against local CLI tools (e.g., `agt` commands)
- Issues in third-party dependencies already tracked by Dependabot
- Social engineering or phishing attacks against maintainers

## Severity Definitions

| Severity | Description | Example |
|----------|-------------|---------|
| Critical | Remote exploitation, data exfiltration, or complete policy bypass without authentication | Sandbox escape allowing host code execution |
| High | Policy bypass under specific conditions, credential exposure, or trust boundary violation | Kill switch bypass via crafted IEEE 754 values |
| Medium | Race conditions, information disclosure, or partial bypass requiring local access | Thread safety issue in concurrent policy evaluation |
| Low | Minor information leak, hardening gap, or defense-in-depth improvement | Missing input validation on non-security path |

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 3.4.x   | :white_check_mark: |
| 3.3.x   | :white_check_mark: |
| 3.2.x   | :white_check_mark: |
| < 3.2   | :x:                |

## Disclosure Policy

We follow a **90-day coordinated disclosure** timeline. After a vulnerability is
reported and confirmed, we will:

1. Acknowledge receipt within **24 hours**.
2. Provide a fix or mitigation within **90 days**.
3. Coordinate public disclosure with the reporter after the fix is released.

If a fix requires more than 90 days, we will negotiate an extended timeline with
the reporter before any public disclosure.

## Security Advisories

### CostGuard Organization Kill Switch Bypass (Fixed in v2.1.0)

**Severity:** High
**Affected versions:** < 2.1.0
**Fixed in:** v2.1.0 (PR #272)

A crafted input using IEEE 754 special values (NaN, Infinity, negative numbers) to
CostGuard budget parameters could bypass the organization-level kill switch, allowing
agents to continue operating after the budget threshold was exceeded.

**Fix:** Input validation now rejects NaN/Inf/negative values. The `_org_killed` flag
persists kill state permanently — once the organization budget threshold is crossed,
all agents are blocked including newly created ones.

**Recommendation:** Upgrade to v2.1.0 or later. No workaround exists for earlier versions.

### Thread Safety Fixes (Fixed in v2.1.0)

**Severity:** Medium
**Affected versions:** < 2.1.0
**Fixed in:** v2.1.0

Four independent thread safety issues were fixed in security-critical paths:
- CostGuard breach history: unbounded growth + missing lock (#253)
- VectorClock: race condition under concurrent access (#243)
- ErrorBudget._events: unbounded deque without size limit (#172)
- .NET SDK: thread safety, caching, disposal sweep (#252)

**Recommendation:** Upgrade to v2.1.0 or later if running under concurrent agent load.
