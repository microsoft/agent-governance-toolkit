# Security policy

AGT is proposed for AAIF hosting in `aaif/project-proposals#19`. During
contribution finalization, canonical vulnerability intake is moving to the
repository's GitHub Security Advisory flow.

**Do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Include the affected component, reproduction steps, impact, and any suggested
   fix or mitigation.

Security responders are listed in [OWNERS.md](OWNERS.md). Microsoft product
security channels are not the canonical AGT vulnerability intake after AAIF
transfer.

## Threat model

Agent governance tooling sits between autonomous AI agents and the resources they
access. Unlike traditional middleware, agents can reason, adapt, and attempt to
circumvent controls. This creates threat categories that do not exist in
conventional software.

**Trust boundaries:**

```text
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
|---|---|---|
| Policy bypass | Agent crafts inputs that cause the policy engine to permit unauthorized actions | Deterministic evaluation with no LLM in the policy path; conformance tests for normative behavior |
| Identity spoofing | Agent presents forged credentials or DIDs to impersonate a higher-trust agent | Cryptographic identity verification via AgentMesh identity layer |
| Audit tampering | Attacker modifies or deletes audit records to hide policy violations | Append-only audit log patterns with cryptographic chaining where enabled |
| Budget evasion | Agent manipulates cost inputs to bypass spending limits | Input validation for special values and negative costs |
| Tool-call injection | Malicious MCP server returns tool results designed to manipulate agent behavior | MCP security scanning and policy checks where integrated |
| Supply chain compromise | Compromised dependency introduces backdoor into policy evaluation | SBOMs, provenance attestations, dependency review, and security scanning |
| Privilege escalation via delegation | Agent delegates to a sub-agent that has broader permissions than the parent | Delegation chain verification and trust attenuation where enabled |

## Intended behavior / not a vulnerability

The following behaviors are expected AGT behavior and are not vulnerabilities by
themselves:

- **Policy-permitted actions**: if a policy explicitly allows an agent to call a
  tool or access a resource, the resulting action is expected behavior.
- **Configured tool execution**: AGT governs configured tool calls. Reports that
  a trusted tool can perform its documented function are not vulnerabilities
  unless AGT bypasses or misapplies policy.
- **Bypass outside the enforcement path**: AGT can only enforce calls routed
  through its integration point. Direct network or process access outside AGT's
  deployment boundary requires operator controls such as gateway, firewall,
  sandbox, or container policy.
- **Example-only behavior**: examples and demos may use local-only bindings,
  fake credentials, or simplified policies. Treat those as demonstration
  artifacts unless the same behavior exists in a shipped package.
- **Documented experimental surfaces**: features marked experimental or proposed
  are not stable security guarantees.

## Scope

The following components are in scope for private security reports:

- policy engine and enforcement integrations;
- identity, DID, trust, delegation, and registry surfaces;
- MCP governance and security components;
- sandbox and runtime isolation surfaces;
- audit, receipt, and provenance generation;
- release, package, and CI/CD supply-chain infrastructure;
- compliance tooling where false negatives create material security risk.

Out of scope:

- denial of service against local CLI tools without security boundary impact;
- vulnerabilities solely in third-party dependencies already tracked upstream;
- social engineering or phishing against maintainers;
- behavior in examples that is explicitly documented as non-production.

## Severity definitions

| Severity | Description | Example |
|---|---|---|
| Critical | Remote exploitation, data exfiltration, sandbox escape, or complete policy bypass without required authority | Sandbox escape allowing host code execution |
| High | Policy bypass under specific conditions, credential exposure, trust-boundary violation, or unauthorized privileged action | Governance check incorrectly permits a denied tool |
| Medium | Race condition, information disclosure, partial bypass requiring local access, or audit-integrity weakness | Concurrent evaluation corrupts policy state |
| Low | Defense-in-depth gap or limited information leak | Missing validation on non-security path |

## Supported versions

| Version | Supported |
|---|---|
| 3.7.x | Yes |
| 3.6.x | Security fixes only |
| < 3.6 | No |

## Disclosure policy

After a vulnerability is reported and confirmed, maintainers will:

1. acknowledge receipt through the private advisory thread;
2. triage severity and affected versions;
3. coordinate a fix or mitigation;
4. publish an advisory when users need to take action.

The project targets coordinated disclosure within 90 days for confirmed
vulnerabilities, with faster handling for actively exploited issues.

## Prior advisories

### CostGuard Organization Kill Switch Bypass (Fixed in v2.1.0)

**Severity:** High<br>
**Affected versions:** < 2.1.0<br>
**Fixed in:** v2.1.0 (PR #272)

A crafted input using IEEE 754 special values (NaN, Infinity, negative numbers)
to CostGuard budget parameters could bypass the organization-level kill switch,
allowing agents to continue operating after the budget threshold was exceeded.

### Thread Safety Fixes (Fixed in v2.1.0)

**Severity:** Medium<br>
**Affected versions:** < 2.1.0<br>
**Fixed in:** v2.1.0

Four independent thread safety issues were fixed in security-critical paths:

- CostGuard breach history: unbounded growth plus missing lock (#253)
- VectorClock: race condition under concurrent access (#243)
- ErrorBudget events: unbounded deque without size limit (#172)
- .NET SDK: thread safety, caching, disposal sweep (#252)
