# OWASP Agent Security Initiative — Code Samples Contribution

**Submission:** [GenAI-Security-Project/GenAI-Agent-Security-Initiative#2](https://github.com/GenAI-Security-Project/GenAI-Agent-Security-Initiative/pull/2)
**Status:** Open — awaiting review
**Type:** Pull Request (insecure/secure code pairs)
**Date Submitted:** March 2, 2026

---

## Summary

Contribution of insecure/secure code pairs to the OWASP Agent Security Initiative (ASI), demonstrating how the Agent Governance Toolkit mitigates OWASP Agentic Top 10 risks. Initial submission covers 3 risks with plans to expand to all 9 covered risks.

## Samples Contributed

### ASI-01: Agent Hijacking

| | Description |
|---|---|
| **Vulnerability** | Unrestricted goal modification — agent accepts arbitrary goals without validation |
| **Insecure** | Agent directly executes user-provided goals with no policy check |
| **Secure** | `PolicyEngine` validates goals against declarative YAML policy before execution |
| **Package** | Agent OS (`agent_os.PolicyEngine`) |

### ASI-02: Excessive Capabilities

| | Description |
|---|---|
| **Vulnerability** | Unrestricted filesystem and network access — agent has full system access |
| **Insecure** | Agent directly calls `os.system()`, `open()`, `requests.get()` without restrictions |
| **Secure** | `CapabilitySandbox` enforces ring-based least-privilege with explicit capability grants |
| **Package** | Agent OS (`agent_os.CapabilitySandbox`) |

### ASI-05: Insecure Output

| | Description |
|---|---|
| **Vulnerability** | Raw agent output passed directly to SQL queries — SQL injection risk |
| **Insecure** | Agent output used in f-string SQL query without sanitization |
| **Secure** | `OutputValidator` from Agent Hypervisor sanitizes output before downstream consumption |
| **Package** | Agent Hypervisor (`agent_hypervisor.OutputValidator`) |

## File Structure

```
frameworks/agent-os/
├── README.md                          # Framework overview + architecture
├── Dockerfile                         # Build/run container
├── ASI-01-agent-hijacking/
│   ├── README.md                      # Vulnerability + mitigation description
│   ├── insecure.py                    # Deliberately vulnerable agent
│   └── secure.py                      # Agent OS secured version
├── ASI-02-excessive-capabilities/
│   ├── README.md / insecure.py / secure.py
└── ASI-05-insecure-output/
    ├── README.md / insecure.py / secure.py
```

## Full OWASP Coverage (9/10)

The Agent Governance Toolkit covers 9 of 10 OWASP Agentic Top 10 risks. Future PRs will add samples for the remaining 6 covered risks:

| Risk | Description | Package | Status |
|------|-------------|---------|--------|
| ASI-01 | Agent Hijacking | Agent OS | ✅ In this PR |
| ASI-02 | Excessive Capabilities | Agent OS | ✅ In this PR |
| ASI-03 | Insecure Communication | Agent Mesh | 🔜 Planned |
| ASI-04 | Supply Chain (Agent-SBOM) | Agent Mesh | 🔜 Planned |
| ASI-05 | Insecure Output | Agent Hypervisor | ✅ In this PR |
| ASI-06 | Confused Deputy | Agent OS | 🔜 Planned |
| ASI-07 | Identity Spoofing | Agent Mesh | 🔜 Planned |
| ASI-08 | Unbounded Autonomy | Agent Hypervisor | 🔜 Planned |
| ASI-09 | Missing Audit Trails | Agent SRE | 🔜 Planned |
| ASI-10 | Cascading Hallucinations | Agent SRE | 🔜 Planned |

## Ecosystem Context

- **3,900+ tests** across 5 packages
- **5 PyPI packages** published
- **MCP server** for governance-as-a-service
- **8 framework integrations** (MAF, LangChain, CrewAI, ADK, etc.)
- Full compliance mapping: [OWASP-COMPLIANCE.md](https://github.com/microsoft/agent-governance-toolkit/blob/master/docs/OWASP-COMPLIANCE.md)

## Links

- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [Agent OS](https://github.com/microsoft/agent-governance-toolkit)
- [Agent Hypervisor](https://github.com/microsoft/agent-governance-toolkit)
- [OWASP Agentic Top 10](https://owasp.org/www-project-agentic-ai-threats-and-mitigations/)
