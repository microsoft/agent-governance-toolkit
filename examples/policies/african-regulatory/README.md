# African Regulatory Policy Pack

Agent-OS governance policies for AI agents operating in Nigeria, Kenya, and
South Africa — plus five universal agent safety controls aligned to the OWASP
Agentic AI Top 10.

Maintained by the [agt-policies-nigeria](https://github.com/kingztech2019/agt-policies-nigeria)
open-source project. Contributions welcome.

---

## Two-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 1 — Universal Agent Safety Controls (all jurisdictions)      │
│  agent-prompt-injection  agent-pii-leakage  agent-tool-permissions  │
│  agent-human-approval    agent-model-routing                        │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 2 — African Regulatory Packs (jurisdiction-specific)         │
│  NG: ndpa-data-residency  cbn-transaction-limits  bvn-nin-protection│
│      nfiu-aml-str  pos-geofencing                                   │
│  KE: kenya-dpa                                                      │
│  ZA: popia-south-africa                                             │
└─────────────────────────────────────────────────────────────────────┘
```

The jurisdiction router (`rego/jurisdiction-router.rego`) determines which
policies apply to each agent action based on `customer_country` and
`transaction_countries`. Universal policies always apply; regulatory packs
are selected per jurisdiction.

---

## Policy Files

### Universal Agent Safety Controls

| File | Regulation | OWASP Agentic AI |
|------|-----------|-----------------|
| `agent-prompt-injection.yaml` | OWASP LLM01; NIST AI RMF GOVERN 6.1 | LLM01 / ASI01 |
| `agent-pii-leakage.yaml` | OWASP LLM06; NDPA 2023 s.24; POPIA s.19 | LLM06 |
| `agent-tool-permissions.yaml` | OWASP LLM08; NIST AI RMF GOVERN 2.2 | LLM08 |
| `agent-human-approval.yaml` | OWASP LLM09; CBN Maker-Checker | LLM09 |
| `agent-model-routing.yaml` | OWASP LLM03/LLM05; NIST AI RMF GOVERN 1.1 | LLM03 / LLM05 |

### African Regulatory Packs

| File | Regulation | Jurisdiction |
|------|-----------|-------------|
| `ndpa-data-residency.yaml` | Nigeria Data Protection Act 2023 | 🇳🇬 NG |
| `cbn-transaction-limits.yaml` | CBN Tiered KYC + NIP Framework | 🇳🇬 NG |
| `bvn-nin-protection.yaml` | CBN BVN Framework; NIBSS Rules | 🇳🇬 NG |
| `nfiu-aml-str.yaml` | MLPPA 2022; NFIU Guidelines | 🇳🇬 NG |
| `pos-geofencing.yaml` | CBN Agent Banking Guidelines 2020 | 🇳🇬 NG |
| `kenya-dpa.yaml` | Kenya Data Protection Act 2019 | 🇰🇪 KE |
| `popia-south-africa.yaml` | POPIA Act 4 of 2013 | 🇿🇦 ZA |

---

## Rego Reference Implementations

The `rego/` subdirectory contains [OPA](https://www.openpolicyagent.org/) Rego
implementations of all 12 policies, plus a jurisdiction router.

> **⚠️ Important:** The `.rego` files are **reference implementations only**.
> They are **not loaded by the Agent-OS Python runtime**, which uses the YAML
> `PolicyDocument` format evaluated by the Python policy engine. The Rego files
> are provided for:
>
> - Teams running OPA as a standalone policy engine
> - Side-by-side verification of YAML rule logic
> - Integration with OPA-based CI pipelines

To run the Rego policies with OPA:

```bash
# Install OPA
curl -L -o /tmp/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x /tmp/opa

# Run all tests (306 tests)
/tmp/opa test rego/ -v

# Evaluate a single policy
/tmp/opa eval \
  -d rego/ \
  -i your-input.json \
  "data.agt_policies_nigeria.ndpa.decision"

# Query the jurisdiction router
/tmp/opa eval \
  -d rego/ \
  -i '{"context": {"customer_country": "NG"}}' \
  "data.agt_policies.router.applicable_policies"
```

### Jurisdiction Router

The router maps customer/transaction country to applicable policy packs:

```json
// Input
{"context": {"customer_country": "NG"}}

// Output: applicable_policies
["ndpa", "cbn", "bvn_nin", "nfiu", "prompt_injection", "pii_leakage",
 "tool_permissions", "human_approval", "model_routing"]

// Cross-border: NG customer + ZA transaction
{"context": {"customer_country": "NG", "transaction_countries": ["NG", "ZA"]}}
// → adds "popia" (10 policies total)
```

---

## Framework Integrations

The source repository includes integration examples for all major agent
frameworks. See [agt-policies-nigeria](https://github.com/kingztech2019/agt-policies-nigeria)
for:

- **LangGraph** — governance nodes wired into the agent graph
- **CrewAI** — `OPAGovernanceTool` as a crewAI `BaseTool`
- **Microsoft AutoGen** — `check_compliance()` registered as a GroupChat tool

---

## Loading Policies in Agent-OS

```python
from agent_os.policies.schema import PolicyDocument

# Load a single pack
policy = PolicyDocument.from_yaml("ndpa-data-residency.yaml")

# Load all packs for a jurisdiction
import os
packs = [
    PolicyDocument.from_yaml(f)
    for f in os.listdir(".")
    if f.endswith(".yaml")
]
```

---

## Disclaimer

These policies are community-maintained governance starter packs. They are
**not certified legal compliance instruments**. Organisations must perform
their own compliance assessments with qualified legal and regulatory advisors
before deploying in regulated environments. Regulatory thresholds (CBN limits,
NDPA adequacy lists) are subject to change — verify against current official
sources before production deployment.
