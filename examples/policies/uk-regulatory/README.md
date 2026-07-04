# UK Regulatory Policy Pack

Reference Policy-as-Code for governing AI agents under UK regulation: data protection,
automated decision-making, and financial-sector principles-based controls.

> Community-maintained governance starter policies. NOT certified legal compliance instruments.
> Perform your own assessment with qualified advisors before deploying in regulated environments.
> Regulatory status is noted per file (binding vs advisory/draft).

## Coverage

| Policy file | Regulation | Authority | Status |
|---|---|---|---|
| `uk-gdpr-data-protection.yaml` | UK GDPR + DPA 2018 + DUAA 2025 (transfer/complaints reforms) | ICO | Binding |
| `ico-automated-decisions.yaml` | UK GDPR Arts. 22A–22D (DUAA 2025 s.80, in force 5 Feb 2026) | ICO | Binding; ICO ADM guidance draft (final expected summer 2026) |
| `fca-financial-conduct.yaml` | FCA Handbook PRIN 2A (Consumer Duty), SM&CR | FCA | Principles-based — no AI-specific binding rules as of 2026 |

## Regulatory context (2026)

- **Data (Use and Access) Act 2025 (DUAA)** received Royal Assent on 19 June 2025. Key data-protection reforms commenced 5 February 2026, including replacement of UK GDPR Art. 22 with Arts. 22A–22D (safeguard-led automated decision-making) and updated international transfer rules using the **"not materially lower"** data protection test.
- **Breach notification** remains UK GDPR Art. 33 / DPA 2018 s.67: notify the ICO without undue delay and, where feasible, within **72 hours** when a breach is **likely to result in a risk** to rights and freedoms. Inform individuals without undue delay where the breach poses **high risk** (Art. 34).
- **Complaints procedure**: DPA 2018 s.164A (inserted by DUAA s.103) requires all controllers to maintain a formal data protection complaints procedure by **19 June 2026**. Data subjects must raise complaints with the controller before escalating to the ICO.
- **FCA**: No AI-specific binding regulation as of 2026. The FCA applies its existing principles-based framework (Consumer Duty, SM&CR, operational resilience). The Mills Review reports to the FCA Board in summer 2026.

## What these rules detect (and what they do not)

Output-side rules match intent phrases (for example "store PII unencrypted", "don't report the breach", "no human review"). Cross-border transfer rules **escalate** for review rather than blanket-block when adequacy or safeguards may apply. They catch an agent that narrates or proposes a violation in its output; they do not observe the underlying system action. Treat them as a starting point, pair them with real action-level enforcement, and run your own compliance assessment.

## Not covered (known gaps)

Material obligations the pack does not represent yet:

- **UK GDPR**: Art. 13–14 privacy notices; Art. 15–22 full data-subject rights workflow; Art. 27 UK representative requirement; children's code (Age Appropriate Design Code).
- **DUAA**: Recognised legitimate interests lawful basis; full cookie/PECR reforms; ICO statutory objectives.
- **NIS2 / UK cyber**: Network and information security incident reporting for in-scope entities.
- **Online Safety Act 2023**: Platform duties for user-generated content (out of scope for generic agent policies).
- **NHS / healthcare**: NHS DSPT, Caldicott principles, and health-sector-specific controls.
- **FCA**: Detailed SYSC mapping, operational resilience impact tolerances, and forthcoming AI good/poor practice benchmarks (expected 2026).

## Two layers

Universal agent-safety controls (prompt_injection, pii_leakage, tool_permissions, human_approval, model_routing) apply to all agents and are evaluated via the shared jurisdiction router in `../african-regulatory/rego/jurisdiction-router.rego`. These UK national packs add jurisdiction-specific regulatory controls, selected by `context.customer_country = "GB"`.

## Rego

`rego/` holds OPA reference implementations (NOT loaded by the Agent-OS Python runtime). Each pack exposes `data.agt_policies_uk.<pack>.decision`. The shared router maps `GB` to `uk_gdpr`, `ico_adm`, and `fca_conduct`.

To evaluate with OPA:

```bash
# Run all UK Rego tests (includes jurisdiction router checks)
./examples/policies/uk-regulatory/rego/run_tests.sh

# Or manually:
opa test examples/policies/african-regulatory/rego examples/policies/uk-regulatory/rego -v

# Evaluate applicable policies for GB
opa eval \
  -d examples/policies/african-regulatory/rego/ \
  -d examples/policies/uk-regulatory/rego/ \
  -i '{"context": {"customer_country": "GB"}}' \
  "data.agt_policies.router.applicable_policies"
```

## Loading policies in Agent-OS

```python
from agent_os.policies.schema import PolicyDocument

policy = PolicyDocument.from_yaml("uk-gdpr-data-protection.yaml")
```

## Disclaimer

These policies are community-maintained governance starter packs. They are **not certified legal compliance instruments**. Organisations must perform their own compliance assessments with qualified legal and regulatory advisors before deploying in regulated environments.
