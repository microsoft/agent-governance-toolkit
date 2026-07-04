# India Regulatory Policy Pack

Reference Policy-as-Code for governing AI agents under Indian regulation: data protection,
financial-sector data flows, securities-market cyber resilience, incident reporting, and identity protection.

> Community-maintained governance starter policies. NOT certified legal compliance instruments.
> Perform your own assessment with qualified advisors before deploying in regulated environments.
> Regulatory status is noted per file (binding vs advisory/draft).

## Coverage
| Policy file | Regulation | Authority | Status |
|---|---|---|---|
| dpdp-data-protection | DPDP Act 2023 + DPDP Rules 2025 | Data Protection Board of India | Binding, phased (full enforcement 13 May 2027) |
| certin-2022-directions | CERT-In Directions, 28 Apr 2022 (s.70B(6) IT Act) | CERT-In | Binding |
| rbi-data-localization | RBI Storage of Payment System Data 2018 + KYC/IT MDs | Reserve Bank of India | Binding (FREE-AI advisory) |
| sebi-governance | SEBI CSCRF 2024 + AI/ML responsibility amendment Feb 2025 | SEBI | Binding (June 2025 AI guidelines draft) |
| aadhaar-pii-protection | Aadhaar Act s.29 + 2021 Regulations | UIDAI | Binding |

## Binding vs advisory
Encoded as advisory/draft (never block): RBI FREE-AI (Aug 2025 committee report) and the SEBI June 2025
AI/ML guidelines (consultation). DPDP Rules are notified but phased. The DPDP s.16 restriction list is
currently empty, so no country is hardcoded as blocked.

## What these rules detect (and what they do not)
The output-side rules match intent phrases (for example "store PII unencrypted", "keep payment data
abroad", "don't report the breach"). They catch an agent that narrates or proposes a violation in its
output; they do not observe the underlying system action, so they are detection heuristics for an
examples pack, not compliance controls. Treat them as a starting point, pair them with real
action-level enforcement, and run your own compliance assessment.

## Not covered (known gaps)
Material obligations the pack does not represent yet, listed so the example is honest about its scope:
- DPDP: s.5 notice; s.9 children's data (verifiable parental consent, no behavioural monitoring of minors); ss.11-14 Data Principal rights.
- CERT-In: Direction (v) cloud/VPS/VPN-provider five-year subscriber-record retention; Annexure-I 20-incident reporting schedule.
- RBI: System Audit Report (SAR) by a CERT-In-empanelled auditor; Outsourcing Master Direction exit-strategy and concentration-risk clauses.
- SEBI: CSCRF six-hour reporting window (currently encoded only as "mandated timelines"); SBOM; Cyber Capability Index; Reg 16A disclosure of AI/ML use to SEBI.
- Aadhaar: Aadhaar Data Vault (mandatory reference-key tokenisation and HSM encryption for stored Aadhaar numbers); Virtual ID; AUA/KUA licensing gate.

## Two layers
Universal agent-safety controls (prompt_injection, pii_leakage, tool_permissions, human_approval,
model_routing) apply to all agents and are evaluated via the shared jurisdiction router. These India
national packs add jurisdiction-specific regulatory controls, selected by context.customer_country = "IN".

## Rego
rego/ holds OPA reference implementations (NOT loaded by the Agent-OS Python runtime). Each pack exposes
data.agt_policies_india.<pack>.decision. The shared router maps IN to these packs.
