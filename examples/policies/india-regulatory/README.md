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

  ## Two layers
  Universal agent-safety controls (prompt_injection, pii_leakage, tool_permissions, human_approval,
  model_routing) apply to all agents and are evaluated via the shared jurisdiction router. These India
  national packs add jurisdiction-specific regulatory controls, selected by `context.customer_country = "IN"`.

  ## Rego
  `rego/` holds OPA reference implementations (NOT loaded by the Agent-OS Python runtime). Each pack exposes
  `data.agt_policies_india.<pack>.decision`. The shared router maps `IN` to these packs.
