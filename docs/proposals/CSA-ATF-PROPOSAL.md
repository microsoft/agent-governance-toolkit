# Proposal: CSA Agentic Trust Framework (ATF) Integration

**Status:** 🔄 Active — ATF author (Josh Woodruff) engaged. Conformance spec published. Async assessment in progress. All 15 requirements mapped.  
**Author:** Imran Siddique (Microsoft)  
**Created:** 2026-03-04  
**Target:** Cloud Security Alliance (CSA) Agentic Trust Framework Working Group

## Summary

This proposal documents the Agent Governance Toolkit's alignment with the [CSA Agentic Trust Framework (ATF) v0.1.0](https://github.com/massivescale-ai/agentic-trust-framework), an open specification establishing Zero Trust principles for AI agent security.

The ATF defines 5 core pillars and 15 security requirements. The Agent Governance Toolkit provides **full coverage across all 15 requirements** through its 5 packages.

## ATF Pillar Coverage

| ATF Pillar | Toolkit Package | Coverage |
|------------|----------------|----------|
| 1. Identity Management | AgentMesh (DID + Entra Agent ID) | ✅ Full |
| 2. Behavioral Monitoring | Agent Runtime + Agent SRE | ✅ Full |
| 3. Data Governance | Agent OS (VFS + Policy Engine) | ✅ Full |
| 4. Segmentation | Agent Runtime (Execution Rings) | ✅ Full |
| 5. Incident Response | Agent SRE (Circuit Breakers + Kill Switch) | ✅ Full |

## Key Differentiators

1. **End-to-end coverage** — Single toolkit covers all 5 ATF pillars (most solutions cover 1-2)
2. **Cryptographic identity** — Ed25519 DID identity with trust scoring, delegation chains, and Entra Agent ID enterprise bridge
3. **Runtime enforcement** — Not just documentation; policies are enforced at the kernel level
4. **AI-BOM supply chain** — Full model/data/weights provenance tracking (aligns with ATF data governance requirements)
5. **OWASP alignment** — 10/10 OWASP Agentic Top 10 coverage complements ATF compliance

## Detailed Compliance Mapping

See [docs/compliance/csa-atf-mapping.md](compliance/csa-atf-mapping.md) for the full requirement-by-requirement mapping.

## Proposed Engagement

1. **Contribute toolkit as ATF reference implementation** — Open-source, MIT-licensed, ready for community validation
2. **ATF conformance testing** — Develop automated conformance tests based on ATF checklist
3. **Feedback on ATF spec** — Propose additions for:
   - Agent delegation chain verification (not covered in current ATF spec)
   - AI-BOM integration for data governance requirements
   - Trust scoring quantification methodology

## References

- [CSA Agentic Trust Framework](https://github.com/massivescale-ai/agentic-trust-framework)
- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [Full ATF Compliance Mapping](compliance/csa-atf-mapping.md)
- [OWASP Compliance Mapping](OWASP-COMPLIANCE.md)

## Progress

- 2026-03-04: Proposal created with full 5-pillar compliance mapping
- 2026-03-08: Published to microsoft/agent-governance-toolkit
- 2026-03-19: ATF author Josh Woodruff reached out (Discussion #301)
- 2026-03-20: Confirmed alignment on 3 spec additions (delegation chains, AI-BOM, trust scoring)
- 2026-03-23: ATF Conformance Specification published — reviewing for implementer feedback
- Next: Async conformance assessment document
