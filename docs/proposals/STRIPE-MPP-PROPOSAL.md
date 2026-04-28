# Proposal: Stripe Machine Payments Protocol Integration

**Status:** 📋 Planned — Research complete, implementation not started  
**Author:** Agent Governance Toolkit Team (Microsoft)  
**Created:** 2026-03-21  

## Summary

Integrate Stripe's Machine Payments Protocol (MPP) with AGT to enable governed, autonomous agent-to-agent payments with spending delegation, escrow verification, and audit trails.

## Background

Stripe launched MPP in March 2026 — an open standard for agent-initiated payments supporting fiat + stablecoin. The "Sessions" primitive provides pre-authorized spending caps (OAuth for money).

## Proposed Integration

1. **Agent Wallet** — VADP delegation receipt with spending caps maps to Stripe MPP sessions
2. **Escrow Bridge** — Connect Nexus escrow system to Stripe payment confirmation
3. **Compliance** — EU PSD3 SCA satisfied at delegation time; agents transact within authorized scope
4. **Audit Trail** — Every payment linked to VADP delegation chain for provenance

## Architecture

```
Human → VADP Delegation (spend ≤ $X) → Agent Wallet → Stripe MPP Session → Payment
                                                    ↕
                                              Nexus Escrow
                                           (credits locked until confirmation)
```

## Dependencies

- Stripe MPP SDK (March 2026)
- VADP delegation chain (agent-delegation-protocol/)
- Nexus escrow system (agent-governance-python/agent-os/modules/nexus/escrow.py)

## References

- [Stripe MPP](https://stripe.com/payments/mpp)
- [Agent Internet Research](../../research/docs/2026-03-21-agent-internet-economy.md)
