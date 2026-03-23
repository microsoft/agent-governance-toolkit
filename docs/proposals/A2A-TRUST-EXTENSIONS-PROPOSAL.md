# Proposal: A2A Protocol Trust & Payment Extensions

**Status:** ✅ Adapter Shipped — Trust extensions proposed for AAIF contribution  
**Author:** Imran Siddique (Microsoft)  
**Created:** 2026-03-21  
**Target:** AAIF / Linux Foundation (A2A Protocol)

## Summary

Extend Google's A2A protocol with trust scoring, payment negotiation, and delegation authorization — embedding AGT governance capabilities into the emerging industry standard.

## Current State

- A2A trust adapter shipped: `packages/agentmesh-integrations/a2a-protocol/`
- Agent Cards with governance metadata implemented
- Trust-gated task acceptance implemented

## Proposed AAIF Contributions

1. **Trust scores in Agent Cards** — Add ATR trust scores to Agent Card metadata
2. **Payment negotiation phase** — New phase between "submitted" and "working" in Task lifecycle
3. **VADP delegation references** — Task objects carry authorization provenance

## References

- [A2A Protocol](https://a2a-protocol.org/latest/)
- [AAIF Proposal](AAIF-PROPOSAL.md)
