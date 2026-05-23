---
title: Pin azure-functions for foundry-ai-gateway-pdp sample
last_reviewed: 2026-05-23
owner: Ricky-G
---

# Pin azure-functions for foundry-ai-gateway-pdp sample

## Which Dependencies Changed And Why

- `examples/foundry-ai-gateway-pdp/function/requirements.txt` (new file)
  pins `azure-functions==1.21.3` as the sole runtime dependency for the
  reference PDP Azure Function shipped with the RFC #2470 sample.
- Exact-version pin (no range) per the repo's supply-chain guidance.
- The package has been published for well over the 7-day stability window.

## Security Advisory Relevance

- No CVEs addressed; this is a new sample, not a security update.
- `azure-functions` is the Microsoft-published Functions Python worker
  binding library; sourced from PyPI under the `azure-functions` name
  (no dependency-confusion risk).

## Breaking Change Risk Assessment

- Risk is none for the rest of the repo: dependency is scoped to a single
  example directory and is not imported by any AGT package.
- Sample is labeled experimental in its README; adopters who copy the
  Bicep / Function code will track their own dependency cadence.
