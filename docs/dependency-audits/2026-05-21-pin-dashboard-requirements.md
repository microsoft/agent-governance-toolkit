---
title: Pin governance-dashboard Python dependencies
last_reviewed: 2026-05-21
owner: imran-siddique
---

# Pin governance-dashboard Python dependencies

## Which Dependencies Changed And Why

- `examples/demos/governance-dashboard/requirements.txt` pins all five
  dependencies to exact versions (was using range specifiers).
- streamlit `>=1.54.0,<2.0` pinned to `1.57.0`
- plotly `>=5.18.0,<6.0` pinned to `5.24.1`
- pandas `>=2.1.0,<3.0` pinned to `2.2.3`
- agent-discovery `>=0.0.2` pinned to `0.0.2`
- agentmesh-platform `>=3.0.0` pinned to `3.0.0`
- This change addresses Scorecard Pinned-Dependencies medium-severity alerts.

## Security Advisory Relevance

- No CVEs addressed; this is a reproducibility and supply-chain hardening change.
- Exact version pins prevent silent upgrades to potentially vulnerable versions.

## Breaking Change Risk Assessment

- Risk is low: all pinned versions fall within the original range constraints.
- The governance-dashboard is a demo/example, not a production dependency.
