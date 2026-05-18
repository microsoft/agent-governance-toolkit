# Presentation Demos

Self-contained demo scripts for live presentations and meetups.
All demos work **offline** with no API keys required.

## Usage

```powershell
# Run all demos in sequence
.\demo-run-all.ps1

# Run a specific demo
.\demo-run-all.ps1 -Demo 4
```

## Prerequisites

```powershell
pip install agent-governance-toolkit[full]
```

## Demo List

| # | Script | What It Shows | Time |
|---|--------|--------------|------|
| 1 | `demo-1-install-health-check.ps1` | `agt doctor` environment validation | ~30s |
| 2 | `demo-2-owasp-verify.ps1` | OWASP ASI 2026 compliance checker | ~20s |
| 3 | `demo-3-policy-enforcement.ps1` | YAML policy engine blocking destructive tools + PII | ~20s |
| 4 | `demo-4-trust-scoring.ps1` | DID identity, cryptographic handshake, capability scoping, kill switch | ~25s |
| 5 | `demo-5-framework-integration.ps1` | 3-line governance wrapper for any framework | ~15s |
| 6 | `demo-6-eu-ai-act.ps1` | EU AI Act risk classification and compliance reports | ~30s |

## Notes

- Scripts set `$env:PYTHONUTF8 = "1"` to handle Unicode on Windows terminals.
- Demo 3 runs the MAF loan-processing example if available, otherwise uses an inline fallback.
- Demo 6 runs the repo's EU AI Act example, with an inline fallback if not found.
