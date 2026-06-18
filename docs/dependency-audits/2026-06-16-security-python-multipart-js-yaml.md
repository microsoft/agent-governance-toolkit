# Dependency Audit: python-multipart 0.0.32, js-yaml 4.2.0 (security fixes)

**Date:** 2026-06-16
**PR:** #3080
**Lockfiles changed:**
- `agent-governance-python/agent-os/modules/caas/requirements.txt`
- `agent-governance-antigravity-cli/package-lock.json`
- `agent-governance-claude-code/package-lock.json`
- `agent-governance-copilot-cli/package-lock.json`
- `agent-governance-opencode/package-lock.json`

## Dependencies changed

| Package | From | To | Scope | Reason |
|---|---|---|---|---|
| `python-multipart` | 0.0.26 | 0.0.32 | production (caas) | Fix GHSA security alerts #230, #299, #300, #301, #302 |
| `js-yaml` | 4.1.1 (transitive) | 4.2.0 (via npm overrides) | production (CLI packages) | Fix CVE-2026-53550 / GHSA-h67p-54hq-rp68 |

## Security advisory relevance

### python-multipart
Multiple GitHub Security Advisories (GHSA) affect versions < 0.0.32. The vulnerabilities cover multipart form parsing edge cases. The caas module uses python-multipart transitively via FastAPI for handling multipart uploads in the document ingestion pipeline.

### js-yaml
**CVE-2026-53550 / GHSA-h67p-54hq-rp68**: Quadratic-complexity denial-of-service in YAML merge key (`<<`) handling. Any input that triggers repeated merge key resolution results in O(n²) expansion. Affects js-yaml <= 4.1.1; fixed in 4.2.0. The four CLI packages carry js-yaml as a transitive dependency via `@microsoft/agent-governance-sdk`. Fixed by adding an npm `overrides` field to force js-yaml@4.2.0 in all CLI package trees.

## Breaking change risk

**python-multipart:** Risk: low. 0.0.26 to 0.0.32 is a patch/minor series fixing security issues with no documented API removals.

**js-yaml 4.1.1 → 4.2.0:** Risk: low. 4.2.0 is API-compatible with 4.1.1 within the 4.x series. The fix tightens merge-key depth handling; legitimate YAML without deeply nested merge keys is unaffected.

## Rollback plan

- **python-multipart**: Revert `agent-governance-python/agent-os/modules/caas/requirements.txt` to `python-multipart==0.0.26`.
- **js-yaml**: Remove the `"overrides": {"js-yaml": "4.2.0"}` field from the four CLI `package.json` files and revert the corresponding `package-lock.json` `node_modules/js-yaml` entries.
