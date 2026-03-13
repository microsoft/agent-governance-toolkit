## NIST RFI Mapping — Provenance & Artifacts

This file records the provenance of the automated mapping performed on 2026-03-11 and lists the commands, search queries, commit SHA, and artifacts created. Use this to establish the moment-in-time snapshot for both the Federal Register source and this repository's state.

- Mapping run timestamp (UTC): 2026-03-11T13:07:21Z
- Repository commit SHA: 020b718b21a1b6adc98bfc0e0da70397c552e581
- Federal Register source consulted: https://www.federalregister.gov/documents/2026/01/08/2026-00206/request-for-information-regarding-security-considerations-for-artificial-intelligence-agents

### Search queries (examples used during scan)
- Keyword regexes: `SPIFFE|DID|identity|policy|audit|telemetry|sandbox|hypervisor|execution rings|trust scoring|monitor|anomaly|SLO|kill switch|quarantine|capability model`
- Exact file searches: README.md, CHANGELOG.md, demo/maf_governance_demo.py, demo/README.md, fuzz/*.py, packages/agent-mesh/src/**/governance/audit.py, packages/agent-sre/src/**/anomaly/rogue_detector.py, packages/**/docs/**, packages/agent-os/modules/control-plane/benchmark/

### Commands and scripts (representative)
- `git rev-parse --verify HEAD` — capture commit SHA
- `date -u +%Y-%m-%dT%H:%M:%SZ` — timestamp
- Repository text searches via code search / grep patterns (as listed above)
- File reads of: `README.md`, `CHANGELOG.md`, `demo/maf_governance_demo.py`, `fuzz/fuzz_policy_yaml.py`, `packages/agent-mesh/src/agentmesh/governance/audit.py`

### Generated artifacts in this repo
- `docs/nist-rfi-mapping.md` — question-by-question mapping (automated mapping outputs)
- `docs/nist-rfi-response.md` — narrative draft response (initial take)
- `docs/internal/nist-rfi-provenance.md` — this provenance file

### Notes and limitations
- This provenance captures the static repository snapshot and the search/scan commands used to generate the mapping. It does NOT include runtime telemetry or external evidence (OTLP traces, signed audit exports, benchmark outputs) — those must be captured and attached separately.
- The mapping was produced using an automated assistant (GPT-5 mini) that performed repository searches and synthesized findings. The assistant's internal reasoning and chain-of-thought are intentionally omitted. Only final outputs, commands, and extracted file pointers are recorded.

If you reproduce this mapping later, please update this file with the new timestamp and commit SHA to preserve provenance.
