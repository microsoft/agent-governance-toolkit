# Agent-SRE — Basic Runbook Example

A minimal end-to-end demo of [`agent-sre`](../../../agent-governance-python/agent-sre/): define an SLO, watch it transition through health states, detect a breach, and run a multi-step recovery runbook with an approval gate.

## What This Shows

| Step | API used | Outcome |
| --- | --- | --- |
| Define & monitor an SLO | `SLO`, `TaskSuccessRate`, `ErrorBudget`, `SLODashboard` | Health transitions `unknown` → `healthy` → `exhausted` |
| Detect a breach | `IncidentDetector.ingest_signal(...)` | A `p1` incident is auto-created from an `ERROR_BUDGET_EXHAUSTED` signal |
| Remediate | `RunbookExecutor.execute(runbook, incident, approve_callback=...)` | Three steps run; the remediation step passes through an approval gate |

## Prerequisites

- Python 3.10+
- pip

No API keys are required. After installation, the example runs locally and does not call external services.

## Quick Start

```bash
cd examples/agent-sre/basic-runbook
python -m venv .venv

# Activate the venv — pick the right line for your shell:
#   Windows PowerShell:        .venv\Scripts\Activate.ps1
#   macOS / Linux / Git Bash:  source .venv/bin/activate

pip install -r requirements.txt
python main.py
```

## Expected Output

```text
Agent-SRE Basic Runbook
============================================================
Initial health  : unknown
After warmup    : healthy
After failure   : exhausted

[!] Incident created: error_budget_exhausted: Error budget exhausted after task failure
    Severity:    p1
    Incident ID: <hex12>

Runbook execution: completed
  [ok] Check health       (<duration>s)  -> health summary refreshed (status=exhausted)
  [ok] Restart agent      (<duration>s)  -> agent restarted
  [ok] Verify recovery    (<duration>s)  -> recovery checks passed
```

Notes on what to expect run-to-run:

- **Health line values** (`unknown`, `healthy`, `exhausted`) are deterministic.
- **Severity** is `p1` because `ERROR_BUDGET_EXHAUSTED` maps to `IncidentSeverity.P1` via `Signal.severity_hint`.
- **Incident ID** is a random 12-char hex string (`uuid.uuid4().hex[:12]`), so it differs every run.
- **Durations** are sub-millisecond and vary slightly between runs — they are not part of the contract.

## Files

| File | Purpose |
| --- | --- |
| `main.py` | The runnable demo (single file, no async, no external services) |
| `requirements.txt` | Pins `agent-sre==3.4.0` |
| `README.md` | This file |

## How It Maps to the SDK

- **SLO + health** → [`agent_sre.SLO`](../../../agent-governance-python/agent-sre/src/agent_sre/slo/objectives.py), [`agent_sre.ErrorBudget`](../../../agent-governance-python/agent-sre/src/agent_sre/slo/objectives.py), [`agent_sre.slo.indicators.TaskSuccessRate`](../../../agent-governance-python/agent-sre/src/agent_sre/slo/indicators.py), [`agent_sre.slo.dashboard.SLODashboard`](../../../agent-governance-python/agent-sre/src/agent_sre/slo/dashboard.py)
- **Incidents** → [`agent_sre.incidents.detector.IncidentDetector`](../../../agent-governance-python/agent-sre/src/agent_sre/incidents/detector.py), `Signal`, `SignalType`
- **Runbooks** → [`agent_sre.incidents.runbook.Runbook`](../../../agent-governance-python/agent-sre/src/agent_sre/incidents/runbook.py), `RunbookStep`, [`agent_sre.incidents.runbook_executor.RunbookExecutor`](../../../agent-governance-python/agent-sre/src/agent_sre/incidents/runbook_executor.py)

For the full SDK overview, see [`agent-governance-python/agent-sre/README.md`](../../../agent-governance-python/agent-sre/README.md).

## Cleanup

Nothing to clean up — the example writes no files and opens no sockets at runtime. To remove the local virtual environment, delete the `.venv/` directory.
