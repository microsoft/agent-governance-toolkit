# Agent Governance Toolkit, Presentation Demos

Live, runnable demos used in keynotes, conference booths, and stakeholder reviews.

## Pick your path

| If you are... | Open this | Time |
|---|---|---|
| Presenting live (8 min keynote) | [`agt-live-demo.ipynb`](agt-live-demo.ipynb) | ~8 min |
| Walking a security audience through OWASP Agentic Top 10 | [`owasp-contoso-bank.ipynb`](owasp-contoso-bank.ipynb) | ~15 min |
| Showing the visual story (booth screen, async share, leadership flyby) | [`console.html`](console.html) | self-paced |
| Running headless verification (CI, vanilla box, no Jupyter) | [`scripts/`](scripts/) | ~2 min total |

The notebooks and the console are the primary demo path. The PowerShell scripts under `scripts/` are the verification harness.

## On-stage runbook

See [`RUNBOOK.md`](RUNBOOK.md) for the exact cell-by-cell narration, smoke-test commands, and recovery tips for the live notebooks.

## Prerequisites

```powershell
pip install agent-governance-toolkit[full]
```

The notebooks include a bootstrap cell that installs any missing AGT subsystem into your active Python interpreter on first run, so you can simply open a notebook and run all cells.
