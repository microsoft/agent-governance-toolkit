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

## Prerequisites

```powershell
pip install agent-governance-toolkit[full]
```

Run the notebooks from the repository root environment so the local packages,
OPA binary, manifests, and Rego bundles are available.

## Recommended demo flow (~10 min total)

You tell the audience: *"Slides are done. Time for some demos."* Then:

1. **Flip from slides to `console.html`** (fullscreen, dark room loves it). Walk the audience through the cards for ~60 seconds. Hover, let the animations run. This is the visual map of what AGT does.
2. **Open VS Code with `agt-live-demo.ipynb`.** Run it top to bottom. It loads a native ACS manifest and shows an allowed input beside a denied prompt-injection attempt.
3. **Flip back to `console.html`.** Say *"Now let's see it under attack."* Click the OWASP cards to walk through the threat story.
4. **Open `owasp-contoso-bank.ipynb`.** Run it cell by cell to show the same native runtime applied to a banking scenario.
5. **Flip back to `console.html`** one last time for the closing pitch.

## Pre-flight checklist (run 30 min before the talk)

```powershell
# Fresh env, prove the install story works on this machine
pip install agent-governance-toolkit[full]

# Cold-run both notebooks end to end
jupyter nbconvert --to notebook --execute agt-live-demo.ipynb --output _smoke1.ipynb
jupyter nbconvert --to notebook --execute owasp-contoso-bank.ipynb --output _smoke2.ipynb
Remove-Item _smoke1.ipynb, _smoke2.ipynb

# Open the console once so the browser caches the fonts
start console.html
```

If both notebooks execute clean, you are stage-ready.

## On-stage tips

- **Monitor 1**: VS Code with both notebooks already open in tabs.
- **Monitor 2 / projector**: `console.html` fullscreen (F11).
- **Cell-by-cell**: hit `Shift+Enter`. Never "Run All" on stage; the rhythm of one-cell-at-a-time is what sells it.
- If anything errors live, say *"this is exactly the kind of policy denial AGT is designed to surface"* and move on. The audit log will prove it.
