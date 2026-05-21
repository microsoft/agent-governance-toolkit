# Alpha Demos · Live Presentation Pack

The on-stage demo kit for the Agent Governance Toolkit talk. Three artifacts,
one seamless story.

## What is in this folder

| File | Role on stage |
|------|---------------|
| `index.html` | Demo Runtime Console. Beautiful animated narrative the audience watches. Open on Monitor 2 (or fullscreen on the main projector when you flip from slides). |
| `agt-live-demo.ipynb` | Notebook 1. Install, identity, policy, audit. Proves AGT is real code, not a slide. |
| `owasp-contoso-bank.ipynb` | Notebook 2. The full OWASP Agentic Top 10 (ASI-01 to ASI-10) lived through Contoso Bank scenarios. The "we mitigate everything" finale. |

## Recommended demo flow

You will tell the audience: *"Slides are done. Time for some demos."*  Then:

1. **Flip from slides to `index.html`** (fullscreen, dark room loves it).
2. Walk the audience through the console for ~60 seconds. Hover the cards,
   let the animations run. This is the visual map of what AGT does.
3. **Open VS Code with `agt-live-demo.ipynb`.** Run it top to bottom. ~3 min.
   This is the "it actually works" moment: install, sign an action, evaluate
   a policy, write a tamper-evident audit entry.
4. **Flip back to `index.html`.** Say *"Now let's see it under attack."*
   Click the OWASP badges on the cards (they tell the threat story).
5. **Open `owasp-contoso-bank.ipynb`.** Run cell by cell. Each ASI scenario
   takes ~20 seconds and ends with a clear ALLOW or DENY verdict. ~6 min total.
6. **Flip back to `index.html` one last time** for the closing pitch.

Total demo time: ~10 minutes. Total LOC the audience sees: real, runnable,
unedited.

## Why not embed the notebooks inside the website?

Tempting, but not worth it for a live talk:

- **JupyterLite in a `<iframe>`** works, but the in-browser kernel cannot install
  `agent-governance-toolkit` from PyPI and many AGT modules need real CPython
  (cryptography, asyncio). You would have to vendor a stripped-down build, and
  it would no longer be "the real package the audience just `pip install`ed."
- **Voila / nbconvert** turns notebooks into a static dashboard, but you lose
  the "I am typing this live" credibility.
- **Embedding the website inside the notebook** (an `IPython.display.HTML`
  iframe) works, but it crams the beautiful console into a 600px cell on a
  white notebook background. The console is designed to be fullscreen.

The Alt+Tab handoff (website ↔ VS Code notebook) is what high-credibility
technical demos do. Keep it.

## Pre-flight checklist (run 30 min before the talk)

```powershell
# Fresh env, prove the install story works on this machine
pip install agent-governance-toolkit[full]

# Cold-run both notebooks end to end
jupyter nbconvert --to notebook --execute agt-live-demo.ipynb --output _smoke1.ipynb
jupyter nbconvert --to notebook --execute owasp-contoso-bank.ipynb --output _smoke2.ipynb
Remove-Item _smoke1.ipynb, _smoke2.ipynb

# Open the console once so the browser caches the fonts
start index.html
```

If both notebooks execute clean, you are stage-ready.

## On-stage tips

- **Monitor 1**: VS Code with both notebooks already open in tabs.
- **Monitor 2 / projector**: `index.html` fullscreen (F11).
- **Keyboard shortcuts on the console**: `0` overview · `1`-`6` jump to demo
  card · `m` topic map.
- **Cell-by-cell**: hit `Shift+Enter`. Never "Run All" on stage; the rhythm
  of one-cell-at-a-time is what sells it.
- If anything errors live, say *"this is exactly the kind of policy denial
  AGT is designed to surface"* and move on. The audit log will prove it.
