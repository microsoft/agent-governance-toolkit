# Facilitator Notes — Introduction to AI Agent Governance

> For facilitator use only. Keep this tab open alongside the slide deck.

---

## Before the Session

- [ ] Send [prerequisites.md](prerequisites.md) to participants **48 hours** in advance.
- [ ] Test all three lab scripts on your own machine and note any errors.
- [ ] Confirm the venue has reliable Wi-Fi — participants need `pip install` access.
- [ ] Prepare a backup: download the packages and serve them locally with
      `pip install --find-links ./wheels/ agent-os-kernel agentmesh-platform agent-governance-toolkit`
      in case the internet is unavailable.
- [ ] Open [slides.md](slides.md) in your presenter tool and rehearse transitions.
- [ ] Identify 2–3 volunteers in advance who have completed prerequisites — they
      can help other participants during lab time.

---

## Agenda and Timing

| Segment | Duration | Cumulative | Notes |
|---------|----------|------------|-------|
| Intro + agenda (Slides 1–2) | 3 min | 0:03 | Keep this brief |
| Why governance matters (Slides 3–6) | 12 min | 0:15 | Invite 1–2 audience questions |
| Lab 1 intro (Slide 7) | 5 min | 0:20 | Live-code Step 1 on projector |
| **Lab 1 — First policy** | 20 min | 0:40 | Circulate; most issues are YAML indentation |
| Lab 1 debrief | 2 min | 0:42 | Ask: "Who got all 5 scenarios matching?" |
| Trust & identity (Slides 8–13) | 13 min | 0:55 | Walk through the handshake diagram slowly |
| Lab 2 intro (Slide 14) | 5 min | 1:00 | Live-code Step 1 on projector |
| **Lab 2 — Multi-agent trust** | 20 min | 1:20 | Common issue: forgetting to record events |
| Break ☕ | 10 min | 1:30 | Hard stop — labs 3 must start on time |
| Production patterns (Slides 15–20) | 10 min | 1:40 | Keep slides 18–19 to 2 min each |
| Lab 3 intro (Slide 21) | 3 min | 1:43 | Show pipeline diagram |
| **Lab 3 — Full stack** | 20 min | 2:03 | The tampering step usually draws "wow" reactions |
| Wrap-up & next steps (Slide 22) | 5 min | 2:08 | OK to run over by 8 min |

---

## Slide-by-Slide Talking Points

### Slide 3 — The Problem

> "Raise your hand if you've deployed a web service with no authentication. No
> one? Right — we learned that lesson in the 1990s. AI agents are at exactly
> that point today. Most agents run with no policy, no identity, and no audit
> trail."

Good analogy: an agent without governance is like `chmod 777` on a production
server — it works, until it doesn't.

### Slide 4 — OWASP ASI Top 10

Don't go through every item. Highlight three:

- **ASI-01 Prompt Injection** — the most common attack today
- **ASI-03 Excessive Agency** — agents doing more than they should
- **ASI-08 Inadequate Logging** — you can't investigate what you can't see

### Slide 5 — The Toolkit

Emphasise: these aren't theoretical controls. Every layer has runnable Python.

### Slide 6 — Three Layers

Spend 30 seconds per layer. The YAML snippet for policies often surprises people
with how simple it is — lean into that.

### Slides 8–11 — Trust and Identity

The trust handshake diagram (Slide 11) is the most complex diagram in the deck.
Walk through it step by step:

1. Initiator sends a random challenge (nonce)
2. Responder signs with Ed25519 private key
3. Initiator verifies with public key
4. Initiator checks trust score ≥ threshold

If anyone asks "why not JWT?" — JWTs require a central issuer and don't
naturally support dynamic trust scores.

### Slides 15–20 — Production Patterns

These are reference slides. Don't try to cover every cell in the tables.
Instead, pick whichever 2–3 patterns are most relevant to the audience
(enterprise? → compliance gates; startup? → policy-as-code and circuit breakers).

---

## Common Issues and Fixes

### Lab 1

| Symptom | Cause | Fix |
|---------|-------|-----|
| `yaml.scanner.ScannerError` | YAML indentation error | Check that `rules:` is flush-left; list items indent 2 spaces |
| All calls return `allow` | `defaults.action` is `allow` and no rules matched | Add `print(decision.reason)` to debug which rule matched |
| `ImportError: agent_os` | Package not installed | `pip install agent-os-kernel` |

### Lab 2

| Symptom | Cause | Fix |
|---------|-------|-----|
| Trust score stays at 500 | `record_event()` not called | Confirm the loop is executing: add `print(i)` |
| `AttributeError: revoke` | Old package version | `pip install --upgrade agentmesh-platform` |
| Handshake never succeeds | Threshold too high | Lower `min_trust_score` to 540 for demonstration purposes |

### Lab 3

| Symptom | Cause | Fix |
|---------|-------|-----|
| Tampering check returns `True` | Mutated the wrong field | Make sure you mutate `audit.entries[0].outcome`, not a copy |
| `AuditLog` has no `entries` | Using wrong import | Use `from agentmesh.governance.audit import AuditLog` |

---

## Frequently Asked Questions

**Q: Does this work with LangChain / CrewAI / AutoGen?**

A: Yes — see [Tutorial 03 — Framework Integrations](../tutorials/03-framework-integrations.md).
The `agent-os-kernel` package ships middleware adapters for all major frameworks.

**Q: Can I use my own policy format (OPA/Rego)?**

A: Yes — [Tutorial 08](../tutorials/08-opa-rego-cedar-policies.md) covers OPA,
Rego, and Cedar. The policy engine supports pluggable backends.

**Q: Is there a cloud-hosted version?**

A: The toolkit is designed to run wherever your agents run — on-premises, cloud,
or local. There's no SaaS dependency.

**Q: What about Python < 3.10?**

A: Python 3.10 is the minimum for all packages. Most features work on 3.9 but
it's not officially supported.

**Q: How do I handle secrets / API keys in policies?**

A: Never hardcode secrets. Use environment variables and reference them in policy
YAML as `${ENV_VAR_NAME}`. See [SECURITY.md](../../SECURITY.md).

---

## Post-Session

- [ ] Collect feedback (1-minute written form or quick show-of-hands on value/difficulty).
- [ ] Share the GitHub repo link and encourage participants to star it.
- [ ] Point advanced participants at the full tutorial series in
      [docs/tutorials/README.md](../tutorials/README.md).
- [ ] File any bugs or content improvements found during the session as GitHub issues.
