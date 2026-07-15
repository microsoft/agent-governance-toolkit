# External Checkpoint Bridge

This example shows how to bridge Agent Governance Toolkit (AGT) action
governance with an external checkpoint or verifier.

The key idea is simple:

1. AGT prepares a deterministic action envelope before a tool executes.
2. The envelope is hashed so the external verdict is bound to the proposed action.
3. A local or remote checkpoint returns a verdict: `allow`, `require_approval`, or `deny`.
4. AGT remains the enforcement point and maps that verdict to execute, pause, or block.

This is useful when an organization wants an external service, ledger, reviewer, or
independent verification layer to add a signal without moving enforcement out of the
agent runtime.

## Quick start

From the repository root:

```bash
python examples/external-checkpoint-bridge/demo.py
```

No API keys or third-party packages are required. By default, the demo uses a local
checkpoint implementation.

## Optional remote checkpoint

Set `EXTERNAL_CHECKPOINT_URL` to send each action envelope to an HTTPS endpoint:

```bash
EXTERNAL_CHECKPOINT_URL=https://checkpoint.example.com/review \
  python examples/external-checkpoint-bridge/demo.py
```

The endpoint should accept a JSON action envelope and return JSON like:

```json
{
  "verdict": "require_approval",
  "reason": "PII export requires human approval",
  "decision_id": "dec_123",
  "action_hash": "..."
}
```

The demo rejects a remote response if the returned `action_hash` does not match the
action envelope that AGT sent.

## Expected output

```text
External Checkpoint Bridge
checkpoint: local

Action                         Verdict             AGT enforcement
crm.lookup_customer            allow               execute
crm.export_customer_records    require_approval    pause_for_human_approval
filesystem.delete_file         deny                block

Sample proof object:
{
  "decision_id": "local-...",
  "action_hash": "...",
  "verdict": "require_approval",
  "enforcement": "pause_for_human_approval"
}
```

## What this proves

- External governance is bound to the exact action envelope, not a free-form label.
- The runtime can pause for approval before execution when an external checkpoint
  requires it.
- A verifier can participate without becoming the runtime enforcement layer.
- The same pattern can support internal review services, independent ledgers, or
  third-party attestations.

## Scope

This is a self-contained interoperability example. It does not introduce a new AGT
public API and should not be treated as a production checkpoint protocol.
