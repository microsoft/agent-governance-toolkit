# Native information flow control example

This example demonstrates the native AGT IFC enforcement slice: untrusted private content is quarantined behind an opaque handle, folded into runtime context through FIDES-compatible metadata, blocked from a trusted-only public sink before execution, and safely revealed only through a bounded reveal policy.

## Run

```bash
python examples/information-flow-control/demo.py
```

## Expected output

The runtime may also print existing AGT deprecation or sample-rule warnings to stderr. The proof output is:

```text
accumulated integrity: untrusted
accumulated sensitivity: CONFIDENTIAL
send_public_email: blocked
reason: IFC blocked sink send_public_email: untrusted context cannot flow to a trusted-only sink
safe reveal allowed: True
safe reveal value: {'ticket_id': 'T-123'}
send_quarantine_queue: allowed
```

## What this proves

- Source output can carry FIDES-compatible `additional_properties.content_label` metadata.
- `post_execute` folds the source label into the `ContextEnvelope`.
- `pre_execute` denies a trusted-only sink before the tool call runs.
- Raw untrusted content can stay behind an opaque `ifcvar://...` handle.
- A bounded reveal policy can release only an approved field with explicit authority and reason.
- A sink that explicitly accepts untrusted confidential context can still run.

This example is intentionally deterministic and does not call a model or external service.
