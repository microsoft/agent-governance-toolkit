# Distributed Information Flow Control

This example proves the first AgentMesh-native distributed IFC slice: one agent
signs an information-flow receipt for a message, the receiver verifies the
receipt before accepting the message, and downgrade attempts fail.

## What this demonstrates

- A native AgentMesh message frame can carry an `information_flow_receipt`.
- The receipt is signed by the sending agent's Ed25519 identity.
- The receipt binds the message payload hash, recipient DID, subject/message ID,
  envelope reference, aggregate sensitivity, integrity, timestamp, and nonce.
- The receiver rejects payload tampering, nonce replay, and attempts to lower
  sensitivity or restore untrusted integrity.

## Run

```bash
python examples/distributed-information-flow-control/demo.py
```

Expected proof output:

```text
valid_receipt: allowed
tampered_payload: denied
downgrade_attempt: denied
replay_attempt: denied
```

Existing package deprecation warnings can appear on stderr when running from a
development checkout; the proof signal is the stdout shown above.
