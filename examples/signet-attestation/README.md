# Signet Attestation Layer

Demonstrates using [Signet](https://github.com/Prismer-AI/signet) alongside AGT to add cryptographic attestation to governed tool calls.

**AGT enforces policy. Signet proves what happened.**

## What This Example Shows

1. AGT evaluates a policy (allow/deny) before execution
2. Signet signs the allowed action with Ed25519
3. The signed receipt embeds a `PolicyAttestation` proving which policy was in effect
4. The audit trail is hash-chained and tamper-evident

## Install

```bash
pip install agent-governance-toolkit signet-auth
```

## Run

```bash
python getting_started.py
```

## How It Works

```
Agent Action → AGT Policy Check → Allow? → Signet Sign → Execute → Audit Log
                                  Deny?  → Block + Log Violation
```

The receipt cryptographically proves:
- Which tool was called with what parameters
- Who signed it (Ed25519 identity)
- Which policy was in effect (hash + rule ID)
- When it happened (timestamp inside signature scope)

## Links

- [Signet](https://github.com/Prismer-AI/signet) — Cryptographic action receipts for AI agents
- [Compliance Mapping](https://github.com/Prismer-AI/signet/blob/main/docs/COMPLIANCE.md) — SOC 2, ISO 27001, EU AI Act, DORA
