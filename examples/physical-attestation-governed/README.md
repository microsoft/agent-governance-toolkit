# Physical Attestation Governed Example

Ed25519-signed receipts for physical-world sensor events. Every temperature,
shock, GPS, and light reading from a cold chain attestation sensor is
policy-evaluated and signed, producing the **same receipt format** used by
software agent tool calls in the protect-mcp integration (PRs #667 and #1159).

## Background

This example was developed as part of an active hardware R&D program
(Australian ETCF grant, TRL 4 → 6) for a cold chain attestation sensor
device. The device specification predates this contribution — we're sharing
it here because the physical AI governance gap identified in #787 is exactly
the problem we're solving at the hardware level.

The connection: SINT Protocol's `DynamicEnvelopePlugin` enforces
`maxVelocityMps` and `maxForceNewtons` inline for robotic actuators.
Our sensor enforces `temperature_c < 18.0` and `shock_g < 5.0` inline
for supply chain shipments. Both produce signed receipts that verify with
the same offline CLI. Same pattern, different domain.

## Hardware specification

The simulated sensor matches the ETCF device BOM:

| Component | Part | Role |
|-----------|------|------|
| Temperature + humidity | Sensirion SHT40 | ±0.2°C accuracy, 10-90% RH |
| Accelerometer | ST LIS2DH12 | ±16g range, shock detection |
| GPS | Quectel L76K | Position + timestamp |
| Ambient light | Vishay VEML7700 | Sun exposure detection |
| Secure element | Microchip ATECC608B | Ed25519 key storage + signing |
| MCU | Nordic nRF52840 | BLE 5.0, 256KB RAM |
| NFC | NXP NT3H2111 | Tap-to-verify at delivery |

BOM target: $14.50 at volume (10K units).

## Scenarios

| # | Scenario | What it demonstrates |
|---|----------|---------------------|
| 1 | Cold Chain Journey | 12 readings from Barossa Valley → Tokyo with policy at every step |
| 2 | Temperature Excursion Blocks Release | 22.4°C triggers deny — shipment release blocked |
| 3 | Shock Event Creates Alert | 8.7g shock produces signed alert receipt |
| 4 | Receipt Tamper Detection | Editing any field invalidates the signature |
| 5 | Chain Integrity Verification | Hash-linked chain detects insertions/deletions |
| 6 | Multi-Sensor Correlation | Compound event (temp + shock + lux) in single receipt |
| 7 | Offline Verification | All receipts verify without network |
| 8 | Device Identity Attestation | Boot receipt proves which hardware produced readings |

## Run

```bash
python examples/physical-attestation-governed/getting_started.py
# 8 scenarios, 12 journey receipts, all verified
```

Zero dependencies beyond Python 3.10+.

## Relationship to existing AGT work

| PR | What | Relationship |
|----|------|-------------|
| #667 | ScopeBlind protect-mcp integration | Software tool-call receipts — the software counterpart |
| #1159 | protect-mcp governed example | 8 software scenarios — this PR mirrors with 8 physical scenarios |
| #787 | Physical AI OWASP gap (SINT) | The governance gap this example addresses from the sensor side |

The receipt envelope format (`payload` + `signature`, JCS-canonicalized,
hash-chained via `previousReceiptHash`) is identical across software agent
and physical sensor receipts. A verifier that handles one handles both:

```bash
npx @veritasacta/verify software-receipts.jsonl --key <agent-key>
npx @veritasacta/verify sensor-receipts.jsonl --key <device-key>
# Same CLI, same exit codes, same chain verification
```

## Policy

See `policies/cold-chain-policy.yaml` for the rules. In production firmware,
these translate to Cedar policies evaluated on the device:

```cedar
forbid (
    principal,
    action == Action::"release_shipment",
    resource
) when {
    context.temperature_c > 18.0
};
```

## Standards

- **Ed25519** — RFC 8032 (digital signatures from ATECC608B)
- **JCS** — RFC 8785 (canonical JSON before signing)
- **IETF draft-farley-acta-signed-receipts** — receipt wire format
- **Cedar** — AWS's open authorization engine (device-side policy)

## Note on demonstration signing

This example uses SHA-256 HMAC for signing (no external dependencies).
Production devices use Ed25519 from the ATECC608B secure element. The
receipt **envelope format is identical** — only the `signature.alg` field
changes from `HS256-DEMO` to `EdDSA`.
