# Physical / IoT Sensor Attestation Governance

Demonstrates governance receipts for physical sensor data in supply chain
and cold chain logistics scenarios. Each sensor reading is policy-checked
and receipted with tamper-evident hashing for regulatory accountability.

## What This Shows

1. **Sensor attestation model** — governance receipts for physical readings
   (temperature, humidity, GPS, shock/vibration)
2. **Cedar policy enforcement** — threshold-based permit/forbid rules for
   cold chain compliance
3. **Tamper detection** — SHA-256 hashing of reading data and receipt payloads
4. **Audit trail** — all readings produce receipts regardless of decision

## Architecture

```
┌──────────────┐    ┌─────────────────┐    ┌──────────────────┐
│  IoT Sensor  │───>│  Cedar Policy   │───>│   Attestation    │
│  (reading)   │    │  Evaluator      │    │   Receipt        │
└──────────────┘    └─────────────────┘    └──────────────────┘
                          │                        │
                    ┌─────┴──────┐          ┌──────┴───────┐
                    │ Thresholds │          │ Tamper-proof │
                    │ permit/    │          │ SHA-256 hash │
                    │ forbid     │          │ chain        │
                    └────────────┘          └──────────────┘
```

## Sensor Types and Thresholds

| Sensor | Safe Range | Violation Action |
|--------|-----------|------------------|
| Temperature | -25°C to 8°C | Excursion alert |
| Humidity | 20% to 80% | Seal breach alert |
| Shock | ≤ 5.0g | Damage alert |
| GPS | Any | Always permitted |

## Setup

No dependencies required — uses Python stdlib only.

```bash
python examples/physical-attestation-governed/getting_started.py
```

## Expected Output

```
══════════════════════════════════════════════════════════════
  Physical / IoT Sensor Attestation Governance
  Cold Chain Monitoring Demo
══════════════════════════════════════════════════════════════

Cedar policy: cold-chain.cedar
Shipment: SHIP-2026-04-27-001
Sensors: 4 devices, 8 readings

Sensor       Type         Value        Decision   Details
──────────────────────────────────────────────────────────────────────
  ✅ TEMP-001    temperature  2.3°C        allow      within policy
  ✅ TEMP-001    temperature  4.1°C        allow      within policy
  ✅ HUM-001     humidity     45.0%        allow      within policy
  ✅ GPS-001     gps          40.7128lat   allow      within policy
  ✅ SHOCK-001   shock        1.2g         allow      within policy
  🚫 TEMP-001    temperature  12.5°C       deny       Temperature excursion
  🚫 HUM-001     humidity     92.0%        deny       Humidity outside range
  🚫 SHOCK-001   shock        8.7g         deny       Shock exceeds threshold

📊 Attestation Summary:
   Total readings:     8
   Compliant:          5
   Violations:         3
   Unique sensors:     4

🔐 Tamper Detection:
   Integrity:    ✅ VERIFIED
   After tamper: 🚫 DETECTED
```

## Files

| File | Purpose |
|------|---------|
| `getting_started.py` | Self-contained demo with simulated sensor data |
| `policies/cold-chain.cedar` | Cedar policy for cold chain thresholds |

## Use Cases

- **Pharmaceutical cold chain** — FDA 21 CFR Part 11 compliance
- **Food safety** — HACCP temperature monitoring
- **Industrial IoT** — equipment vibration governance
- **Logistics** — shipment integrity verification

## License

MIT
