#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Physical / IoT Sensor Attestation Governance — Getting Started
==============================================================

Simulates a cold chain shipment with temperature, humidity, GPS, and shock
sensors. Each reading is governed by a Cedar policy and produces a signed
attestation receipt for regulatory accountability.

    python examples/physical-attestation-governed/getting_started.py

What this demonstrates:
  1. Sensor attestation model with governance receipts
  2. Cedar policy enforcement for threshold violations
  3. Tamper detection via cryptographic hashing
  4. End-to-end cold chain monitoring audit trail
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Sensor Attestation Model ────────────────────────────────────────────


@dataclass
class SensorReading:
    """A single reading from a physical sensor."""

    sensor_id: str
    sensor_type: str  # temperature, humidity, gps, shock
    value: float
    unit: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttestationReceipt:
    """Governance receipt binding a sensor reading to a policy decision."""

    receipt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sensor_id: str = ""
    sensor_type: str = ""
    reading_value: float = 0.0
    reading_unit: str = ""
    policy_id: str = ""
    policy_decision: str = "deny"  # allow | deny
    violation_reason: Optional[str] = None
    shipment_id: str = ""
    timestamp: float = field(default_factory=time.time)
    payload_hash: str = ""
    reading_hash: str = ""

    def compute_hashes(self) -> None:
        """Compute tamper-evident hashes for the reading and receipt."""
        reading_data = json.dumps(
            {
                "sensor_id": self.sensor_id,
                "sensor_type": self.sensor_type,
                "value": self.reading_value,
                "unit": self.reading_unit,
                "timestamp": self.timestamp,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        self.reading_hash = hashlib.sha256(reading_data.encode()).hexdigest()

        payload = json.dumps(
            {
                "receipt_id": self.receipt_id,
                "sensor_id": self.sensor_id,
                "reading_hash": self.reading_hash,
                "policy_id": self.policy_id,
                "policy_decision": self.policy_decision,
                "shipment_id": self.shipment_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        self.payload_hash = hashlib.sha256(payload.encode()).hexdigest()


# ── Cold Chain Policy Evaluator ──────────────────────────────────────────


# Thresholds matching the Cedar policy
TEMP_MIN, TEMP_MAX = -25.0, 8.0
HUMIDITY_MIN, HUMIDITY_MAX = 20.0, 80.0
SHOCK_MAX = 5.0


def evaluate_sensor_policy(
    reading: SensorReading, policy_id: str
) -> AttestationReceipt:
    """Evaluate a sensor reading against cold chain governance policy."""
    receipt = AttestationReceipt(
        sensor_id=reading.sensor_id,
        sensor_type=reading.sensor_type,
        reading_value=reading.value,
        reading_unit=reading.unit,
        policy_id=policy_id,
        shipment_id=reading.metadata.get("shipment_id", "unknown"),
        timestamp=reading.timestamp,
    )

    if reading.sensor_type == "temperature":
        if TEMP_MIN <= reading.value <= TEMP_MAX:
            receipt.policy_decision = "allow"
        else:
            receipt.policy_decision = "deny"
            receipt.violation_reason = (
                f"Temperature {reading.value}°C outside safe range "
                f"[{TEMP_MIN}, {TEMP_MAX}]°C"
            )

    elif reading.sensor_type == "humidity":
        if HUMIDITY_MIN <= reading.value <= HUMIDITY_MAX:
            receipt.policy_decision = "allow"
        else:
            receipt.policy_decision = "deny"
            receipt.violation_reason = (
                f"Humidity {reading.value}% outside safe range "
                f"[{HUMIDITY_MIN}, {HUMIDITY_MAX}]%"
            )

    elif reading.sensor_type == "shock":
        if reading.value <= SHOCK_MAX:
            receipt.policy_decision = "allow"
        else:
            receipt.policy_decision = "deny"
            receipt.violation_reason = (
                f"Shock {reading.value}g exceeds damage threshold {SHOCK_MAX}g"
            )

    elif reading.sensor_type == "gps":
        receipt.policy_decision = "allow"

    else:
        receipt.policy_decision = "deny"
        receipt.violation_reason = f"Unknown sensor type: {reading.sensor_type}"

    receipt.compute_hashes()
    return receipt


# ── Simulated Cold Chain Shipment ────────────────────────────────────────


def simulate_shipment() -> List[SensorReading]:
    """Simulate a pharmaceutical cold chain shipment with mixed readings."""
    shipment_id = "SHIP-2026-04-27-001"
    base_time = time.time()

    readings = [
        # Normal readings — should be allowed
        SensorReading(
            "TEMP-001", "temperature", 2.3, "°C",
            base_time, {"shipment_id": shipment_id, "location": "warehouse"},
        ),
        SensorReading(
            "TEMP-001", "temperature", 4.1, "°C",
            base_time + 3600, {"shipment_id": shipment_id, "location": "loading_dock"},
        ),
        SensorReading(
            "HUM-001", "humidity", 45.0, "%",
            base_time + 3600, {"shipment_id": shipment_id, "location": "loading_dock"},
        ),
        SensorReading(
            "GPS-001", "gps", 40.7128, "lat",
            base_time + 7200, {"shipment_id": shipment_id, "lon": -74.0060},
        ),
        SensorReading(
            "SHOCK-001", "shock", 1.2, "g",
            base_time + 7200, {"shipment_id": shipment_id, "location": "in_transit"},
        ),
        # Violation readings — should be denied
        SensorReading(
            "TEMP-001", "temperature", 12.5, "°C",
            base_time + 10800,
            {"shipment_id": shipment_id, "location": "in_transit",
             "note": "refrigeration failure"},
        ),
        SensorReading(
            "HUM-001", "humidity", 92.0, "%",
            base_time + 10800,
            {"shipment_id": shipment_id, "location": "in_transit",
             "note": "seal breach"},
        ),
        SensorReading(
            "SHOCK-001", "shock", 8.7, "g",
            base_time + 14400,
            {"shipment_id": shipment_id, "location": "in_transit",
             "note": "impact event"},
        ),
    ]
    return readings


# ── Main ─────────────────────────────────────────────────────────────────


def main() -> None:
    policy_path = Path(__file__).parent / "policies" / "cold-chain.cedar"

    print("=" * 60)
    print("  Physical / IoT Sensor Attestation Governance")
    print("  Cold Chain Monitoring Demo")
    print("=" * 60)
    print(f"\nCedar policy: {policy_path.name}")

    readings = simulate_shipment()
    receipts: List[AttestationReceipt] = []
    policy_id = "policy:cold-chain:v1"

    print(f"Shipment: {readings[0].metadata.get('shipment_id', 'unknown')}")
    print(f"Sensors: {len(set(r.sensor_id for r in readings))} devices, "
          f"{len(readings)} readings\n")
    print(f"{'Sensor':<12} {'Type':<12} {'Value':<12} {'Decision':<10} {'Details'}")
    print("─" * 70)

    for reading in readings:
        receipt = evaluate_sensor_policy(reading, policy_id)
        receipts.append(receipt)

        icon = "✅" if receipt.policy_decision == "allow" else "🚫"
        value_str = f"{reading.value}{reading.unit}"
        detail = receipt.violation_reason or "within policy"

        print(
            f"  {icon} {reading.sensor_id:<10} {reading.sensor_type:<12} "
            f"{value_str:<12} {receipt.policy_decision:<10} {detail}"
        )

    # Audit summary
    allowed = sum(1 for r in receipts if r.policy_decision == "allow")
    denied = sum(1 for r in receipts if r.policy_decision == "deny")
    sensors = len(set(r.sensor_id for r in receipts))

    print("\n" + "─" * 70)
    print(f"\n📊 Attestation Summary:")
    print(f"   Total readings:     {len(receipts)}")
    print(f"   Compliant:          {allowed}")
    print(f"   Violations:         {denied}")
    print(f"   Unique sensors:     {sensors}")

    # Tamper detection demo
    print(f"\n🔐 Tamper Detection:")
    sample = receipts[0]
    print(f"   Receipt:      {sample.receipt_id[:16]}...")
    print(f"   Reading hash: {sample.reading_hash[:32]}...")
    print(f"   Payload hash: {sample.payload_hash[:32]}...")

    # Verify integrity
    original_hash = sample.payload_hash
    sample.compute_hashes()
    integrity = "✅ VERIFIED" if sample.payload_hash == original_hash else "❌ TAMPERED"
    print(f"   Integrity:    {integrity}")

    # Simulate tampering
    sample.reading_value = 999.0
    sample.compute_hashes()
    tampered = "✅ VERIFIED" if sample.payload_hash == original_hash else "🚫 DETECTED"
    print(f"   After tamper: {tampered}")

    # Violations detail
    violations = [r for r in receipts if r.policy_decision == "deny"]
    if violations:
        print(f"\n⚠️  Violations Requiring Escalation:")
        for v in violations:
            print(f"   • {v.sensor_id} ({v.sensor_type}): {v.violation_reason}")

    print(f"\n✨ Done! All {len(receipts)} sensor readings have attestation receipts.")
    print("\nNext steps:")
    print("  📚 Cedar policies:  examples/physical-attestation-governed/policies/")
    print("  🔐 MCP receipts:    examples/mcp-receipt-governed/")
    print("  🌐 Agent governance: docs/tutorials/01-policy-engine.md")


if __name__ == "__main__":
    main()
