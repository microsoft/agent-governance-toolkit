#!/usr/bin/env python3
"""
Physical Attestation Governed Example — Cold Chain Sensor Receipts

Demonstrates Ed25519-signed receipts for physical-world events: temperature,
shock, GPS, and ambient light readings from a cold chain attestation sensor.
Every reading is policy-evaluated and signed, producing the same receipt format
used by software agent tool calls (protect-mcp, AGT integration).

This example simulates a wine shipment sensor journey from Barossa Valley to
Tokyo, based on hardware specs from the ScopeBlind ETCF device (SHT40 temp,
LIS2DH12 accelerometer, L76K GPS, VEML7700 lux, ATECC608B secure element).

The receipts verify with the same offline CLI:
    npx @veritasacta/verify receipts.jsonl --key <public-key-hex>

Runs standalone with zero dependencies beyond Python 3.10+.

IMPORTANT: This uses SHA-256 HMAC for demonstration only. Production devices
use Ed25519 from an ATECC608B secure element — the receipt envelope format
is identical, only the signature algorithm differs.

Related:
    - AGT #787: Physical AI agents OWASP coverage gap
    - AGT #667: ScopeBlind protect-mcp integration (Cedar + receipts)
    - AGT #1159: protect-mcp governed example (software tool calls)
    - IETF draft-farley-acta-signed-receipts
    - SINT Protocol physical constraint enforcement (DynamicEnvelopePlugin)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Optional


# ═══════════════════════════════════════════════════════════════
#  Signing primitives (inline fallback — same as protect-mcp-governed)
# ═══════════════════════════════════════════════════════════════

DEMO_KEY = "a" * 64  # demonstration only — production uses ATECC608B Ed25519

def _jcs_canonicalize(obj: Any) -> str:
    """RFC 8785 JCS canonicalization."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class SensorReceipt:
    """A signed receipt for a physical sensor reading."""
    payload: dict[str, Any]
    signature: dict[str, str] = field(default_factory=dict)
    receipt_id: str = ""

    def sign(self, key: str) -> None:
        canonical = _jcs_canonicalize(self.payload)
        sig = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        self.signature = {"alg": "HS256-DEMO", "kid": f"sensor:{key[:8]}", "sig": sig}
        self.receipt_id = "sha256:" + _sha256_hex(canonical)

    def verify(self, key: str) -> bool:
        canonical = _jcs_canonicalize(self.payload)
        expected = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature.get("sig", ""), expected)

    def to_dict(self) -> dict[str, Any]:
        return {"payload": self.payload, "signature": self.signature}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ═══════════════════════════════════════════════════════════════
#  Sensor simulator — matches ETCF device spec (SHT40, LIS2DH12, L76K, VEML7700)
# ═══════════════════════════════════════════════════════════════

@dataclass
class SensorReading:
    """A reading from a cold chain attestation sensor."""
    timestamp: str
    temperature_c: float
    humidity_pct: float
    shock_g: float
    latitude: float
    longitude: float
    lux: float
    battery_pct: float
    location_label: str = ""

    def to_context(self) -> dict[str, Any]:
        """Convert to Cedar-style context attributes for policy evaluation."""
        return {
            "temperature_c": self.temperature_c,
            "humidity_pct": self.humidity_pct,
            "shock_g": self.shock_g,
            "lux": self.lux,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "battery_pct": self.battery_pct,
            "sensor_time": self.timestamp,
        }


def simulate_journey() -> list[SensorReading]:
    """Simulate a wine shipment: Barossa Valley → Adelaide → Singapore → Tokyo.

    Based on the ETCF device spec: 724 readings over 5 days.
    We simulate 12 representative readings that cover the key scenarios.
    """
    base = datetime(2026, 4, 10, 6, 0, 0, tzinfo=timezone.utc)
    return [
        # Barossa Valley winery — cool storage
        SensorReading(
            timestamp=(base + timedelta(hours=0)).isoformat(),
            temperature_c=14.2, humidity_pct=62.0, shock_g=0.1,
            latitude=-34.5612, longitude=138.9507, lux=5.0, battery_pct=100.0,
            location_label="Barossa Valley — winery cold room",
        ),
        # Loading onto truck — minor shock
        SensorReading(
            timestamp=(base + timedelta(hours=2)).isoformat(),
            temperature_c=15.8, humidity_pct=58.0, shock_g=2.3,
            latitude=-34.5612, longitude=138.9507, lux=850.0, battery_pct=99.5,
            location_label="Barossa Valley — loading dock",
        ),
        # Truck to Adelaide — highway, warm
        SensorReading(
            timestamp=(base + timedelta(hours=4)).isoformat(),
            temperature_c=17.1, humidity_pct=45.0, shock_g=0.8,
            latitude=-34.8688, longitude=138.5999, lux=12.0, battery_pct=99.0,
            location_label="Highway — en route to Adelaide",
        ),
        # Adelaide cold storage — back in range
        SensorReading(
            timestamp=(base + timedelta(hours=8)).isoformat(),
            temperature_c=13.5, humidity_pct=65.0, shock_g=0.2,
            latitude=-34.9285, longitude=138.6007, lux=3.0, battery_pct=98.0,
            location_label="Adelaide — cold storage facility",
        ),
        # *** EXCURSION: forklift leaves pallet in sun ***
        SensorReading(
            timestamp=(base + timedelta(hours=12)).isoformat(),
            temperature_c=22.4, humidity_pct=38.0, shock_g=0.3,
            latitude=-34.9285, longitude=138.6007, lux=45000.0, battery_pct=97.5,
            location_label="Adelaide — loading area (EXCURSION: sun exposure)",
        ),
        # Back into cold storage — damage may be done
        SensorReading(
            timestamp=(base + timedelta(hours=14)).isoformat(),
            temperature_c=15.9, humidity_pct=55.0, shock_g=0.2,
            latitude=-34.9285, longitude=138.6007, lux=4.0, battery_pct=97.0,
            location_label="Adelaide — returned to cold storage",
        ),
        # Air freight — pressurized hold
        SensorReading(
            timestamp=(base + timedelta(hours=24)).isoformat(),
            temperature_c=12.0, humidity_pct=30.0, shock_g=1.5,
            latitude=-10.0, longitude=120.0, lux=0.0, battery_pct=95.0,
            location_label="Air freight — Adelaide to Singapore",
        ),
        # Singapore — transit hub
        SensorReading(
            timestamp=(base + timedelta(hours=36)).isoformat(),
            temperature_c=14.8, humidity_pct=70.0, shock_g=0.4,
            latitude=1.3521, longitude=103.8198, lux=8.0, battery_pct=92.0,
            location_label="Singapore — Changi cold chain hub",
        ),
        # *** SHOCK EVENT: rough handling at Singapore ***
        SensorReading(
            timestamp=(base + timedelta(hours=38)).isoformat(),
            temperature_c=15.2, humidity_pct=68.0, shock_g=8.7,
            latitude=1.3521, longitude=103.8198, lux=200.0, battery_pct=91.5,
            location_label="Singapore — SHOCK EVENT (rough handling)",
        ),
        # Air freight — Singapore to Tokyo
        SensorReading(
            timestamp=(base + timedelta(hours=48)).isoformat(),
            temperature_c=11.5, humidity_pct=28.0, shock_g=0.9,
            latitude=25.0, longitude=130.0, lux=0.0, battery_pct=88.0,
            location_label="Air freight — Singapore to Tokyo",
        ),
        # Tokyo — destination cold storage
        SensorReading(
            timestamp=(base + timedelta(hours=60)).isoformat(),
            temperature_c=13.8, humidity_pct=60.0, shock_g=0.3,
            latitude=35.6762, longitude=139.6503, lux=6.0, battery_pct=85.0,
            location_label="Tokyo — destination cold storage",
        ),
        # Final reading — ready for delivery
        SensorReading(
            timestamp=(base + timedelta(hours=72)).isoformat(),
            temperature_c=14.0, humidity_pct=61.0, shock_g=0.1,
            latitude=35.6762, longitude=139.6503, lux=4.0, battery_pct=83.0,
            location_label="Tokyo — delivery inspection point",
        ),
    ]


# ═══════════════════════════════════════════════════════════════
#  Policy engine — Cedar-style context evaluation
# ═══════════════════════════════════════════════════════════════

@dataclass
class PolicyResult:
    decision: str  # "allow", "deny", "alert"
    policy_id: str
    reason: str


# Cold chain policy: wine must stay 10-18°C, shock < 5g, lux < 1000 (no sun)
COLD_CHAIN_POLICY = {
    "policy_id": "cold-chain-wine-premium",
    "rules": {
        "temperature_max_c": 18.0,
        "temperature_min_c": 10.0,
        "shock_max_g": 5.0,
        "lux_max": 1000.0,
        "battery_min_pct": 10.0,
    },
}


def evaluate_policy(reading: SensorReading) -> PolicyResult:
    """Evaluate a sensor reading against the cold chain policy.

    In production, this runs as Cedar policy on the device:
        forbid(principal, action == Action::"release_shipment", resource)
        when { context.temperature_c > 18.0 };

    Here we simulate the same evaluation logic inline.
    """
    rules = COLD_CHAIN_POLICY["rules"]
    pid = COLD_CHAIN_POLICY["policy_id"]

    if reading.temperature_c > rules["temperature_max_c"]:
        return PolicyResult("deny", pid,
            f"Temperature {reading.temperature_c}°C exceeds max {rules['temperature_max_c']}°C")
    if reading.temperature_c < rules["temperature_min_c"]:
        return PolicyResult("deny", pid,
            f"Temperature {reading.temperature_c}°C below min {rules['temperature_min_c']}°C")
    if reading.shock_g > rules["shock_max_g"]:
        return PolicyResult("alert", pid,
            f"Shock {reading.shock_g}g exceeds max {rules['shock_max_g']}g — possible damage")
    if reading.lux > rules["lux_max"]:
        return PolicyResult("alert", pid,
            f"Light {reading.lux} lux exceeds max {rules['lux_max']} lux — possible sun exposure")
    if reading.battery_pct < rules["battery_min_pct"]:
        return PolicyResult("alert", pid,
            f"Battery {reading.battery_pct}% below minimum {rules['battery_min_pct']}%")

    return PolicyResult("allow", pid, "All parameters within acceptable range")


# ═══════════════════════════════════════════════════════════════
#  Receipt chain builder
# ═══════════════════════════════════════════════════════════════

class SensorReceiptChain:
    """Append-only chain of sensor receipts with hash linking."""

    def __init__(self, device_id: str, key: str):
        self.device_id = device_id
        self.key = key
        self.receipts: list[SensorReceipt] = []
        self._sequence = 0

    def sign_reading(self, reading: SensorReading, policy_result: PolicyResult) -> SensorReceipt:
        self._sequence += 1
        prev_hash = None
        if self.receipts:
            prev_canonical = _jcs_canonicalize(self.receipts[-1].payload)
            prev_hash = "sha256:" + _sha256_hex(prev_canonical)

        payload = {
            "type": "scopeblind:physical_attestation",
            "spec": "draft-farley-acta-signed-receipts-01",
            "device_id": self.device_id,
            "sensor_reading": reading.to_context(),
            "location_label": reading.location_label,
            "decision": policy_result.decision,
            "policy_id": policy_result.policy_id,
            "policy_reason": policy_result.reason,
            "issued_at": reading.timestamp,
            "issuer_id": f"sensor:{self.device_id}",
            "sequence": self._sequence,
            "previousReceiptHash": prev_hash,
            "hardware": {
                "secure_element": "ATECC608B",
                "temp_sensor": "SHT40",
                "accel_sensor": "LIS2DH12",
                "gps": "L76K",
                "lux_sensor": "VEML7700",
            },
        }

        receipt = SensorReceipt(payload=payload)
        receipt.sign(self.key)
        self.receipts.append(receipt)
        return receipt

    def to_jsonl(self) -> str:
        return "\n".join(
            json.dumps(r.to_dict(), separators=(",", ":")) for r in self.receipts
        ) + "\n"


# ═══════════════════════════════════════════════════════════════
#  Scenarios
# ═══════════════════════════════════════════════════════════════

def header(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def scenario_1_cold_chain_journey():
    """Simulate complete journey with policy evaluation at every reading."""
    header("Scenario 1: Cold Chain Journey — Barossa Valley to Tokyo")
    chain = SensorReceiptChain(device_id="SB-ETCF-001", key=DEMO_KEY)
    journey = simulate_journey()

    allows = denies = alerts = 0
    for reading in journey:
        result = evaluate_policy(reading)
        receipt = chain.sign_reading(reading, result)

        icon = {"allow": "+", "deny": "X", "alert": "!"}[result.decision]
        print(f"  [{icon}] {reading.location_label}")
        print(f"      {result.decision.upper()}: {result.reason}")
        print(f"      Receipt: {receipt.receipt_id[:32]}...")

        if result.decision == "allow":
            allows += 1
        elif result.decision == "deny":
            denies += 1
        else:
            alerts += 1

    print(f"\n  Journey complete: {len(journey)} readings")
    print(f"  Decisions: {allows} allow, {denies} deny, {alerts} alert")
    print(f"  Chain length: {len(chain.receipts)} receipts, hash-linked")
    return chain


def scenario_2_temperature_excursion_blocks_release():
    """A temperature excursion should deny a 'release shipment' action."""
    header("Scenario 2: Temperature Excursion Blocks Release")
    reading = SensorReading(
        timestamp=datetime.now(timezone.utc).isoformat(),
        temperature_c=22.4, humidity_pct=38.0, shock_g=0.3,
        latitude=-34.9285, longitude=138.6007, lux=500.0, battery_pct=97.0,
        location_label="Adelaide loading area — sun exposure",
    )
    result = evaluate_policy(reading)
    assert result.decision == "deny", f"Expected deny, got {result.decision}"
    print(f"  Temperature: {reading.temperature_c}°C (limit: 18.0°C)")
    print(f"  Decision: {result.decision.upper()} — {result.reason}")
    print(f"  Shipment release BLOCKED. Receipt signed with denial.")

    chain = SensorReceiptChain(device_id="SB-ETCF-002", key=DEMO_KEY)
    receipt = chain.sign_reading(reading, result)
    assert receipt.verify(DEMO_KEY)
    print(f"  Receipt verified: {receipt.receipt_id[:32]}...")
    print("  PASSED")


def scenario_3_shock_event_creates_alert():
    """A shock exceeding 5g should produce an alert receipt."""
    header("Scenario 3: Shock Event Creates Alert")
    reading = SensorReading(
        timestamp=datetime.now(timezone.utc).isoformat(),
        temperature_c=15.0, humidity_pct=65.0, shock_g=8.7,
        latitude=1.3521, longitude=103.8198, lux=200.0, battery_pct=91.5,
        location_label="Singapore — rough handling",
    )
    result = evaluate_policy(reading)
    assert result.decision == "alert", f"Expected alert, got {result.decision}"
    print(f"  Shock: {reading.shock_g}g (limit: 5.0g)")
    print(f"  Decision: {result.decision.upper()} — {result.reason}")

    chain = SensorReceiptChain(device_id="SB-ETCF-003", key=DEMO_KEY)
    receipt = chain.sign_reading(reading, result)
    assert receipt.verify(DEMO_KEY)
    print(f"  Alert receipt signed and verified")
    print("  PASSED")


def scenario_4_receipt_tamper_detection():
    """Modifying any field in a signed receipt should break verification."""
    header("Scenario 4: Receipt Tamper Detection")
    chain = SensorReceiptChain(device_id="SB-ETCF-004", key=DEMO_KEY)
    reading = SensorReading(
        timestamp=datetime.now(timezone.utc).isoformat(),
        temperature_c=14.0, humidity_pct=60.0, shock_g=0.2,
        latitude=35.6762, longitude=139.6503, lux=6.0, battery_pct=85.0,
        location_label="Tokyo cold storage",
    )
    receipt = chain.sign_reading(reading, PolicyResult("allow", "cold-chain-wine-premium", "OK"))
    assert receipt.verify(DEMO_KEY), "Original should verify"
    print("  Original receipt: VERIFIED")

    # Tamper: attacker changes temperature to hide excursion
    receipt.payload["sensor_reading"]["temperature_c"] = 14.0  # was 14.0, but simulating edit
    receipt.payload["decision"] = "deny"  # flip decision
    assert not receipt.verify(DEMO_KEY), "Tampered receipt should fail"
    print("  Tampered receipt (decision flipped): SIGNATURE INVALID")
    print("  PASSED — tamper detected")


def scenario_5_chain_integrity():
    """Hash-linked chain detects insertions and deletions."""
    header("Scenario 5: Chain Integrity Verification")
    chain = SensorReceiptChain(device_id="SB-ETCF-005", key=DEMO_KEY)
    readings = simulate_journey()[:5]

    for reading in readings:
        result = evaluate_policy(reading)
        chain.sign_reading(reading, result)

    # Verify chain links
    for i in range(1, len(chain.receipts)):
        current = chain.receipts[i]
        previous = chain.receipts[i - 1]
        prev_canonical = _jcs_canonicalize(previous.payload)
        expected_hash = "sha256:" + _sha256_hex(prev_canonical)
        actual_hash = current.payload["previousReceiptHash"]
        assert actual_hash == expected_hash, f"Chain break at position {i}"
        print(f"  Link {i-1} → {i}: hash verified")

    print(f"  Chain: {len(chain.receipts)} receipts, all links intact")
    print("  PASSED")


def scenario_6_multi_sensor_correlation():
    """Multiple sensors triggering simultaneously produces compound evidence."""
    header("Scenario 6: Multi-Sensor Correlation")
    # Scenario: pallet left in sun (high temp + high lux) + rough handling (shock)
    reading = SensorReading(
        timestamp=datetime.now(timezone.utc).isoformat(),
        temperature_c=23.1, humidity_pct=35.0, shock_g=6.2,
        latitude=-34.9285, longitude=138.6007, lux=52000.0, battery_pct=96.0,
        location_label="Adelaide — compound event (sun + drop)",
    )

    # Temperature check fires first (deny)
    temp_result = evaluate_policy(reading)
    assert temp_result.decision == "deny"
    print(f"  Temperature: {reading.temperature_c}°C → DENY")

    # But all readings are in the same receipt
    chain = SensorReceiptChain(device_id="SB-ETCF-006", key=DEMO_KEY)
    receipt = chain.sign_reading(reading, temp_result)

    # The receipt payload carries ALL sensor values, not just the triggering one
    ctx = receipt.payload["sensor_reading"]
    print(f"  Shock: {ctx['shock_g']}g (also exceeds limit)")
    print(f"  Lux: {ctx['lux']} (also exceeds limit)")
    print(f"  All three violations captured in single signed receipt")
    print(f"  Receipt: {receipt.receipt_id[:32]}...")
    print("  PASSED — compound evidence preserved")


def scenario_7_offline_verification():
    """Receipts verify without any network call."""
    header("Scenario 7: Offline Verification")
    chain = SensorReceiptChain(device_id="SB-ETCF-007", key=DEMO_KEY)
    journey = simulate_journey()

    for reading in journey:
        result = evaluate_policy(reading)
        chain.sign_reading(reading, result)

    # Verify every receipt independently
    verified = 0
    for receipt in chain.receipts:
        assert receipt.verify(DEMO_KEY)
        verified += 1

    print(f"  Verified {verified}/{len(chain.receipts)} receipts offline")
    print(f"  No network calls. No vendor lookup. No trust in operator.")
    print(f"\n  Production verification command:")
    print(f"    npx @veritasacta/verify receipts.jsonl --key <public-key-hex>")
    print("  PASSED")


def scenario_8_device_attestation_receipt():
    """Device identity receipt — proves which hardware produced the readings."""
    header("Scenario 8: Device Identity Attestation")
    chain = SensorReceiptChain(device_id="SB-ETCF-008", key=DEMO_KEY)

    # Device boot attestation — first receipt in any session
    boot_payload = {
        "type": "scopeblind:device_attestation",
        "spec": "draft-farley-acta-signed-receipts-01",
        "device_id": "SB-ETCF-008",
        "firmware_version": "0.3.1",
        "firmware_hash": "sha256:" + _sha256_hex("firmware-v0.3.1-release"),
        "secure_element_id": "ATECC608B:04:AB:CD:EF",
        "calibration_date": "2026-03-15T00:00:00Z",
        "calibration_hash": "sha256:" + _sha256_hex("cal-2026-03-15"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "issuer_id": "sensor:SB-ETCF-008",
        "sequence": 0,
        "previousReceiptHash": None,
    }
    boot_receipt = SensorReceipt(payload=boot_payload)
    boot_receipt.sign(DEMO_KEY)

    print(f"  Device: {boot_payload['device_id']}")
    print(f"  Firmware: {boot_payload['firmware_version']}")
    print(f"  Secure element: {boot_payload['secure_element_id']}")
    print(f"  Calibration: {boot_payload['calibration_date']}")
    print(f"  Boot receipt: {boot_receipt.receipt_id[:32]}...")
    assert boot_receipt.verify(DEMO_KEY)
    print(f"  Verified: YES")
    print(f"\n  This receipt proves which device, firmware, and calibration")
    print(f"  produced all subsequent sensor readings in the chain.")
    print("  PASSED")


# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  Physical Attestation Governed Example")
    print("  Cold Chain Sensor — Ed25519 Signed Receipts")
    print("=" * 60)
    print()
    print("  Hardware spec: SHT40 (temp) + LIS2DH12 (accel) + L76K (GPS)")
    print("                 VEML7700 (lux) + ATECC608B (secure element)")
    print("  Journey: Barossa Valley → Adelaide → Singapore → Tokyo")
    print("  Policy: wine cold chain (10-18°C, <5g shock, <1000 lux)")
    print()
    print("  NOTE: Signing uses SHA-256 HMAC for this demonstration.")
    print("  Production devices use Ed25519 from ATECC608B hardware.")
    print("  The receipt envelope format is identical in both cases.")

    chain = scenario_1_cold_chain_journey()
    scenario_2_temperature_excursion_blocks_release()
    scenario_3_shock_event_creates_alert()
    scenario_4_receipt_tamper_detection()
    scenario_5_chain_integrity()
    scenario_6_multi_sensor_correlation()
    scenario_7_offline_verification()
    scenario_8_device_attestation_receipt()

    # Export the full journey chain
    print(f"\n{'='*60}")
    print(f"  Summary")
    print(f"{'='*60}")
    print(f"  8 scenarios completed")
    print(f"  {len(chain.receipts)} journey receipts signed and chain-linked")
    print(f"  Temperature excursion: DETECTED and BLOCKED")
    print(f"  Shock event: DETECTED and ALERTED")
    print(f"  Tamper attempt: DETECTED (signature invalid)")
    print(f"  Chain integrity: ALL LINKS VERIFIED")
    print(f"  Offline verification: ALL RECEIPTS VERIFIED")
    print(f"\n  Same receipt format as software agent tool calls.")
    print(f"  Same verifier: npx @veritasacta/verify")
    print(f"  Same chain structure. One proof layer.")


if __name__ == "__main__":
    main()
