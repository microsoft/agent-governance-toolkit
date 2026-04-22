#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
sb-runtime Governed Example — Getting Started

Demonstrates the distinctive architectural claim of the sb-runtime integration:
a single Cedar policy produces semantically-equivalent signed receipts
regardless of the sandbox layer that wraps the agent process. The sandbox
backend is recorded in the signed payload so auditors can see which layer
ran (sb-runtime's own Landlock + seccomp, nono, OpenShell, or none), but
signature verification and policy-digest pinning are identical across all
backends.

Three scenarios run against the same policy and same operator key:

    1. Standalone sb-runtime (Ring 3)
           sandbox_backend = "sb_runtime_builtin"
           sb-runtime's own Landlock + seccomp owns the sandbox.

    2. sb-runtime + nono (Ring 2)
           sandbox_backend = "nono"
           A nono capability set wraps the process; sb-runtime contributes
           only Cedar evaluation + receipt signing.

    3. sb-runtime + OpenShell (Ring 2)
           sandbox_backend = "openshell"
           An OpenShell container boundary; sb-runtime contributes only
           Cedar + receipts.

All 18 receipts (6 actions x 3 scenarios) verify against the same operator
public key. The demo then tampers with the `sandbox_backend` field in one
receipt to prove that the backend choice is covered by the Ed25519
signature, not just sidecar metadata.

Usage:
    pip install -e packages/agentmesh-integrations/sb-runtime-skill/
    python examples/sb-runtime-governed/getting_started.py

Background:
    - Integration doc: docs/integrations/sb-runtime.md (merged as PR #1202)
    - Provider shim:   packages/agentmesh-integrations/sb-runtime-skill/ (merged as PR #1203)
    - Receipt format:  draft-farley-acta-signed-receipts-02
    - Offline verifier: npx @veritasacta/verify (Apache-2.0, zero dependencies)
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

# Import the skill from the in-tree package. Works without a pip install,
# matching the openshell-governed example's convention.
ROOT = Path(__file__).resolve().parent.parent.parent
SKILL_DIR = ROOT / "packages" / "agentmesh-integrations" / "sb-runtime-skill"
sys.path.insert(0, str(SKILL_DIR))

try:
    from sb_runtime_agentmesh.skill import GovernanceSkill, SandboxBackend
    from sb_runtime_agentmesh.receipts import (
        Signer,
        receipt_hash,
        verify_receipt,
    )
except ImportError as exc:
    print(
        "\n  This example requires sb-runtime-skill to be importable.\n"
        "  Run: pip install -e packages/agentmesh-integrations/sb-runtime-skill/\n"
        "\n  or ensure the repository layout is intact; the example imports\n"
        "  from packages/agentmesh-integrations/sb-runtime-skill/ directly.\n"
        f"\n  Import error: {exc}\n"
    )
    raise SystemExit(2)

from cryptography.hazmat.primitives import serialization

POLICY_DIR = Path(__file__).parent / "policies"
AGENT_DID = "did:mesh:sb-runtime-demo-agent"

# One tool call series exercised under each sandbox backend. Three allowed,
# three denied, deliberately identical to the openshell-governed example's
# action list for cross-example comparison.
ACTIONS = [
    ("file:read:/workspace/main.py", "Read source file"),
    ("shell:python", "Run Python interpreter"),
    ("shell:git", "Git commit"),
    ("shell:rm -rf /tmp", "Destructive shell"),
    ("http:GET:169.254.169.254/metadata", "Cloud metadata exfiltration"),
    ("file:write:/etc/shadow", "System-file write"),
]


@dataclass
class ScenarioResult:
    name: str
    backend: SandboxBackend
    ring: int
    receipts: list[dict]


def run_scenario(
    name: str,
    backend: SandboxBackend,
    ring: int,
    operator_signer: Signer,
) -> ScenarioResult:
    """Run the same six actions through a ScopeBlindExtension... wait, wrong
    class: through GovernanceSkill — configured for one specific sandbox
    backend. Collect the emitted receipts. Return for cross-verification.
    """
    skill = GovernanceSkill(
        policy_dir=POLICY_DIR,
        signer=operator_signer,
        sandbox_backend=backend,
        ring=ring,
    )
    receipts = []
    for action, _desc in ACTIONS:
        decision = skill.check_policy(action, context={"agent_did": AGENT_DID})
        assert decision.receipt is not None, "sign is on by default"
        receipts.append(decision.receipt)
    return ScenarioResult(name=name, backend=backend, ring=ring, receipts=receipts)


def print_scenario_summary(r: ScenarioResult) -> None:
    allowed = sum(1 for rec in r.receipts if rec["payload"]["decision"] == "allow")
    denied = len(r.receipts) - allowed
    kid = r.receipts[0]["signature"]["kid"][:16] + "..."
    digest = r.receipts[0]["payload"]["policy_digest"][:24] + "..."
    print(f"  Scenario: {r.name}")
    print(f"    sandbox_backend = \"{r.backend.value}\"  ring={r.ring}")
    print(f"    receipts:      {len(r.receipts)}  ({allowed} allow, {denied} deny)")
    print(f"    operator kid:  {kid}")
    print(f"    policy digest: {digest}")
    # Show the sandbox_backend field in a sample payload so its presence
    # is unambiguous to the reader of the demo output.
    sample = r.receipts[0]["payload"]
    print(f"    sample payload fields:  "
          f"type={sample['type']}  "
          f"ring={sample['ring']}  "
          f"sandbox_backend={sample['sandbox_backend']}")
    print()


def verify_all_receipts(
    results: list[ScenarioResult],
    operator_signer: Signer,
) -> int:
    """Verify every receipt from every scenario against the same public key.

    Demonstrates the central claim: the verification path is identical
    regardless of which sandbox backend produced the receipt. The operator
    publishes one public key; auditors verify any receipt against it.
    """
    pub = serialization.load_pem_public_key(operator_signer.public_pem())
    total = 0
    verified = 0
    for r in results:
        for rec in r.receipts:
            total += 1
            if verify_receipt(rec, pub):
                verified += 1
            else:  # pragma: no cover - defensive; shouldn't happen in a clean run
                print(f"    FAILED: {rec['payload']['action']} "
                      f"[{r.backend.value}]")
    return total, verified


def demonstrate_tampering(
    results: list[ScenarioResult],
    operator_signer: Signer,
) -> None:
    """Flip `sandbox_backend` in one receipt, confirm verification fails.

    This is the integrity claim the `sandbox_backend` field makes. The
    field is inside the Ed25519 signature scope, not carried alongside it,
    so an attacker claiming a Ring 3 hardened run actually used `none`
    (no sandbox) would be detected at verify time.
    """
    pub = serialization.load_pem_public_key(operator_signer.public_pem())
    # Pick a receipt from the nono scenario and flip it to claim sb_runtime_builtin
    victim_scenario = next(r for r in results if r.backend is SandboxBackend.NONO)
    original = victim_scenario.receipts[0]
    tampered = {
        "payload": {**original["payload"], "sandbox_backend": "sb_runtime_builtin"},
        "signature": original["signature"],
    }
    valid_before = verify_receipt(original, pub)
    valid_after = verify_receipt(tampered, pub)
    print(f"  Tamper test: flip sandbox_backend on a receipt from the nono scenario")
    print(f"    Before: {original['payload']['sandbox_backend']!r}  verifies = {valid_before}")
    print(f"    After:  {tampered['payload']['sandbox_backend']!r}  verifies = {valid_after}")
    if valid_before and not valid_after:
        print(f"    -> sandbox_backend is inside the signature scope, not sidecar metadata.")
    else:  # pragma: no cover - defensive
        print(f"    !! unexpected verification outcome; see receipts.py _check_no_embedded_key")
    print()


def demonstrate_chain_linkage(results: list[ScenarioResult]) -> None:
    """Confirm successive receipts within a scenario link via previousReceiptHash.

    The chain is tamper-evident because each subsequent receipt binds to
    the SHA-256 of the prior envelope. Modifying any earlier receipt
    breaks the chain from that point forward at verify time.
    """
    r = results[0]
    first = r.receipts[0]
    second = r.receipts[1]
    expected = receipt_hash(first)
    actual = second["payload"].get("previousReceiptHash")
    print(f"  Chain linkage (scenario: {r.name})")
    print(f"    hash(receipt[0])          = {expected[:32]}...")
    print(f"    receipt[1].previousReceiptHash = {actual[:32] if actual else '(missing)'}...")
    print(f"    match = {actual == expected}")
    print()


def print_verify_instructions(operator_signer: Signer, out_dir: Path) -> None:
    """Emit the exact commands an auditor would use to verify externally."""
    print("  Offline verification (no dependency on this skill or on AGT):")
    print()
    print("      # publish the operator public key out-of-band, e.g. as a JWKS URL")
    print("      # or write it to a file and pin:")
    print(f"      cat {out_dir / 'operator-public.pem'}")
    print()
    print("      # verify any emitted receipt with the canonical verifier CLI:")
    print(f"      npx @veritasacta/verify {out_dir}/standalone/000.json \\")
    print(f"          --key {out_dir / 'operator-public.pem'}")
    print()
    print("      # receipt format reference: draft-farley-acta-signed-receipts-02")
    print("      # https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/")
    print()


def write_receipts_to_disk(
    results: list[ScenarioResult],
    operator_signer: Signer,
    out_dir: Path,
) -> None:
    """Write every receipt plus the operator public key to disk under out_dir.

    Layout:
        out_dir/
            operator-public.pem
            standalone/{000.json, 001.json, ...}
            nono/{000.json, ...}
            openshell/{000.json, ...}
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "operator-public.pem").write_bytes(operator_signer.public_pem())
    for r in results:
        sub = out_dir / r.name
        sub.mkdir(exist_ok=True)
        for i, rec in enumerate(r.receipts):
            (sub / f"{i:03d}.json").write_text(json.dumps(rec, indent=2, sort_keys=True))


def main() -> int:
    print("=" * 72)
    print("   sb-runtime Governed Agent — Multi-backend Receipt Portability")
    print("=" * 72)
    print()

    operator = Signer.generate()
    print(f"  Operator key:  kid = {operator.kid}")
    print(f"  Policy:        {POLICY_DIR}/sandbox-policy.yaml")
    print(f"  Agent DID:     {AGENT_DID}")
    print()

    scenarios = [
        ("standalone", SandboxBackend.SB_RUNTIME_BUILTIN, 3),
        ("nono", SandboxBackend.NONO, 2),
        ("openshell", SandboxBackend.OPENSHELL, 2),
    ]
    results = [
        run_scenario(name, backend, ring, operator)
        for name, backend, ring in scenarios
    ]

    print("-" * 72)
    print("   Scenario summaries (same policy, three sandbox backends)")
    print("-" * 72)
    print()
    for r in results:
        print_scenario_summary(r)

    print("-" * 72)
    print("   Cross-verification (single public key, all 18 receipts)")
    print("-" * 72)
    print()
    total, verified = verify_all_receipts(results, operator)
    status = "ALL PASS" if verified == total else f"FAIL ({total - verified} failed)"
    print(f"  Verified: {verified} / {total}  [{status}]")
    print()

    print("-" * 72)
    print("   Tamper-evidence demonstration")
    print("-" * 72)
    print()
    demonstrate_tampering(results, operator)
    demonstrate_chain_linkage(results)

    out_dir = Path(__file__).parent / "receipts"
    write_receipts_to_disk(results, operator, out_dir)

    print("-" * 72)
    print(f"   Receipts written to {out_dir.relative_to(Path.cwd()) if out_dir.is_absolute() else out_dir}")
    print("-" * 72)
    print()
    print_verify_instructions(operator, out_dir.relative_to(Path.cwd()) if out_dir.is_absolute() else out_dir)

    print("=" * 72)
    print("   The same signed receipt format across all three sandbox layers.")
    print("   Auditors verify every receipt with one public key, zero runtime")
    print("   dependencies on AGT or sb-runtime. The sandbox_backend field is")
    print("   inside the signature, so an operator cannot claim 'Ring 3' at")
    print("   verify time if the receipt was actually produced under 'none'.")
    print("=" * 72)
    return 0 if verified == total else 1


if __name__ == "__main__":
    sys.exit(main())
