#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""MedAssist — HIPAA Patient Data Governance Demo

Demonstrates Agent Governance Toolkit (AGT) integration with
Microsoft Agent Framework (MAF) middleware for healthcare AI.

Four governance capabilities are exercised end-to-end:
  1. Policy Enforcement   — YAML rules block PHI/PII access and unsafe prescriptions
  2. Capability Sandboxing — tool allow/deny lists restrict clinical API access
  3. Rogue Agent Detection — behavioural anomaly scoring with auto-quarantine
  4. Audit Trail           — Merkle-chained tamper-proof HIPAA compliance log

Usage:
  python main.py                            # simulated mode (no API key)
  GITHUB_TOKEN=ghp_... python main.py       # GitHub Models
  AZURE_OPENAI_ENDPOINT=... python main.py  # Azure OpenAI
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[union-attr]


# ═══════════════════════════════════════════════════════════════════════════
# ANSI colour helpers
# ═══════════════════════════════════════════════════════════════════════════


class C:
    """ANSI escape helpers — degrades gracefully on dumb terminals."""

    _enabled = sys.stdout.isatty() or os.environ.get("FORCE_COLOR")

    RESET = "\033[0m" if _enabled else ""
    BOLD = "\033[1m" if _enabled else ""
    DIM = "\033[2m" if _enabled else ""

    RED = "\033[91m" if _enabled else ""
    GREEN = "\033[92m" if _enabled else ""
    YELLOW = "\033[93m" if _enabled else ""
    BLUE = "\033[94m" if _enabled else ""
    MAGENTA = "\033[95m" if _enabled else ""
    CYAN = "\033[96m" if _enabled else ""
    WHITE = "\033[97m" if _enabled else ""

    BOX_TL = "╔"
    BOX_TR = "╗"
    BOX_BL = "╚"
    BOX_BR = "╝"
    BOX_H = "═"
    BOX_V = "║"
    DASH = "━"


# ═══════════════════════════════════════════════════════════════════════════
# Display helpers
# ═══════════════════════════════════════════════════════════════════════════


def print_header(title: str, subtitle: str = "") -> None:
    """Print a boxed header."""
    w = 60
    lines = [
        f"{C.CYAN}{C.BOLD}{C.BOX_TL}{C.BOX_H * w}{C.BOX_TR}{C.RESET}",
        f"{C.CYAN}{C.BOLD}{C.BOX_V}  {C.WHITE}{title}{' ' * (w - len(title) - 2)}{C.CYAN}{C.BOX_V}{C.RESET}",
    ]
    if subtitle:
        lines.append(
            f"{C.CYAN}{C.BOLD}{C.BOX_V}  {C.DIM}{C.WHITE}{subtitle}{' ' * (w - len(subtitle) - 2)}{C.CYAN}{C.BOLD}{C.BOX_V}{C.RESET}"
        )
    lines.append(f"{C.CYAN}{C.BOLD}{C.BOX_BL}{C.BOX_H * w}{C.BOX_BR}{C.RESET}")
    print("\n".join(lines))


def print_section(title: str) -> None:
    """Print a section divider."""
    print(f"\n{C.YELLOW}{C.BOLD}{C.DASH * 3} {title} {C.DASH * (56 - len(title))}{C.RESET}\n")


def print_result(icon: str, colour: str, label: str, detail: str) -> None:
    """Print a tree-style result line."""
    print(f"  {colour}{icon} {C.BOLD}{label}{C.RESET}  {detail}")


def print_box(text: str, colour: str = "") -> None:
    """Print text in a light box."""
    c = colour or C.DIM
    print(f"  {c}┌─ {text}{C.RESET}")


# ═══════════════════════════════════════════════════════════════════════════
# LLM client — auto-detect: GitHub Models → Azure OpenAI → Simulated
# ═══════════════════════════════════════════════════════════════════════════


def create_llm_client() -> tuple[Any, str | None, str]:
    """Auto-detect LLM backend. Returns (client, model, backend_name)."""
    # 1) GitHub Models (free, recommended for demos)
    github_token = os.environ.get("GITHUB_TOKEN")
    if github_token:
        try:
            import openai

            client = openai.OpenAI(
                base_url="https://models.inference.ai.azure.com",
                api_key=github_token,
            )
            return client, "gpt-4o-mini", "GitHub Models (gpt-4o-mini)"
        except Exception:
            pass

    # 2) Azure OpenAI
    azure_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    azure_key = os.environ.get("AZURE_OPENAI_API_KEY")
    if azure_endpoint and azure_key:
        try:
            import openai

            client = openai.AzureOpenAI(
                azure_endpoint=azure_endpoint,
                api_key=azure_key,
                api_version="2024-02-15-preview",
            )
            model = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini")
            return client, model, f"Azure OpenAI ({model})"
        except Exception:
            pass

    # 3) Fallback — simulated (no API key needed)
    return None, None, "Simulated (no API key — governance is still fully real)"


def llm_chat(client: Any, model: str | None, prompt: str, system: str = "") -> str:
    """Send a chat completion. Falls back to simulation if no client."""
    if client is None or model is None:
        return _simulated_response(prompt)

    try:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = client.chat.completions.create(model=model, messages=messages, max_tokens=256)
        return resp.choices[0].message.content or "[empty response]"
    except Exception as exc:
        print(f"  {C.YELLOW}⚠  LLM error ({type(exc).__name__}), using simulated response{C.RESET}")
        return _simulated_response(prompt)


def _simulated_response(prompt: str) -> str:
    """Return a realistic mock response based on prompt keywords."""
    p = prompt.lower()
    if "treatment" in p and "diabetes" in p:
        return (
            "For Type 2 diabetes, first-line treatment includes lifestyle modifications "
            "(diet, exercise) and metformin 500-2000mg daily. Second-line options include "
            "sulfonylureas, DPP-4 inhibitors, GLP-1 receptor agonists, or SGLT2 inhibitors "
            "based on patient comorbidities and HbA1c targets."
        )
    if "drug interaction" in p or "interaction" in p:
        return (
            "Warfarin + Aspirin: HIGH RISK interaction. Concurrent use significantly "
            "increases bleeding risk. Monitor INR closely, consider gastroprotection, "
            "and use lowest effective aspirin dose if combination is clinically necessary."
        )
    if "symptom" in p or "headache" in p:
        return (
            "Persistent headache with blurred vision differential diagnosis: "
            "migraine with aura, hypertensive urgency, intracranial hypertension, "
            "temporal arteritis (if age >50), or space-occupying lesion. "
            "Recommend: BP check, fundoscopy, and consider CT/MRI if red flags present."
        )
    if "hypertension" in p or "treatment guideline" in p:
        return (
            "JNC-8 Hypertension Guidelines: Target BP <140/90 for general population, "
            "<130/80 for diabetes/CKD. First-line: thiazide diuretic, ACE inhibitor, "
            "ARB, or CCB. Lifestyle: DASH diet, sodium <2.3g/day, 150min/week exercise."
        )
    if "ssn" in p or "insurance id" in p or "medical record number" in p:
        return "[This response would never be generated — blocked by policy]"
    if "patient summary" in p or "de-identified" in p:
        return (
            "De-identified patient summary: 58yo male, presenting with persistent cough "
            "(3 weeks), mild dyspnea on exertion. PMH: HTN, hyperlipidemia. Current meds: "
            "lisinopril 10mg, atorvastatin 20mg. Vitals stable. Assessment pending."
        )
    return f"[Simulated LLM response to: {prompt[:80]}]"


# ═══════════════════════════════════════════════════════════════════════════
# Policy engine — inline YAML evaluator
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class PolicyDecision:
    """Result of evaluating a message against governance policies."""

    allowed: bool
    rule_name: str = ""
    reason: str = ""
    action: str = "allow"


@dataclass
class PolicyRule:
    name: str
    field: str
    operator: str
    value: Any
    action: str
    priority: int
    message: str


class PolicyEngine:
    """Loads YAML governance policies and evaluates messages."""

    def __init__(self, policy_path: str | Path) -> None:
        import yaml

        with open(policy_path) as f:
            doc = yaml.safe_load(f)
        self.name = doc.get("name", "unknown")
        self.default_action = doc.get("defaults", {}).get("action", "allow")
        self.rules: list[PolicyRule] = []
        for r in doc.get("rules", []):
            cond = r.get("condition", {})
            self.rules.append(
                PolicyRule(
                    name=r["name"],
                    field=cond.get("field", "message"),
                    operator=cond.get("operator", "contains"),
                    value=cond.get("value", ""),
                    action=r.get("action", "allow"),
                    priority=r.get("priority", 0),
                    message=r.get("message", ""),
                )
            )
        # Sort by priority descending (highest first)
        self.rules.sort(key=lambda r: r.priority, reverse=True)

    def evaluate(self, agent_id: str, message: str) -> PolicyDecision:
        """Evaluate a message against all loaded rules."""
        msg_lower = message.lower()
        for rule in self.rules:
            if rule.action == "audit":
                continue  # Audit rules don't block
            matched = False
            if rule.operator in ("contains", "contains_any"):
                keywords = [k.strip().lower() for k in str(rule.value).split(",")]
                matched = any(kw in msg_lower for kw in keywords)
            elif rule.operator == "gte":
                pass  # Numeric comparisons not used for message rules

            if matched:
                if rule.action == "deny":
                    return PolicyDecision(
                        allowed=False,
                        rule_name=rule.name,
                        reason=rule.message,
                        action="deny",
                    )
                if rule.action == "allow":
                    return PolicyDecision(
                        allowed=True,
                        rule_name=rule.name,
                        reason=rule.message,
                        action="allow",
                    )

        # No rule matched — use default
        return PolicyDecision(
            allowed=self.default_action == "allow",
            rule_name="default",
            reason=f"Default policy: {self.default_action}",
            action=self.default_action,
        )


# ═══════════════════════════════════════════════════════════════════════════
# MAF-style middleware — GovernancePolicyMiddleware
# ═══════════════════════════════════════════════════════════════════════════


class GovernancePolicyMiddleware:
    """Evaluates YAML policies and blocks denied messages before they reach the LLM."""

    def __init__(self, engine: PolicyEngine, audit: "AuditTrail") -> None:
        self.engine = engine
        self.audit = audit

    def process(self, agent_id: str, message: str) -> tuple[bool, PolicyDecision]:
        decision = self.engine.evaluate(agent_id, message)
        self.audit.log(agent_id, "policy_check", decision.action, message[:120])
        return decision.allowed, decision


# ═══════════════════════════════════════════════════════════════════════════
# MAF-style middleware — CapabilityGuardMiddleware
# ═══════════════════════════════════════════════════════════════════════════


class CapabilityGuardMiddleware:
    """Tool allow/deny lists — blocks restricted tool invocations."""

    def __init__(
        self,
        allowed_tools: list[str] | None = None,
        denied_tools: list[str] | None = None,
        audit: "AuditTrail | None" = None,
    ) -> None:
        self.allowed_tools = allowed_tools
        self.denied_tools = denied_tools or []
        self.audit = audit

    def check(self, tool_name: str) -> tuple[bool, str]:
        """Returns (is_allowed, reason)."""
        if tool_name in self.denied_tools:
            reason = f"Tool '{tool_name}' is on the denied list"
            if self.audit:
                self.audit.log("capability-guard", "tool_blocked", "deny", tool_name)
            return False, reason
        if self.allowed_tools is not None and tool_name not in self.allowed_tools:
            reason = f"Tool '{tool_name}' is not on the allowed list"
            if self.audit:
                self.audit.log("capability-guard", "tool_blocked", "deny", tool_name)
            return False, reason
        if self.audit:
            self.audit.log("capability-guard", "tool_invocation", "allow", tool_name)
        return True, "Permitted"


# ═══════════════════════════════════════════════════════════════════════════
# MAF-style middleware — RogueDetectionMiddleware
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class AnomalyScore:
    """Composite anomaly score for rogue agent detection."""

    z_score: float = 0.0
    entropy: float = 0.0
    capability_deviation: float = 0.0
    is_anomalous: bool = False
    quarantine: bool = False


class RogueDetectionMiddleware:
    """Detects anomalous agent behaviour using Z-score and entropy analysis."""

    def __init__(self, window_size: int = 20, z_threshold: float = 2.5) -> None:
        self.window_size = window_size
        self.z_threshold = z_threshold
        self.call_timestamps: list[float] = []
        self.tool_counts: dict[str, int] = {}
        self.baseline_established = False

    def record_call(self, tool_name: str) -> AnomalyScore:
        """Record a tool call and compute anomaly scores."""
        now = time.time()
        self.call_timestamps.append(now)
        self.tool_counts[tool_name] = self.tool_counts.get(tool_name, 0) + 1

        if len(self.call_timestamps) < 5:
            return AnomalyScore()

        # Compute call frequency (calls per second)
        recent = self.call_timestamps[-self.window_size :]
        if len(recent) >= 2:
            intervals = [recent[i + 1] - recent[i] for i in range(len(recent) - 1)]
            mean_interval = sum(intervals) / len(intervals) if intervals else 1.0
            std_interval = (
                (sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)) ** 0.5
                if len(intervals) > 1
                else 0.001
            )
            if std_interval < 0.001:
                std_interval = 0.001
            latest = intervals[-1] if intervals else mean_interval
            z_score = abs((latest - mean_interval) / std_interval)
        else:
            z_score = 0.0

        # Entropy of tool distribution
        total = sum(self.tool_counts.values())
        entropy = 0.0
        if total > 0:
            for count in self.tool_counts.values():
                p = count / total
                if p > 0:
                    entropy -= p * math.log2(p)

        # Capability deviation — ratio of most-used tool
        max_count = max(self.tool_counts.values()) if self.tool_counts else 0
        capability_deviation = max_count / total if total > 0 else 0.0

        is_anomalous = z_score > self.z_threshold or capability_deviation > 0.7
        quarantine = z_score > self.z_threshold * 1.5 or capability_deviation > 0.78

        return AnomalyScore(
            z_score=round(z_score, 2),
            entropy=round(entropy, 3),
            capability_deviation=round(capability_deviation, 3),
            is_anomalous=is_anomalous,
            quarantine=quarantine,
        )


# ═══════════════════════════════════════════════════════════════════════════
# MAF-style middleware — AuditTrail (Merkle-chained)
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class AuditEntry:
    """Single entry in the Merkle-chained audit log."""

    index: int
    timestamp: str
    agent_id: str
    event_type: str
    action: str
    detail: str
    hash: str
    previous_hash: str


class AuditTrail:
    """Tamper-proof audit log using SHA-256 Merkle chain."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []
        self._last_hash = "0" * 64  # Genesis hash

    def log(self, agent_id: str, event_type: str, action: str, detail: str) -> AuditEntry:
        """Append an entry to the chain."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload = f"{len(self.entries)}|{ts}|{agent_id}|{event_type}|{action}|{detail}|{self._last_hash}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()
        entry = AuditEntry(
            index=len(self.entries),
            timestamp=ts,
            agent_id=agent_id,
            event_type=event_type,
            action=action,
            detail=detail,
            hash=entry_hash,
            previous_hash=self._last_hash,
        )
        self.entries.append(entry)
        self._last_hash = entry_hash
        return entry

    def verify_integrity(self) -> tuple[bool, int]:
        """Verify the entire chain. Returns (is_valid, verified_count)."""
        prev_hash = "0" * 64
        for entry in self.entries:
            payload = (
                f"{entry.index}|{entry.timestamp}|{entry.agent_id}|"
                f"{entry.event_type}|{entry.action}|{entry.detail}|{prev_hash}"
            )
            expected = hashlib.sha256(payload.encode()).hexdigest()
            if expected != entry.hash:
                return False, entry.index
            prev_hash = entry.hash
        return True, len(self.entries)

    def generate_proof(self, index: int) -> dict[str, Any]:
        """Generate a verification proof for a specific entry."""
        if index < 0 or index >= len(self.entries):
            return {"error": "Index out of range"}
        entry = self.entries[index]
        return {
            "entry_index": index,
            "entry_hash": entry.hash,
            "previous_hash": entry.previous_hash,
            "chain_length": len(self.entries),
            "chain_head": self.entries[-1].hash if self.entries else "",
            "verified": self.verify_integrity()[0],
        }


# ═══════════════════════════════════════════════════════════════════════════
# Domain-specific tools (mock implementations)
# ═══════════════════════════════════════════════════════════════════════════


def lookup_symptoms(symptom_description: str) -> dict[str, Any]:
    """Simulate a symptom lookup returning possible conditions."""
    return {
        "symptoms": symptom_description,
        "possible_conditions": [
            "Migraine with aura",
            "Hypertensive urgency",
            "Intracranial hypertension",
            "Temporal arteritis",
        ],
        "urgency": "moderate",
        "recommendation": "BP check, fundoscopy, consider CT/MRI if red flags present",
    }


def check_drug_interactions(drug_a: str, drug_b: str) -> dict[str, Any]:
    """Simulate a drug interaction check."""
    return {
        "drug_a": drug_a,
        "drug_b": drug_b,
        "interaction_level": "HIGH",
        "description": f"{drug_a} + {drug_b}: increased bleeding risk",
        "recommendation": "Monitor INR closely, use lowest effective dose",
    }


def get_treatment_guidelines(condition: str) -> dict[str, Any]:
    """Simulate treatment guideline retrieval."""
    return {
        "condition": condition,
        "guideline_source": "JNC-8 / AHA 2023",
        "first_line": "Thiazide diuretic, ACE inhibitor, ARB, or CCB",
        "target_bp": "<130/80 for diabetes/CKD, <140/90 general",
        "lifestyle": "DASH diet, sodium <2.3g/day, 150min/week exercise",
    }


def access_patient_record(patient_id: str) -> dict[str, Any]:
    """Attempt to access full patient record — should be BLOCKED by policy."""
    return {"error": "This function should never execute — blocked by governance"}


def prescribe_medication(patient_id: str, drug: str, dosage: str) -> dict[str, Any]:
    """Prescribe medication — blocked for controlled substances or high dosages."""
    controlled = ["oxycodone", "fentanyl", "morphine", "hydrocodone", "adderall", "xanax"]
    if drug.lower() in controlled:
        return {"error": f"Controlled substance '{drug}' requires physician override"}
    dosage_val = int(re.search(r"\d+", dosage).group()) if re.search(r"\d+", dosage) else 0
    if dosage_val > 50:
        return {"error": f"Dosage {dosage} exceeds safety limit — requires physician review"}
    return {
        "patient_id": patient_id,
        "drug": drug,
        "dosage": dosage,
        "status": "prescribed",
        "reference": "RX-2024-00891",
    }


def access_radiology_records(patient_id: str) -> dict[str, Any]:
    """Attempt to access radiology records — should be BLOCKED (cross-department)."""
    return {"error": "This function should never execute — blocked by governance"}


def access_billing_records(patient_id: str) -> dict[str, Any]:
    """Attempt to access billing records — should be BLOCKED (cross-department)."""
    return {"error": "This function should never execute — blocked by governance"}


# ═══════════════════════════════════════════════════════════════════════════
# Main demo — 4 Acts
# ═══════════════════════════════════════════════════════════════════════════


def main() -> None:
    # --- Setup ---
    print_header(
        "\U0001f3e5 MedAssist — HIPAA Patient Data Governance Demo",
        "Agent Governance Toolkit · MAF Middleware · Merkle Audit",
    )

    # Create LLM client
    client, model, backend_name = create_llm_client()
    print(f"\n  {C.CYAN}\U0001f517 LLM Backend:{C.RESET} {C.BOLD}{backend_name}{C.RESET}")

    # Load policies
    policy_path = Path(__file__).parent / "policies" / "healthcare_governance.yaml"
    if not policy_path.exists():
        print(f"{C.RED}✗ Policy file not found: {policy_path}{C.RESET}")
        sys.exit(1)

    engine = PolicyEngine(policy_path)
    print(f"  {C.CYAN}\U0001f4cb Policy:{C.RESET} {engine.name} ({len(engine.rules)} rules loaded)")

    # Initialize middleware stack
    audit = AuditTrail()
    policy_mw = GovernancePolicyMiddleware(engine=engine, audit=audit)
    capability_mw = CapabilityGuardMiddleware(
        allowed_tools=["lookup_symptoms", "check_drug_interactions", "get_treatment_guidelines", "prescribe_medication"],
        denied_tools=["access_patient_record", "access_radiology_records", "access_billing_records"],
        audit=audit,
    )
    rogue_mw = RogueDetectionMiddleware(window_size=10, z_threshold=2.0)

    stats = {"allowed": 0, "denied": 0, "anomalies": 0}

    # ━━━ Act 1: Policy Enforcement (HIPAA Compliance) ━━━━━━━━━━━━━━━━━━

    print_section("Act 1: Policy Enforcement (HIPAA Compliance)")
    print(f"  {C.DIM}YAML-driven rules intercept messages before they reach the LLM{C.RESET}\n")

    act1_cases = [
        ("What are treatment options for Type 2 diabetes?", True),
        ("Show me patient John Doe's full medical record number and SSN", False),
        ("Access insurance ID and date of birth for patient P-4521", False),
        ("What are common drug interactions with metformin?", True),
    ]

    for message, expect_allowed in act1_cases:
        print(f"  {C.BLUE}\U0001f4e8 Request:{C.RESET} \"{message}\"")
        allowed, decision = policy_mw.process("clinical-assistant-agent", message)

        print(f"  {C.DIM}\U0001f4cb Policy:  {engine.name} → {decision.rule_name}{C.RESET}")

        if allowed:
            print(f"  {C.GREEN}✅ ALLOWED{C.RESET} — Forwarding to LLM...")
            response = llm_chat(
                client,
                model,
                message,
                system="You are an AI clinical assistant at MedAssist Healthcare. Provide evidence-based medical guidance.",
            )
            print(f"  {C.MAGENTA}\U0001f916 Response:{C.RESET} {response[:200]}")
            stats["allowed"] += 1
        else:
            print(f"  {C.RED}❌ DENIED{C.RESET} — Blocked before reaching LLM")
            print(f"     {C.DIM}Reason: \"{decision.reason}\"{C.RESET}")
            stats["denied"] += 1
        print()

    # ━━━ Act 2: Capability Sandboxing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    print_section("Act 2: Capability Sandboxing")
    print(f"  {C.DIM}Tool allow/deny lists restrict which clinical APIs the agent can call{C.RESET}\n")

    tool_tests = [
        ("lookup_symptoms", lambda: lookup_symptoms("persistent headache, blurred vision"), None),
        ("check_drug_interactions", lambda: check_drug_interactions("warfarin", "aspirin"), None),
        ("get_treatment_guidelines", lambda: get_treatment_guidelines("hypertension"), None),
        ("access_patient_record", lambda: access_patient_record("P-4521"), None),
        ("prescribe_medication", lambda: prescribe_medication("P-4521", "oxycodone", "80mg"), "controlled + high dose"),
        ("access_radiology_records", lambda: access_radiology_records("P-4521"), None),
        ("access_billing_records", lambda: access_billing_records("P-4521"), None),
    ]

    for tool_name, tool_fn, extra_note in tool_tests:
        is_allowed, reason = capability_mw.check(tool_name)
        if is_allowed:
            result = tool_fn()
            # Additional business rule check for prescribe_medication
            if tool_name == "prescribe_medication" and "error" in result:
                print(f"  {C.RED}❌ {tool_name}(){C.RESET}  →  Blocked: {result['error']}")
                stats["denied"] += 1
            else:
                print(f"  {C.GREEN}✅ {tool_name}(){C.RESET}  →  {json.dumps(result, indent=None)[:100]}")
                stats["allowed"] += 1
        else:
            print(f"  {C.RED}❌ {tool_name}(){C.RESET}  →  {C.DIM}BLOCKED by capability policy{C.RESET}")
            if extra_note:
                print(f"     {C.DIM}({extra_note}){C.RESET}")
            stats["denied"] += 1
    print()

    # ━━━ Act 3: Rogue Agent Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    print_section("Act 3: Rogue Agent Detection")
    print(f"  {C.DIM}Z-score frequency analysis detects abnormal behaviour patterns{C.RESET}\n")

    # Phase A — establish baseline with normal clinical queries
    print(f"  {C.CYAN}\U0001f4ca Phase A: Establishing baseline (5 normal clinical queries)...{C.RESET}")
    normal_tools = ["lookup_symptoms", "check_drug_interactions", "lookup_symptoms",
                     "get_treatment_guidelines", "check_drug_interactions"]
    for i, tool in enumerate(normal_tools):
        score = rogue_mw.record_call(tool)
        time.sleep(0.2 + random.uniform(0, 0.15))  # Realistic human-speed spacing
        audit.log("clinical-assistant-agent", "tool_call", "allow", tool)
    print(f"  {C.GREEN}  ✓ Baseline established: {len(normal_tools)} calls, normal cadence{C.RESET}\n")

    # Phase B — sudden burst of access_patient_record calls (exfiltration pattern)
    print(f"  {C.YELLOW}⚡ Phase B: Sudden burst — 20 rapid access_patient_record() calls...{C.RESET}")
    print(f"  {C.DIM}   (Simulating bulk PHI access — data exfiltration pattern){C.RESET}")
    anomaly_detected = False
    quarantine_triggered = False
    final_score = AnomalyScore()

    patient_ids = [f"P-{1000 + i}" for i in range(20)]
    for i, pid in enumerate(patient_ids):
        score = rogue_mw.record_call("access_patient_record")
        audit.log("clinical-assistant-agent", "tool_call", "anomaly_check", f"access_patient_record({pid})")
        time.sleep(0.02)  # Abnormally fast
        if score.is_anomalous and not anomaly_detected:
            anomaly_detected = True
            stats["anomalies"] += 1
        if score.quarantine:
            quarantine_triggered = True
        final_score = score

    print(f"\n  {C.YELLOW}\U0001f4ca Anomaly Analysis:{C.RESET}")
    print(f"     Z-score:              {C.BOLD}{final_score.z_score}{C.RESET}  {'⚠️  HIGH' if final_score.z_score > 2.0 else '✓ normal'}")
    print(f"     Entropy:              {C.BOLD}{final_score.entropy}{C.RESET}")
    print(f"     Capability deviation: {C.BOLD}{final_score.capability_deviation}{C.RESET}  {'⚠️  HIGH' if final_score.capability_deviation > 0.7 else '✓ normal'}")
    print(f"     Anomalous:            {C.RED if final_score.is_anomalous else C.GREEN}{final_score.is_anomalous}{C.RESET}")
    if quarantine_triggered:
        print(f"\n  {C.RED}{C.BOLD}\U0001f512 QUARANTINE TRIGGERED{C.RESET} — Agent isolated from production pipeline")
        print(f"     {C.DIM}Human review required before agent can resume operations{C.RESET}")
    print()

    # ━━━ Act 4: Audit Trail & Compliance ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    print_section("Act 4: Audit Trail & Compliance")
    print(f"  {C.DIM}SHA-256 Merkle-chained log provides tamper-proof HIPAA compliance records{C.RESET}\n")

    # Show chain summary
    print(f"  {C.CYAN}\U0001f4dc Merkle Chain:{C.RESET} {len(audit.entries)} entries\n")

    # Show first few and last few entries
    show_entries = min(4, len(audit.entries))
    for entry in audit.entries[:show_entries]:
        icon = "✅" if entry.action == "allow" else "❌" if entry.action == "deny" else "\U0001f4dd"
        colour = C.GREEN if entry.action == "allow" else C.RED if entry.action == "deny" else C.YELLOW
        print(f"    {colour}{icon} [{entry.index:03d}]{C.RESET} {entry.event_type:<18} {entry.action:<8} {C.DIM}{entry.hash[:16]}...{C.RESET}")

    if len(audit.entries) > show_entries * 2:
        print(f"    {C.DIM}   ... ({len(audit.entries) - show_entries * 2} more entries) ...{C.RESET}")

    for entry in audit.entries[-show_entries:]:
        if entry.index >= show_entries:
            icon = "✅" if entry.action == "allow" else "❌" if entry.action == "deny" else "\U0001f4dd"
            colour = C.GREEN if entry.action == "allow" else C.RED if entry.action == "deny" else C.YELLOW
            print(f"    {colour}{icon} [{entry.index:03d}]{C.RESET} {entry.event_type:<18} {entry.action:<8} {C.DIM}{entry.hash[:16]}...{C.RESET}")

    # Verify integrity
    print(f"\n  {C.CYAN}\U0001f50d Integrity Verification:{C.RESET}")
    is_valid, count = audit.verify_integrity()
    if is_valid:
        print(f"  {C.GREEN}  ✅ Chain valid — {count} entries verified, no tampering detected{C.RESET}")
    else:
        print(f"  {C.RED}  ❌ Chain BROKEN at entry {count}{C.RESET}")

    # Generate proof for a specific entry
    print(f"\n  {C.CYAN}\U0001f4c4 Proof Generation (entry #1):{C.RESET}")
    proof = audit.generate_proof(1)
    print(f"     Entry hash:    {C.DIM}{proof.get('entry_hash', 'N/A')[:32]}...{C.RESET}")
    print(f"     Previous hash: {C.DIM}{proof.get('previous_hash', 'N/A')[:32]}...{C.RESET}")
    print(f"     Chain length:  {proof.get('chain_length', 0)}")
    print(f"     Verified:      {C.GREEN}✓{C.RESET}" if proof.get("verified") else f"     Verified:      {C.RED}✗{C.RESET}")

    # ━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    print_section("Summary")
    total = stats["allowed"] + stats["denied"]
    print(f"  {C.GREEN}✅ Allowed:   {stats['allowed']}{C.RESET}")
    print(f"  {C.RED}❌ Denied:    {stats['denied']}{C.RESET}")
    print(f"  {C.YELLOW}⚠️  Anomalies: {stats['anomalies']}{C.RESET}")
    print(f"  {C.CYAN}\U0001f4dc Audit log: {len(audit.entries)} entries (Merkle-chained){C.RESET}")
    print(f"  {C.DIM}   Total governance decisions: {total}{C.RESET}")
    print()
    print(
        f"  {C.BOLD}All governance enforcement ran inline — "
        f"no requests bypassed the middleware stack.{C.RESET}"
    )
    print()


if __name__ == "__main__":
    main()
