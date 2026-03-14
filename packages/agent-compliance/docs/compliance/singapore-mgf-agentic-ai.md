# Singapore Model Governance Framework — Compliance Mapping

> **Framework**: IMDA Model AI Governance Framework for Agentic AI (January 2026)
> **Stack**: Agent Governance (Agent OS + AgentMesh + Agent SRE + Agent Runtime)
> **Last Updated**: February 2026

---

## Executive Summary

The Agent Governance stack provides comprehensive technical coverage for all four
pillars of Singapore's Model AI Governance Framework for Agentic AI. This document
maps each framework requirement to specific capabilities, modules, and configuration
options in the stack.

Singapore's Infocomm Media Development Authority (IMDA) launched the world's first
Model AI Governance Framework specifically addressing agentic AI systems in January
2026. The framework establishes four pillars that organisations deploying autonomous
AI agents must satisfy: bounding risks upfront, maintaining meaningful human
accountability, implementing technical controls, and ensuring end-user transparency.

The Agent Governance stack — comprising Agent OS (governance kernel), AgentMesh
(zero-trust identity and trust), Agent Runtime (runtime isolation), and Agent SRE
(reliability engineering) — provides production-ready implementations for every
requirement across all four pillars. This document serves as an auditable compliance
artefact for APAC enterprises adopting agentic AI.

---

## Coverage Matrix

| Pillar | Requirement | Coverage | Module(s) |
|--------|------------|----------|-----------|
| **1 — Bound Risks** | Use-case risk assessment | ✅ Full | Agent OS `AdversarialEvaluator`, Control Plane `RiskClassifier` |
| **1 — Bound Risks** | Restrict agent permissions | ✅ Full | `GovernancePolicy.allowed_tools`, `ExecutionContext.capabilities` |
| **1 — Bound Risks** | Limit cascading errors | ✅ Full | `CircuitBreaker`, Agent SRE SLO engine, error budgets |
| **1 — Bound Risks** | Adversarial resilience testing | ✅ Full | `ChaosEngine`, `ChaosScenario`, 9 fault templates |
| **1 — Bound Risks** | Risk classification | ✅ Full | Control Plane `RiskCategory` (Unacceptable/High/Limited/Minimal) |
| **2 — Accountability** | Define roles and responsibilities | ✅ Full | `RBACManager`, `Role` (READER/WRITER/ADMIN/AUDITOR) |
| **2 — Accountability** | Human oversight mechanisms | ✅ Full | `GovernancePolicy.require_human_approval`, `checkpoint_frequency` |
| **2 — Accountability** | Mitigate automation bias | ✅ Full | `GovernanceLogger` audit trail, `FlightRecorder`, `DifferentialAuditor` |
| **2 — Accountability** | Sponsor accountability | ✅ Full | AgentMesh `SponsorManager`, delegation chains |
| **2 — Accountability** | Decision lineage tracking | ✅ Full | Agent Runtime `DeltaTrail` hash-chained audit |
| **3 — Technical Controls** | Sandboxing and safety testing | ✅ Full | `ExecutionSandbox`, AST analysis, blocked modules/builtins |
| **3 — Technical Controls** | Behaviour monitoring | ✅ Full | Agent SRE `AnomalyDetector`, `GovernanceMetrics`, 7 SLI types |
| **3 — Technical Controls** | Identity and permission management | ✅ Full | AgentMesh `AgentDID`, `TrustHandshake`, SPIFFE mTLS |
| **3 — Technical Controls** | Prompt injection defence | ✅ Full | `PromptInjectionDetector` (7 strategies), `MemoryGuard` |
| **3 — Technical Controls** | Gradual rollouts and monitoring | ✅ Full | Agent SRE `BlueGreenDeployment`, canary rollouts, SLO tracking |
| **3 — Technical Controls** | Cost controls | ✅ Full | Agent SRE `CostGuard`, `CostOptimizer`, per-task budgets |
| **4 — Transparency** | User training and intervention | ✅ Full | `require_human_approval`, `kill_agent`, `pause_agent` signals |
| **4 — Transparency** | Structured audit logs | ✅ Full | `GovernanceLogger` JSON logs, OpenTelemetry export |
| **4 — Transparency** | Agent capability communication | ✅ Full | `CapabilityGrant` manifests, `PolicyDocument` schemas |
| **4 — Transparency** | Tamper-evident audit chains | ✅ Full | Agent Runtime `DeltaTrail`, Merkle hash chains |

**Overall: 20/20 requirements mapped with full coverage.**

---

## Pillar 1: Assess and Bound Risks Upfront

The framework requires organisations to proactively identify, assess, and constrain
risks before deploying agentic AI systems. This includes use-case-specific risk
assessment, restricting agent permissions to the minimum necessary, and limiting
exposure to cascading errors.

### 1.1 Use-Case Specific Risk Assessment

**Framework Requirement:** Conduct structured risk assessment for each agentic AI
use case. Classify agents by risk tier and apply proportionate governance controls.

**Stack Mapping:**

| Component | Module | Capability |
|-----------|--------|------------|
| Agent OS | `AdversarialEvaluator` | Automated adversarial testing against agent deployments |
| Agent OS Control Plane | `RiskClassifier` | Categorises agents into risk tiers (Unacceptable, High, Limited, Minimal) |
| Agent OS Control Plane | `ComplianceEngine` | Validates against multiple regulatory frameworks |
| Agent SRE | `ChaosEngine` | Resilience testing with 9 fault injection templates |
| Agent SRE | `AnomalyDetector` | ML-based detection of unusual agent behaviour patterns |

**Implementation:**

```python
from agent_os import StatelessKernel
from agent_os.policies.schema import PolicyDocument, PolicyRule, PolicyAction

kernel = StatelessKernel()

# Define risk-tiered policy for a financial advisory agent
policy = PolicyDocument(
    version="1.0",
    name="financial-advisor-high-risk",
    rules=[
        PolicyRule(
            name="block-unauthorized-transactions",
            condition="action.type == 'financial_transaction' and action.amount > 10000",
            action=PolicyAction.DENY,
            priority=1,
        ),
        PolicyRule(
            name="audit-all-recommendations",
            condition="action.type == 'investment_recommendation'",
            action=PolicyAction.AUDIT,
            priority=5,
        ),
    ],
)

# Adversarial evaluation before deployment
result = kernel.evaluate_adversarial(
    agent_id="financial-advisor-v2",
    scenarios=["prompt_injection", "goal_hijack", "privilege_escalation"],
    iterations=1000,
)
assert result.pass_rate >= 0.99, f"Agent failed adversarial evaluation: {result.summary}"
```

**Chaos-Based Risk Assessment:**

```python
from agent_sre.chaos.engine import ChaosEngine, ChaosScenario

chaos = ChaosEngine()

# Pre-deployment resilience testing
scenario = ChaosScenario(
    name="cascading-failure-test",
    fault_type="dependency_timeout",
    target_agent="financial-advisor-v2",
    duration_seconds=300,
    parameters={"timeout_ms": 5000, "failure_rate": 0.3},
)

report = chaos.execute(scenario)
assert report.agent_recovered, "Agent must recover from dependency failures"
assert report.error_budget_consumed < 0.1, "Must not exceed 10% error budget"
```

### 1.2 Restrict Agent Permissions

**Framework Requirement:** Apply the principle of least privilege. Agents should
only have access to the tools, data, and actions necessary for their specific task.

**Stack Mapping:**

| Component | Module | Capability |
|-----------|--------|------------|
| Agent OS | `GovernancePolicy.allowed_tools` | Explicit tool allowlist per agent |
| Agent OS | `GovernancePolicy.max_tool_calls` | Upper bound on tool invocations per session |
| Agent OS | `ExecutionContext.capabilities` | Capability-based access control at the kernel level |
| Agent OS | `PolicyDocument` | Declarative YAML/JSON policy rules with condition-based evaluation |
| Agent Runtime | `ExecutionSandbox` | AST-based static analysis blocking dangerous imports |
| AgentMesh | `CapabilityGrant` | Fine-grained `action:resource[:qualifier]` grants |

**Implementation:**

```python
from agent_os.integrations.base import GovernancePolicy
from agent_os.sandbox import ExecutionSandbox, SandboxConfig

# Pillar 1.2: Least-privilege policy
policy = GovernancePolicy(
    allowed_tools=["search_documents", "summarise_text", "query_database"],
    max_tool_calls=20,
    max_tokens=4096,
    timeout_seconds=120,
    blocked_patterns=[
        "rm -rf", "DROP TABLE", "DELETE FROM",
        r".*password.*", r".*secret.*",
    ],
)

# Sandbox for code execution with restricted imports
sandbox = ExecutionSandbox(config=SandboxConfig(
    blocked_modules=["subprocess", "os", "sys", "ctypes", "shutil"],
    blocked_builtins=["exec", "eval", "compile", "__import__"],
    max_memory_mb=512,
    timeout_seconds=30,
))
```

**Capability-Based Access Control:**

```python
from agent_os import ExecutionContext, StatelessKernel

kernel = StatelessKernel()

# Each agent gets only the capabilities it needs
ctx = ExecutionContext(
    agent_id="document-search-bot",
    capabilities=["read_documents", "search_index"],
    denied_capabilities=["write_documents", "delete_documents", "admin"],
)

# Kernel enforces capabilities at every tool call
result = kernel.execute(ctx, action="delete_documents", target="contracts/")
# → CapabilityDenied: agent 'document-search-bot' lacks 'delete_documents' capability
```

### 1.3 Limit Exposure to Cascading Errors

**Framework Requirement:** Design systems so that a failure in one agent does not
cascade to other agents or downstream systems. Implement circuit breakers and
graceful degradation.

**Stack Mapping:**

| Component | Module | Capability |
|-----------|--------|------------|
| Agent OS | `CircuitBreaker` | 3-state circuit breaker (CLOSED → OPEN → HALF_OPEN) |
| Agent OS | `CircuitBreakerConfig` | Configurable thresholds (failure count, reset timeout) |
| Agent SRE | `SLOSpec`, `SLOObjective` | Error budget tracking with burn rate alerts |
| Agent SRE | `CircuitBreakerRegistry` | Centralised breaker management with metrics |
| Agent Runtime | Execution Rings | Ring 0–3 isolation preventing cross-agent contamination |

**Implementation:**

```python
from agent_os.circuit_breaker import CircuitBreaker, CircuitBreakerConfig

# Pillar 1.3: Cascade protection
breaker = CircuitBreaker(config=CircuitBreakerConfig(
    failure_threshold=5,        # Open after 5 consecutive failures
    success_threshold=3,        # 3 successes in half-open to close
    timeout_seconds=60.0,       # Wait 60s before attempting recovery
    half_open_max_calls=3,      # Allow 3 test calls in half-open state
))

@breaker.protect
async def call_downstream_agent(task):
    return await downstream_agent.execute(task)
    # → CircuitOpen raised after 5 failures; auto-recovers after 60s
```

**SLO-Based Error Budgets:**

```python
from agent_sre.slo.spec import SLOSpec, SLI
from agent_sre.slo.objectives import SLOObjective

# Define SLO with error budget
slo = SLOSpec(
    name="document-search-availability",
    indicators=[
        SLI(type="availability", target=0.999),
        SLI(type="latency_p99", target_ms=500),
    ],
)

objective = SLOObjective(spec=slo, window_days=30)

# When error budget is exhausted, halt deployments
if objective.budget_remaining < 0.0:
    raise ErrorBudgetExhausted(
        "Cannot deploy: error budget consumed. "
        "Focus on reliability improvements before shipping new features."
    )
```

---

## Pillar 2: Meaningful Human Accountability

The framework requires that humans remain meaningfully accountable for agentic AI
system outcomes. This includes defined roles and responsibilities, effective
oversight mechanisms, and safeguards against automation bias.

### 2.1 Define Roles and Responsibilities

**Framework Requirement:** Establish clear roles (developer, operator, deployer,
auditor) with defined accountability for AI agent outcomes. Maintain a chain of
responsibility.

**Stack Mapping:**

| Component | Module | Capability |
|-----------|--------|------------|
| Agent OS | `RBACManager` | Role-based access control with per-role permission templates |
| Agent OS | `Role` enum | READER, WRITER, ADMIN, AUDITOR roles |
| AgentMesh | `SponsorManager` | Human sponsor accountability for each agent |
| AgentMesh | `DelegationChain` | Max depth: 3 (configurable), traceable delegation |
| Agent Runtime | Execution Rings | Ring-based privilege levels (Ring 0 = highest trust) |

**Implementation:**

```python
from agent_os.integrations.rbac import RBACManager, Role

rbac = RBACManager()

# Define roles with Singapore MGF accountability mapping
rbac.define_role(Role.ADMIN, permissions=[
    "deploy_agent", "modify_policy", "revoke_agent", "view_audit_logs",
])
rbac.define_role(Role.WRITER, permissions=[
    "configure_agent", "update_tools", "view_audit_logs",
])
rbac.define_role(Role.AUDITOR, permissions=[
    "view_audit_logs", "export_compliance_reports", "review_decisions",
])
rbac.define_role(Role.READER, permissions=[
    "view_agent_status", "view_metrics",
])

# Assign roles — every agent action traces back to a responsible human
rbac.assign("alice@company.com", Role.ADMIN, scope="production/*")
rbac.assign("bob@company.com", Role.AUDITOR, scope="production/*")
```

**Sponsor Accountability:**

```python
from agentmesh.identity.sponsor import SponsorManager

sponsors = SponsorManager(max_agents_per_sponsor=10)

# Every agent must have a human sponsor — required by Singapore MGF Pillar 2
sponsor_record = sponsors.register(
    agent_id="financial-advisor-v2",
    sponsor="alice@company.com",
    sponsor_role="Head of AI Operations",
    accountability_scope="all financial recommendations and transactions",
)

# Sponsor is notified and held accountable for agent actions
assert sponsor_record.sponsor == "alice@company.com"
```

### 2.2 Human Oversight Mechanisms

**Framework Requirement:** Implement effective mechanisms for human oversight of
agentic AI actions. High-impact decisions must require human approval. Checkpoints
must exist at meaningful intervals.

**Stack Mapping:**

| Component | Module | Capability |
|-----------|--------|------------|
| Agent OS | `GovernancePolicy.require_human_approval` | Mandatory human-in-the-loop for policy-defined actions |
| Agent OS | `GovernancePolicy.checkpoint_frequency` | Periodic human review checkpoints (every N actions) |
| Agent OS | `HumanApprovalPolicy` | Configurable approval workflows with timeout and escalation |
| Agent Runtime | Kill Switch | Graceful termination with step handoff |
| AgentMesh | `PolicyAction.require_approval` | Trust-policy-level approval gates |

**Implementation:**

```python
from agent_os.integrations.base import GovernancePolicy

# Pillar 2.2: Mandatory human oversight
policy = GovernancePolicy(
    require_human_approval=True,          # All actions require approval
    checkpoint_frequency=5,               # Human review every 5 actions
    timeout_seconds=300,                  # 5-minute approval window
    max_tool_calls=50,                    # Hard cap on autonomous actions
    confidence_threshold=0.8,             # Flag low-confidence decisions
)

# For granular control — approval only for high-impact actions
from agent_os import StatelessKernel, HumanApprovalPolicy

kernel = StatelessKernel()
kernel.add_policy(HumanApprovalPolicy(
    require_approval_for=[
        "financial_transaction",
        "delete_data",
        "send_external_email",
        "modify_production_config",
    ],
    approval_timeout=300,
    escalation="deny",  # If no human responds within timeout → deny
))
```

**Trust-Policy Approval Gates:**

```yaml
# agentmesh trust policy — require approval for untrusted agents
version: "1.0"
rules:
  - name: "require-approval-below-threshold"
    condition: "trust_score < 500"
    action: "require_approval"
    priority: 10
    approvers: ["ai-ops-team@company.com"]
  - name: "block-untrusted"
    condition: "trust_score < 100"
    action: "deny"
    priority: 1
```

### 2.3 Mitigate Automation Bias

**Framework Requirement:** Prevent over-reliance on AI agent outputs. Maintain
audit trails that enable independent review and detect patterns of uncritical
acceptance.

**Stack Mapping:**

| Component | Module | Capability |
|-----------|--------|------------|
| Agent OS | `GovernanceLogger` | Structured JSON audit trail for every agent decision |
| Agent OS | `JSONFormatter` | Standardised log format (agent_id, action, decision, duration_ms) |
| Agent Runtime | `DeltaTrail` | Hash-chained tamper-evident forensic audit |
| Agent Runtime | `FlightRecorder` | Continuous recording of agent state and decisions |
| Agent SRE | `AnomalyDetector` | Detects patterns of blindly accepted recommendations |

**Implementation:**

```python
from agent_os.integrations.logging import GovernanceLogger, JSONFormatter
import logging

# Pillar 2.3: Comprehensive audit trail for bias detection
logger = GovernanceLogger(name="singapore-mgf-audit")
logger.setLevel(logging.INFO)

handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)

# Every decision is logged with full context
logger.log_decision(
    agent_id="financial-advisor-v2",
    action="investment_recommendation",
    decision="recommend_buy",
    confidence=0.87,
    reasoning="Based on 3 analyst reports and market trend data",
    human_reviewer="bob@company.com",
    reviewed=False,  # Flag: not yet reviewed by human
)
# Output: {"agent_id": "financial-advisor-v2", "action": "investment_recommendation",
#          "decision": "recommend_buy", "confidence": 0.87, "reviewed": false, ...}
```

**Tamper-Evident Audit with DeltaTrail:**

```python
from hypervisor import DeltaTrail

# Hash-chained audit — impossible to tamper without detection
trail = DeltaTrail(agent_id="financial-advisor-v2")

trail.record(action="recommendation", payload={"ticker": "SGX:D05", "action": "buy"})
trail.record(action="human_review", payload={"reviewer": "bob@company.com", "approved": True})

# Verify chain integrity — any tampering breaks the hash chain
assert trail.verify_integrity(), "Audit chain has been tampered with"

# Export for compliance audit
report = trail.export(format="json", include_hashes=True)
```

---

## Pillar 3: Implement Technical Controls and Processes

The framework requires robust technical controls including sandboxing, behaviour
monitoring, identity management, and gradual rollout processes.

### 3.1 Sandboxing and Safety Testing

**Framework Requirement:** Execute agent-generated code and actions in sandboxed
environments. Conduct safety testing including adversarial evaluation before
deployment.

**Stack Mapping:**

| Component | Module | Capability |
|-----------|--------|------------|
| Agent OS | `ExecutionSandbox` | AST-based static analysis, blocked modules/builtins |
| Agent OS | `SandboxConfig` | Configurable blocked imports, memory limits, timeouts |
| Agent OS | `SecurityViolation` | Structured exception for sandbox violations |
| Agent OS | `PromptInjectionDetector` | 7-strategy injection detection |
| Agent OS | `MemoryGuard` | SHA-256 integrity checking for context poisoning defence |
| Agent Runtime | Execution Rings | Ring 0–3 process-level isolation |

**Implementation:**

```python
from agent_os.sandbox import ExecutionSandbox, SandboxConfig
from agent_os.prompt_injection import PromptInjectionDetector

# Pillar 3.1: Sandboxed execution
sandbox = ExecutionSandbox(config=SandboxConfig(
    blocked_modules=["subprocess", "os", "sys", "ctypes", "shutil", "socket"],
    blocked_builtins=["exec", "eval", "compile", "__import__"],
    max_memory_mb=512,
    timeout_seconds=30,
))

# Execute agent-generated code safely
try:
    result = sandbox.execute(agent_generated_code)
except SecurityViolation as e:
    logger.log_violation(agent_id="code-gen-bot", violation=str(e))
    # → SecurityViolation: Import of 'subprocess' is blocked

# Prompt injection defence (7 strategies)
detector = PromptInjectionDetector()
scan = detector.detect(
    input_text=user_message,
    strategies=["heuristic", "ml_classifier", "canary_token",
                "perplexity", "delimiter", "encoding", "escalation"],
)
if scan.is_injection:
    raise SecurityError(f"Injection detected via {scan.strategy}: {scan.details}")
```

**Memory Integrity Protection:**

```python
from agent_os.memory_guard import MemoryGuard

# Protect agent memory/context from poisoning attacks
guard = MemoryGuard()

# Store context with integrity hash
guard.store("conversation_history", conversation_data)

# Verify integrity before using context — detects tampering
if not guard.verify("conversation_history"):
    raise IntegrityError("Agent memory has been tampered with")
```

### 3.2 Behaviour Monitoring

**Framework Requirement:** Continuously monitor agent behaviour in production.
Detect anomalies, drift, and unexpected patterns. Alert operators when agents
deviate from expected behaviour.

**Stack Mapping:**

| Component | Module | Capability |
|-----------|--------|------------|
| Agent SRE | `AnomalyDetector` | ML-based unsupervised anomaly detection |
| Agent SRE | `SLOSpec`, 7 SLI types | Availability, latency, error rate, throughput monitoring |
| Agent SRE | `MetricsCollector` | OpenTelemetry-native metric export |
| Agent OS | `GovernancePolicy.drift_threshold` | Configurable drift detection threshold (default 0.15) |
| Agent OS | `GovernancePolicy.confidence_threshold` | Flag low-confidence decisions (default 0.8) |
| AgentMesh | `ReputationEngine` | Trust score decay (2 pts/hr) detecting degraded agents |
| AgentMesh | `AnomalyDetector` | 5 anomaly classes for trust-layer detection |

**Implementation:**

```python
from agent_sre.slo.spec import SLOSpec, SLI
from agent_sre.anomaly.detector import AnomalyDetector
from agent_os.integrations.base import GovernancePolicy

# Pillar 3.2: Continuous behaviour monitoring
slo = SLOSpec(
    name="agent-behaviour-monitoring",
    indicators=[
        SLI(type="availability", target=0.999),
        SLI(type="latency_p99", target_ms=500),
        SLI(type="error_rate", target=0.01),
        SLI(type="throughput", target_rps=100),
    ],
)

# Anomaly detection on agent behaviour
anomaly_detector = AnomalyDetector()
anomaly_detector.monitor(
    agent_id="financial-advisor-v2",
    metrics=["latency", "token_usage", "policy_violations", "error_rate"],
    alert_callback=lambda alert: ops_team.notify(alert),
)

# Drift detection in governance policy
policy = GovernancePolicy(
    drift_threshold=0.15,         # Alert if agent behaviour drifts >15%
    confidence_threshold=0.8,     # Flag decisions below 80% confidence
    log_all_calls=True,           # Log every action for audit
)
```

**Trust Score Monitoring:**

```python
from agentmesh.reward.engine import ReputationEngine

# Trust scores naturally decay (2 pts/hr) — agents must maintain good behaviour
reputation = ReputationEngine()
score = reputation.get_score("financial-advisor-v2")

if score.value < 500:
    # Agent trust has degraded — require additional human oversight
    policy.require_human_approval = True
    ops_team.alert(f"Agent trust score degraded to {score.value}/1000")
```

### 3.3 Identity and Permission Management

**Framework Requirement:** Implement robust identity management for all AI agents.
Verify agent identity before granting access. Manage permissions through a
centralised system with least-privilege defaults.

**Stack Mapping:**

| Component | Module | Capability |
|-----------|--------|------------|
| AgentMesh | `AgentDID` | Decentralised identifiers (`did:mesh:<hex>`) via SHA-256 |
| AgentMesh | `AgentIdentity` | Ed25519 cryptographic key pairs |
| AgentMesh | `TrustHandshake` | 3-phase mutual authentication (challenge → sign → verify) |
| AgentMesh | `SPIFFE` / `SPIFFEConfig` | mTLS with SVID rotation (1h TTL, rotated at <10 min) |
| AgentMesh | `DelegationChain` | Bounded delegation (max depth: 3) |
| AgentMesh | `CapabilityGrant` | Fine-grained `action:resource[:qualifier]` permissions |
| Agent OS | `RBACManager` | Role-based access with READER/WRITER/ADMIN/AUDITOR |

**Implementation:**

```python
from agentmesh.identity.agent_id import AgentDID
from agentmesh.trust.handshake import TrustHandshake
from agentmesh.trust.capability import CapabilityGrant

# Pillar 3.3: Cryptographic agent identity
did = AgentDID.create(
    name="financial-advisor-v2",
    organisation="acme-corp",
)
# → did:mesh:a1b2c3d4e5f6...  (Ed25519 key pair generated)

# 3-phase trust handshake before any interaction
handshake = TrustHandshake()
session = handshake.initiate(
    initiator=did,
    responder=peer_did,
    required_trust_score=0.7,
)
# Phase 1: Challenge (30s nonce expiry)
# Phase 2: Peer signs challenge
# Phase 3: Verify signature + trust score check

# Fine-grained capability grants
grants = [
    CapabilityGrant("read:market_data"),
    CapabilityGrant("read:analyst_reports"),
    CapabilityGrant("write:recommendations:draft"),
    # No grant for write:recommendations:publish — requires human approval
]
```

**SPIFFE/mTLS Integration:**

```python
from agentmesh.identity.spiffe import SPIFFEConfig, SPIFFE

# Enterprise mTLS identity — complements DIDs for infrastructure-level auth
spiffe = SPIFFE(config=SPIFFEConfig(
    svid_ttl_seconds=3600,              # 1-hour certificate lifetime
    rotation_threshold_seconds=600,      # Rotate when <10 min remaining
    revocation_propagation_seconds=5,    # Revocation propagates in ≤5s
))

svid = spiffe.issue(agent_id="financial-advisor-v2", namespace="production")
```

### 3.4 Gradual Rollouts and Monitoring

**Framework Requirement:** Deploy agentic AI systems gradually. Use canary
deployments, blue-green strategies, and progressive rollouts with continuous
monitoring at each stage.

**Stack Mapping:**

| Component | Module | Capability |
|-----------|--------|------------|
| Agent SRE | `BlueGreenDeployment` | Zero-downtime deployment with shadow mode |
| Agent SRE | `RolloutStrategy` | Canary deployments with configurable traffic splits |
| Agent SRE | `SLOObjective` | Error budget tracking during rollout |
| Agent SRE | `ChaosEngine` | Pre-deployment resilience validation |
| Agent SRE | `CostGuard` | Auto-throttle on budget breach during rollout |

**Implementation:**

```python
from agent_sre.delivery.blue_green import BlueGreenDeployment
from agent_sre.delivery.rollout import RolloutStrategy
from agent_sre.slo.objectives import SLOObjective

# Pillar 3.4: Progressive deployment
rollout = RolloutStrategy(
    name="financial-advisor-v2-canary",
    stages=[
        {"traffic_percent": 5,  "duration_minutes": 30, "slo_check": True},
        {"traffic_percent": 25, "duration_minutes": 60, "slo_check": True},
        {"traffic_percent": 50, "duration_minutes": 120, "slo_check": True},
        {"traffic_percent": 100, "duration_minutes": 0,  "slo_check": True},
    ],
    rollback_on_slo_breach=True,
)

# Blue-green with shadow traffic for pre-production validation
deployment = BlueGreenDeployment(
    blue="financial-advisor-v1",
    green="financial-advisor-v2",
    shadow_mode=True,  # Green receives shadow traffic, responses discarded
)

# SLO gate — only promote if error budget is healthy
objective = SLOObjective(spec=slo, window_days=30)
if objective.budget_remaining > 0.5:
    deployment.promote(to="green")
else:
    deployment.rollback()
```

---

## Pillar 4: End-User Responsibility and Transparency

The framework requires that end users are informed about agent capabilities and
limitations, have the ability to intervene, and that all agent actions are
transparently logged and auditable.

### 4.1 User Training and Intervention

**Framework Requirement:** Provide users with the ability to intervene in, pause,
or terminate agentic AI operations at any time. Ensure users understand when they
are interacting with an AI agent.

**Stack Mapping:**

| Component | Module | Capability |
|-----------|--------|------------|
| Agent OS | `GovernancePolicy.require_human_approval` | Mandatory approval gates |
| Agent Runtime | Kill Switch | Graceful termination with state preservation |
| Agent Runtime | Saga Transactions | Automatic rollback on termination |
| AgentMesh | `PolicyAction` | `allow`, `deny`, `warn`, `require_approval`, `log` |

**Implementation:**

```python
from agent_os.integrations.base import GovernancePolicy

# Pillar 4.1: User intervention capabilities
policy = GovernancePolicy(
    require_human_approval=True,
    checkpoint_frequency=5,         # Force human review every 5 actions
    timeout_seconds=300,            # 5-minute window for user response
    max_tool_calls=50,              # Hard stop after 50 actions
    max_concurrent=10,              # Limit parallel agent operations
    backpressure_threshold=8,       # Slow down at 80% capacity
)

# Kill switch — immediate graceful termination
from hypervisor import KillSwitch

kill_switch = KillSwitch(agent_id="financial-advisor-v2")

# User can terminate at any time
kill_switch.terminate(reason="User requested stop", graceful=True)
# → Agent completes current step, saves state, rolls back incomplete saga
```

**Pause and Resume:**

```python
# Pause agent execution — preserves full state for later resumption
kill_switch.pause(reason="User reviewing intermediate results")

# User reviews agent state and decisions...
state = kill_switch.get_state()
print(f"Agent completed {state.steps_completed} steps")
print(f"Pending actions: {state.pending_actions}")

# Resume or terminate based on user decision
kill_switch.resume()  # or kill_switch.terminate(reason="User rejected plan")
```

### 4.2 Transparency

**Framework Requirement:** Maintain comprehensive, structured, and tamper-evident
audit logs of all agent actions. Logs must be accessible for compliance audits and
exportable in standard formats.

**Stack Mapping:**

| Component | Module | Capability |
|-----------|--------|------------|
| Agent OS | `GovernanceLogger` | Structured JSON audit logs |
| Agent OS | `JSONFormatter` | Standardised log schema (agent_id, action, decision, duration_ms, error_code) |
| Agent Runtime | `DeltaTrail` | Hash-chained tamper-evident audit |
| Agent Runtime | `FlightRecorder` | Continuous state recording |
| AgentMesh | `AuditEntry`, `AuditLog` | Append-only audit with CloudEvents v1.0 serialisation |
| Agent SRE | OpenTelemetry | Traces, metrics, and logs to any OTEL-compatible backend |

**Implementation:**

```python
from agent_os.integrations.logging import GovernanceLogger, JSONFormatter
from agentmesh.governance.audit import AuditLog, AuditEntry
import logging

# Pillar 4.2: Structured transparency logging
logger = GovernanceLogger(name="singapore-mgf-transparency")
logger.setLevel(logging.INFO)

# JSON structured output — machine-parseable for compliance tools
handler = logging.FileHandler("audit/agent-decisions.jsonl")
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)

# Every agent action is automatically logged
logger.info("tool_call", extra={
    "agent_id": "financial-advisor-v2",
    "action": "query_market_data",
    "tool": "bloomberg_api",
    "arguments": {"ticker": "SGX:D05", "range": "1Y"},
    "result_summary": "200 OK, 365 data points returned",
    "duration_ms": 142,
    "policy_decisions": ["allowed_by_tool_allowlist", "within_rate_limit"],
})

# AgentMesh append-only audit with CloudEvents serialisation
audit = AuditLog()
audit.append(AuditEntry(
    agent_id="financial-advisor-v2",
    event_type="recommendation.created",
    payload={"ticker": "SGX:D05", "action": "buy", "confidence": 0.87},
    ce_source="urn:agent:financial-advisor-v2",
    ce_type="com.acme.agent.recommendation",
))

# Export for Singapore PDPC or IMDA compliance audit
audit.export(format="cloudevents-json", output="audit/compliance-export.json")
```

**OpenTelemetry Integration:**

```python
from agent_sre import AgentSRE

# Export governance telemetry to enterprise observability stack
sre = AgentSRE(otel_endpoint="http://otel-collector:4317")

sre.track(
    agent_id="financial-advisor-v2",
    metrics=["latency", "token_usage", "policy_violations", "error_rate"],
    traces=True,   # Distributed tracing across multi-agent workflows
    logs=True,     # Structured log export
)
# → Telemetry flows to Datadog, Prometheus, Grafana, Splunk, or any OTEL backend
```

### 4.3 Agent Capability Communication

**Framework Requirement:** Clearly communicate to users what an AI agent can and
cannot do. Provide structured capability manifests and documentation for each
deployed agent.

**Stack Mapping:**

| Component | Module | Capability |
|-----------|--------|------------|
| AgentMesh | `CapabilityGrant` | Structured `action:resource[:qualifier]` manifests |
| Agent OS | `PolicyDocument` | Declarative policy schemas documenting constraints |
| Agent OS | `GovernancePolicy` | Complete configuration surface as documentation |
| AgentMesh | `ComplianceMapping` | Framework-to-control mapping documentation |

**Implementation:**

```python
from agentmesh.trust.capability import CapabilityGrant

# Pillar 4.3: Structured capability manifest
capability_manifest = {
    "agent_id": "financial-advisor-v2",
    "version": "2.1.0",
    "description": "Provides investment recommendations based on market data analysis",
    "capabilities": [
        CapabilityGrant("read:market_data"),
        CapabilityGrant("read:analyst_reports"),
        CapabilityGrant("write:recommendations:draft"),
    ],
    "limitations": [
        "Cannot execute trades — all transactions require human approval",
        "Cannot access client personal data beyond portfolio holdings",
        "Maximum 20 tool calls per session",
        "Recommendations are advisory only — not financial advice",
    ],
    "governance": {
        "human_approval_required": True,
        "checkpoint_frequency": 5,
        "max_tool_calls": 20,
        "risk_tier": "HIGH",
        "sponsor": "alice@company.com",
        "compliance_frameworks": ["Singapore MGF", "MAS TRM", "SOC 2"],
    },
}

# Expose via API for user-facing documentation
from agent_os.policies.schema import PolicyDocument

policy_doc = PolicyDocument(
    version="1.0",
    name="financial-advisor-v2-policy",
    description="Governance policy for financial advisory agent — Singapore MGF compliant",
    rules=[...],  # Full rule set as self-documenting policy-as-code
)
```

---

## Implementation Quick Start

A complete example demonstrating compliance with all four pillars in a single
deployment configuration:

```python
from agent_os import StatelessKernel, ExecutionContext, HumanApprovalPolicy
from agent_os.integrations.base import GovernancePolicy
from agent_os.integrations.rbac import RBACManager, Role
from agent_os.integrations.logging import GovernanceLogger, JSONFormatter
from agent_os.sandbox import ExecutionSandbox, SandboxConfig
from agent_os.prompt_injection import PromptInjectionDetector
from agent_os.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from agentmesh.identity.agent_id import AgentDID
from agentmesh.identity.sponsor import SponsorManager
from agent_sre.slo.spec import SLOSpec, SLI
from agent_sre.anomaly.detector import AnomalyDetector
import logging

# ──────────────────────────────────────────────────────────
# Pillar 1: Assess and Bound Risks Upfront
# ──────────────────────────────────────────────────────────
policy = GovernancePolicy(
    allowed_tools=["search_documents", "query_database", "summarise"],
    max_tool_calls=20,
    max_tokens=4096,
    timeout_seconds=120,
    blocked_patterns=["DROP TABLE", "rm -rf", r".*password.*"],
    confidence_threshold=0.8,
    drift_threshold=0.15,
)

breaker = CircuitBreaker(config=CircuitBreakerConfig(
    failure_threshold=5, timeout_seconds=60.0,
))

# ──────────────────────────────────────────────────────────
# Pillar 2: Meaningful Human Accountability
# ──────────────────────────────────────────────────────────
policy.require_human_approval = True
policy.checkpoint_frequency = 5

rbac = RBACManager()
rbac.assign("alice@company.com", Role.ADMIN, scope="production/*")
rbac.assign("bob@company.com", Role.AUDITOR, scope="production/*")

sponsors = SponsorManager(max_agents_per_sponsor=10)
sponsors.register(agent_id="my-agent", sponsor="alice@company.com",
                  sponsor_role="AI Operations Lead",
                  accountability_scope="all production actions")

# ──────────────────────────────────────────────────────────
# Pillar 3: Implement Technical Controls
# ──────────────────────────────────────────────────────────
sandbox = ExecutionSandbox(config=SandboxConfig(
    blocked_modules=["subprocess", "os", "sys", "ctypes"],
    blocked_builtins=["exec", "eval", "compile"],
))

detector = PromptInjectionDetector()

did = AgentDID.create(name="my-agent", organisation="acme-corp")

slo = SLOSpec(name="agent-slo", indicators=[
    SLI(type="availability", target=0.999),
    SLI(type="latency_p99", target_ms=500),
])

anomaly = AnomalyDetector()
anomaly.monitor(agent_id="my-agent",
                metrics=["latency", "error_rate", "policy_violations"])

# ──────────────────────────────────────────────────────────
# Pillar 4: End-User Responsibility and Transparency
# ──────────────────────────────────────────────────────────
logger = GovernanceLogger(name="singapore-mgf")
logger.setLevel(logging.INFO)
handler = logging.FileHandler("audit/singapore-mgf-audit.jsonl")
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)

# Deploy with full Singapore MGF compliance
kernel = StatelessKernel()
ctx = ExecutionContext(
    agent_id="my-agent",
    capabilities=["search_documents", "query_database", "summarise"],
)
```

---

## Compliance Checklist

Use this checklist during deployment reviews to verify Singapore MGF compliance:

### Pillar 1 — Bound Risks

- [ ] Risk assessment completed using `AdversarialEvaluator`
- [ ] Agent classified by risk tier (Unacceptable/High/Limited/Minimal)
- [ ] `GovernancePolicy.allowed_tools` configured with least-privilege allowlist
- [ ] `GovernancePolicy.max_tool_calls` set to appropriate limit
- [ ] `CircuitBreaker` configured for all downstream dependencies
- [ ] Error budgets defined via `SLOObjective`
- [ ] Chaos testing completed with `ChaosEngine`

### Pillar 2 — Accountability

- [ ] RBAC roles assigned (`RBACManager`)
- [ ] Human sponsor registered (`SponsorManager`)
- [ ] `require_human_approval` enabled for high-impact actions
- [ ] `checkpoint_frequency` configured for periodic human review
- [ ] Audit trail active (`GovernanceLogger`)
- [ ] Delegation chains bounded (max depth ≤ 3)

### Pillar 3 — Technical Controls

- [ ] `ExecutionSandbox` configured with blocked modules/builtins
- [ ] `PromptInjectionDetector` active with all 7 strategies
- [ ] `MemoryGuard` protecting agent context integrity
- [ ] Agent identity established (`AgentDID` or SPIFFE)
- [ ] `TrustHandshake` required for agent-to-agent communication
- [ ] SLO monitoring active with 7 SLI types
- [ ] `AnomalyDetector` monitoring agent behaviour
- [ ] Gradual rollout strategy defined (`RolloutStrategy`)

### Pillar 4 — Transparency

- [ ] `GovernanceLogger` with `JSONFormatter` producing structured logs
- [ ] `DeltaTrail` hash-chained audit active
- [ ] OpenTelemetry export configured
- [ ] Capability manifest documented for each agent
- [ ] Kill switch and pause mechanisms tested
- [ ] Compliance report exportable for IMDA audit

---

## Cross-Reference: OWASP Agentic AI Top 10

The Singapore MGF requirements align closely with the OWASP Agentic AI Top 10 risks.
Organisations that implement the Agent Governance stack satisfy both frameworks simultaneously.

| OWASP Risk | Singapore MGF Pillar | Module |
|-----------|---------------------|--------|
| ASI01 Agent Hijacking | Pillar 3 (Technical Controls) | `PromptInjectionDetector` |
| ASI02 Privilege Escalation | Pillar 1 (Bound Risks) | `GovernancePolicy.allowed_tools` |
| ASI03 Insecure Communication | Pillar 3 (Technical Controls) | AgentMesh mTLS, `TrustHandshake` |
| ASI04 Insufficient Identity | Pillar 3 (Technical Controls) | `AgentDID`, SPIFFE |
| ASI05 Unsafe Code Execution | Pillar 3 (Technical Controls) | `ExecutionSandbox` |
| ASI06 Excessive Autonomy | Pillar 2 (Accountability) | `require_human_approval` |
| ASI07 Data Leakage | Pillar 4 (Transparency) | Output scanning, PII redaction |
| ASI08 Lack of Observability | Pillar 4 (Transparency) | `GovernanceLogger`, OpenTelemetry |
| ASI09 Resource Exhaustion | Pillar 1 (Bound Risks) | `CostGuard`, `max_tool_calls` |
| ASI10 Lack of Error Handling | Pillar 1 (Bound Risks) | `CircuitBreaker`, SLOs |

See the full [OWASP Agentic AI Implementation Guide](../analyst/owasp-agentic-mapping.md)
for detailed code examples.

---

## References

- [IMDA Model AI Governance Framework for Generative AI](https://www.imda.gov.sg/how-we-can-help/model-ai-governance-framework) — Foundation framework
- [IMDA Model AI Governance Framework for Agentic AI (January 2026)](https://www.imda.gov.sg/how-we-can-help/model-ai-governance-framework) — Agentic AI extension
- [Agent Governance — OWASP Agentic AI Top 10 Mapping](../analyst/owasp-agentic-mapping.md) — Implementation guide
- [Agent Governance — Fact Sheet](../analyst/fact-sheet.md) — Stack overview
- [Agent Governance — Enterprise Reference Architecture](../enterprise/reference-architecture.md) — Deployment guide
- [Agent Governance — Security Hardening Guide](../enterprise/security-hardening.md) — Production security
- [MAS Technology Risk Management Guidelines](https://www.mas.gov.sg/regulation/guidelines/technology-risk-management-guidelines) — Singapore financial sector requirements
- [PDPA (Personal Data Protection Act)](https://www.pdpc.gov.sg/overview-of-pdpa/the-legislation/personal-data-protection-act) — Singapore data protection

---

*Part of the [Agent Governance](https://github.com/microsoft/agent-governance-toolkit) ecosystem — Building the governance layer for the agentic era*
