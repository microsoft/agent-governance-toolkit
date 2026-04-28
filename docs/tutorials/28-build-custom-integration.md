# Tutorial 28 — Building Custom Governance Integrations

> **Package:** `agent-os-kernel` / standalone · **Time:** 30 minutes · **Prerequisites:** Python 3.10+

---

## What You'll Learn

- Trust integrations — standalone packages for identity, gating, and trust tracking
- Kernel adapters — `BaseIntegration` subclasses with pre/post hooks and tool interception
- Publishing governance packages — package structure, PR requirements, and versioning

---

Every governed agent system follows the same pattern: verify identity, gate
actions, intercept tool calls, log everything. The toolkit provides 15 kernel
adapters and 17 trust integrations that implement this pattern. This tutorial
shows how to build your own for any framework not yet covered.

| Section | What you'll learn |
|---------|-------------------|
| 1. Two Integration Styles | When to build a trust integration vs a kernel adapter |
| 2. Trust Integration | Standalone package: identity, gating, trust tracking, tests |
| 3. Kernel Adapter | `BaseIntegration` subclass: pre/post hooks, tool interception |
| 4. Wiring Trust into the Kernel | Trust verification inside the governance proxy |
| 5. Publishing | Package structure, PR requirements, versioning |

---

## Prerequisites

- Python 3.10+
- Familiarity with the agent framework you want to govern
- `pip install agent-os-kernel` (for kernel-style adapters only)

---

## 1. Two Integration Styles

The toolkit supports two approaches. Pick the one that matches your goal, or
use both together (Section 4).

```
┌──────────────────────────────────────────────────────────┐
│                    Your Application                      │
├────────────────────────┬─────────────────────────────────┤
│   Trust Integration    │       Kernel Adapter            │
│   (who can act?)       │       (what can they do?)       │
│                        │                                 │
│   AgentProfile         │       GovernancePolicy          │
│   ActionGuard          │       BaseIntegration           │
│   TrustTracker         │       ToolCallInterceptor       │
│                        │       pre_execute / post_execute│
├────────────────────────┴─────────────────────────────────┤
│                   Agent Framework                        │
│              (OpenAI, LangChain, CrewAI, …)              │
└──────────────────────────────────────────────────────────┘
```

| Style | When to use | Base layer | Examples |
|-------|-------------|------------|----------|
| **Trust integration** | Identity verification, capability gating, trust scoring between agents | Standalone dataclasses, no base class required | `crewai-agentmesh`, `langchain-agentmesh`, `openai-agents-agentmesh` |
| **Kernel adapter** | Wrapping a framework client to enforce token limits, tool allow/deny, drift detection | `BaseIntegration` from `agent_os.integrations.base` | OpenAI, LangChain, CrewAI, Anthropic, Gemini, AutoGen kernels |

Trust integrations are simpler — no dependency on `agent-os-kernel`. Kernel
adapters are deeper — they provide the full governance lifecycle. Both styles
coexist in production.

---

## 2. Trust Integration (Standalone Package)

> **Starter template available.** Copy
> `agent-governance-python/agentmesh-integrations/template-agentmesh/` and rename it for your
> framework. It includes a working `trust.py`, `__init__.py`, `pyproject.toml`,
> and 29 tests. The walkthrough below explains each component.

Trust integrations live under `agent-governance-python/agentmesh-integrations/` and follow a
consistent structure. Most have zero runtime dependencies on the target
framework SDK (CrewAI and OpenAI Agents use duck typing). The LangChain
integration is an exception — it requires `langchain-core` and `cryptography`
for Ed25519 signature verification. Prefer the zero-dependency approach unless
cryptographic verification demands otherwise.

### 2.1 Scaffold the package

```
myframework-agentmesh/
  myframework_agentmesh/
    __init__.py       # Public API
    trust.py          # Core implementation
  tests/
    test_trust.py     # Test suite
  pyproject.toml
  README.md
```

#### pyproject.toml

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "myframework_agentmesh"
version = "0.1.0"
description = "AgentMesh trust layer for MyFramework"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.10"
dependencies = []              # No hard deps — framework needed at call time, not import time

[project.optional-dependencies]
dev = ["pytest>=7.0"]

[tool.hatch.build.targets.wheel]
packages = ["myframework_agentmesh"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

Conventions from existing integrations:
- `dependencies = []` — zero runtime deps where possible.
- Build with `hatchling` (matches all toolkit packages).
- Python 3.10+ (matches tutorial prerequisites in `docs/tutorials/README.md`).

### 2.2 Define your data model

Every trust integration needs three things: agent identity, a gate, and a
result type.

```python
# myframework_agentmesh/trust.py
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentProfile:
    """Identity and trust state for a governed agent."""

    did: str                                # Decentralized identifier (did:agentmesh:...)
    name: str
    capabilities: list[str] = field(default_factory=list)
    trust_score: int = 500                  # 0-1000 scale
    status: str = "active"                  # active | suspended | revoked
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities

    def has_all_capabilities(self, required: list[str]) -> bool:
        return all(c in self.capabilities for c in required)

    def has_any_capability(self, required: list[str]) -> bool:
        return any(c in self.capabilities for c in required)
```

This mirrors `crewai-agentmesh`. The `did` field uses the `did:agentmesh:` format
defined by AgentMesh. Trust scores use the 0-1000 integer scale used across
the toolkit.

### 2.3 Build the gate

The gate decides whether an agent can perform an action.

```python
@dataclass
class ActionResult:
    """Outcome of a trust-gated action check."""

    allowed: bool
    agent_did: str
    action: str
    reason: str = ""
    trust_score: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "agent_did": self.agent_did,
            "action": self.action,
            "reason": self.reason,
            "trust_score": self.trust_score,
            "timestamp": self.timestamp,
        }


class ActionGuard:
    """Trust-gated action enforcement.

    Checks agent trust score and capabilities before allowing an action.
    Supports per-action minimum trust thresholds for sensitive operations.
    """

    def __init__(
        self,
        min_trust_score: int = 500,
        sensitive_actions: dict[str, int] | None = None,
        blocked_actions: list[str] | None = None,
    ) -> None:
        self.min_trust_score = min_trust_score
        self.sensitive_actions: dict[str, int] = sensitive_actions or {}
        self.blocked_actions: list[str] = blocked_actions or []

    def check(
        self,
        agent: AgentProfile,
        action: str,
        required_capabilities: list[str] | None = None,
    ) -> ActionResult:
        """Evaluate whether an agent may perform an action."""
        # Hard block
        if action in self.blocked_actions:
            return ActionResult(
                allowed=False,
                agent_did=agent.did,
                action=action,
                reason=f"Action '{action}' is blocked by policy",
                trust_score=agent.trust_score,
            )

        # Status check
        if agent.status != "active":
            return ActionResult(
                allowed=False,
                agent_did=agent.did,
                action=action,
                reason=f"Agent status is '{agent.status}'",
                trust_score=agent.trust_score,
            )

        # Trust threshold (per-action or global)
        threshold = self.sensitive_actions.get(action, self.min_trust_score)
        if agent.trust_score < threshold:
            return ActionResult(
                allowed=False,
                agent_did=agent.did,
                action=action,
                reason=f"Trust score {agent.trust_score} below threshold {threshold}",
                trust_score=agent.trust_score,
            )

        # Capability check
        if required_capabilities and not agent.has_all_capabilities(required_capabilities):
            missing = [c for c in required_capabilities if not agent.has_capability(c)]
            return ActionResult(
                allowed=False,
                agent_did=agent.did,
                action=action,
                reason=f"Missing capabilities: {missing}",
                trust_score=agent.trust_score,
            )

        return ActionResult(
            allowed=True,
            agent_did=agent.did,
            action=action,
            trust_score=agent.trust_score,
        )
```

This follows `openai-agents-agentmesh`, where `TrustedFunctionGuard.check_call()`
returns a `FunctionCallResult` with `allowed`, `reason`, and `trust_score`.

### 2.4 Add trust tracking

Trust scores change over time. A tracker records outcomes and adjusts scores.

```python
class TrustTracker:
    """Records agent outcomes and adjusts trust scores."""

    def __init__(self, reward: int = 10, penalty: int = 50) -> None:
        self.reward = reward
        self.penalty = penalty
        self._history: list[dict[str, Any]] = []

    def record_success(self, agent: AgentProfile, action: str) -> int:
        """Reward an agent for a successful action. Returns new score."""
        agent.trust_score = min(1000, agent.trust_score + self.reward)
        self._history.append({
            "did": agent.did, "action": action,
            "outcome": "success", "new_score": agent.trust_score,
            "timestamp": time.time(),
        })
        return agent.trust_score

    def record_failure(self, agent: AgentProfile, action: str) -> int:
        """Penalize an agent for a failed action. Returns new score."""
        agent.trust_score = max(0, agent.trust_score - self.penalty)
        self._history.append({
            "did": agent.did, "action": action,
            "outcome": "failure", "new_score": agent.trust_score,
            "timestamp": time.time(),
        })
        return agent.trust_score

    def get_history(self, did: str | None = None) -> list[dict[str, Any]]:
        if did:
            return [h for h in self._history if h["did"] == did]
        return list(self._history)
```

This matches `crewai-agentmesh`'s `TrustTracker` with asymmetric reward/penalty
(small reward for success, large penalty for failure).

### 2.5 Export your public API

```python
# myframework_agentmesh/__init__.py
"""AgentMesh trust layer for MyFramework."""

from myframework_agentmesh.trust import (
    ActionGuard,
    ActionResult,
    AgentProfile,
    TrustTracker,
)

__all__ = [
    "ActionGuard",
    "ActionResult",
    "AgentProfile",
    "TrustTracker",
]
```

### 2.6 Write tests

Tests run without the target framework installed. Every existing integration
achieves this by testing governance logic in isolation.

```python
# tests/test_trust.py
from myframework_agentmesh import AgentProfile, ActionGuard, TrustTracker, ActionResult


def test_allow_action_above_threshold():
    agent = AgentProfile(did="did:agentmesh:a1", name="Alpha", trust_score=700)
    guard = ActionGuard(min_trust_score=500)
    result = guard.check(agent, "search")
    assert result.allowed


def test_block_action_below_threshold():
    agent = AgentProfile(did="did:agentmesh:a1", name="Alpha", trust_score=300)
    guard = ActionGuard(min_trust_score=500)
    result = guard.check(agent, "search")
    assert not result.allowed
    assert "below threshold" in result.reason


def test_sensitive_action_requires_higher_trust():
    agent = AgentProfile(did="did:agentmesh:a1", name="Alpha", trust_score=600)
    guard = ActionGuard(
        min_trust_score=500,
        sensitive_actions={"delete_record": 800},
    )
    assert guard.check(agent, "search").allowed
    assert not guard.check(agent, "delete_record").allowed


def test_blocked_action_always_denied():
    agent = AgentProfile(did="did:agentmesh:a1", name="Alpha", trust_score=1000)
    guard = ActionGuard(blocked_actions=["drop_table"])
    result = guard.check(agent, "drop_table")
    assert not result.allowed
    assert "blocked by policy" in result.reason


def test_capability_check():
    agent = AgentProfile(
        did="did:agentmesh:a1", name="Alpha",
        capabilities=["read"], trust_score=700,
    )
    guard = ActionGuard(min_trust_score=500)
    assert guard.check(agent, "query", required_capabilities=["read"]).allowed
    assert not guard.check(agent, "query", required_capabilities=["write"]).allowed


def test_suspended_agent_blocked():
    agent = AgentProfile(did="did:agentmesh:a1", name="Alpha", trust_score=900, status="suspended")
    guard = ActionGuard(min_trust_score=500)
    result = guard.check(agent, "search")
    assert not result.allowed
    assert "suspended" in result.reason


def test_trust_tracker_adjusts_scores():
    agent = AgentProfile(did="did:agentmesh:a1", name="Alpha", trust_score=500)
    tracker = TrustTracker(reward=10, penalty=50)

    tracker.record_success(agent, "search")
    assert agent.trust_score == 510

    tracker.record_failure(agent, "search")
    assert agent.trust_score == 460

    history = tracker.get_history("did:agentmesh:a1")
    assert len(history) == 2
    assert history[0]["outcome"] == "success"
    assert history[1]["outcome"] == "failure"


def test_trust_score_clamped():
    agent = AgentProfile(did="did:agentmesh:a1", name="Alpha", trust_score=995)
    tracker = TrustTracker(reward=10, penalty=50)
    tracker.record_success(agent, "search")
    assert agent.trust_score == 1000  # Clamped at max

    agent.trust_score = 20
    tracker.record_failure(agent, "search")
    assert agent.trust_score == 0    # Clamped at min


def test_action_result_serialization():
    result = ActionResult(
        allowed=True, agent_did="did:agentmesh:a1",
        action="search", trust_score=700,
    )
    d = result.to_dict()
    assert d["allowed"] is True
    assert d["agent_did"] == "did:agentmesh:a1"
    assert "timestamp" in d
```

Run the tests:

```bash
cd myframework-agentmesh
pip install -e ".[dev]"
pytest tests/ -x -q --tb=short
```

---

## 3. Kernel Adapter (Agent OS Integration)

Kernel adapters provide the full governance lifecycle: token budgets, tool
interception, drift detection, and a unified audit trail. They extend
`BaseIntegration` from `agent-os-kernel`.

> **Already read Tutorial 03, Section 8?** That section covers the minimal
> adapter pattern. This section goes further: it adds trust verification inside
> the proxy, shows how `post_execute` drift detection works (event-based, not
> blocking), and demonstrates `CompositeInterceptor` with custom interceptors.

### 3.1 The BaseIntegration contract

`BaseIntegration` (defined in `agent_os/integrations/base.py`) requires two
abstract methods:

| Method | Purpose |
|--------|---------|
| `wrap(agent)` | Accept a framework object, return a governed proxy |
| `unwrap(governed)` | Return the original unwrapped object |

The base class provides these hooks:

```
┌──────────────┐
│  wrap(agent) │
└──────┬───────┘
       │  creates ExecutionContext (deep-copies policy)
       ▼
┌──────────────────────────────────────────────────────┐
│                  Governed Proxy                       │
│                                                      │
│  run(prompt) ─────────────────────────────────────── │
│     │                                                │
│     ├─► pre_execute(ctx, input)                      │
│     │     enforces: tokens, timeout, blocked         │
│     │     patterns, human approval                   │
│     │     returns: (allowed: bool, reason: str|None) │
│     │                                                │
│     ├─► framework.run(prompt)                        │
│     │     the real LLM / agent call                  │
│     │                                                │
│     ├─► post_execute(ctx, output)                    │
│     │     runs: drift detection, checkpoints         │
│     │     emits: DRIFT_DETECTED event if threshold   │
│     │     exceeded (event-based, not blocking)       │
│     │     returns: (True, None) always               │
│     │                                                │
│     └─► emit(event_type, data)                       │
│           fires registered listeners                 │
│                                                      │
│  call_tool(name, args) ──────────────────────────── │
│     │                                                │
│     └─► PolicyInterceptor.intercept(request)         │
│           validates: allowed_tools, blocked_patterns │
│           validates: call count (if context passed)  │
│           returns: ToolCallResult(allowed, reason)   │
└──────────────────────────────────────────────────────┘
```

**Important:** `post_execute()` always returns `(True, None)`. Drift detection
is event-based — the base class emits a `DRIFT_DETECTED` event when the score
exceeds the threshold, but it does not block execution. To make drift blocking,
register an event listener that raises (shown in Section 3.4).

### 3.2 Write the kernel and proxy

```python
# myframework_kernel.py
from __future__ import annotations

from agent_os.integrations.base import (
    BaseIntegration,
    CompositeInterceptor,
    ExecutionContext,
    GovernanceEventType,
    GovernancePolicy,
    PolicyInterceptor,
    ToolCallRequest,
    ToolCallResult,
)
from agent_os.exceptions import PolicyViolationError


class MyFrameworkKernel(BaseIntegration):
    """Governance kernel for MyFramework."""

    def __init__(self, policy: GovernancePolicy | None = None) -> None:
        super().__init__(policy)

    def wrap(self, agent):
        """Wrap a MyFramework agent with governance. Returns a governed proxy."""
        agent_id = getattr(agent, "name", "unknown")
        ctx = self.create_context(agent_id=agent_id)

        self.emit(GovernanceEventType.POLICY_CHECK, {
            "agent_id": agent_id,
            "policy": self.policy.name,
            "action": "wrap",
        })

        return _GovernedAgent(agent, self, ctx)

    def unwrap(self, governed_agent):
        """Remove governance, return original agent."""
        return governed_agent._original


class _GovernedAgent:
    """Transparent governance proxy for a MyFramework agent."""

    def __init__(self, original, kernel: MyFrameworkKernel, ctx: ExecutionContext):
        self._original = original
        self._kernel = kernel
        self._ctx = ctx

    def run(self, prompt: str, **kwargs):
        """Execute with governance checks."""
        # Pre-execution: token limits, timeout, blocked patterns
        allowed, reason = self._kernel.pre_execute(self._ctx, prompt)
        if not allowed:
            self._kernel.emit(GovernanceEventType.POLICY_VIOLATION, {
                "agent_id": self._ctx.agent_id,
                "reason": reason,
                "phase": "pre_execute",
            })
            raise PolicyViolationError(reason)

        # Delegate to the real framework
        result = self._original.run(prompt, **kwargs)

        # Post-execution: drift detection (event-based, not blocking)
        self._kernel.post_execute(self._ctx, result)

        return result

    def call_tool(self, tool_name: str, arguments: dict):
        """Execute a tool call through the interception chain."""
        request = ToolCallRequest(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=self._ctx.agent_id,
        )

        # Pass context so PolicyInterceptor can enforce max_tool_calls
        interceptor = PolicyInterceptor(self._kernel.policy, self._ctx)
        result: ToolCallResult = interceptor.intercept(request)

        if not result.allowed:
            self._kernel.emit(GovernanceEventType.TOOL_CALL_BLOCKED, {
                "agent_id": self._ctx.agent_id,
                "tool_name": tool_name,
                "reason": result.reason,
            })
            raise PolicyViolationError(f"Tool '{tool_name}' blocked: {result.reason}")

        final_args = result.modified_arguments or arguments
        return self._original.call_tool(tool_name, final_args)

    def get_context(self) -> ExecutionContext:
        return self._ctx
```

Key differences from the minimal adapter in Tutorial 03, Section 8:

- `post_execute()` result is not checked — it always returns `(True, None)`.
  Tutorial 03 Section 8 checks the return and raises on failure, but that
  branch can never execute. Drift is handled via events (Section 3.4).
- `PolicyInterceptor` receives `self._ctx` so that `max_tool_calls` enforcement
  works. Without context, call-count limits are silently skipped.
- `PolicyViolationError` is imported from `agent_os.exceptions` (also available
  via `agent_os.integrations.base`).

### 3.3 Compose interceptors

Chain multiple interceptors with `CompositeInterceptor`. All must allow the
call for it to proceed.

```python
class RateLimitInterceptor:
    """Block tool calls when an agent exceeds its per-minute quota."""

    def __init__(self, max_per_minute: int = 30) -> None:
        self._max = max_per_minute
        self._counts: dict[str, list[float]] = {}

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        import time
        now = time.time()
        calls = self._counts.setdefault(request.agent_id, [])
        calls[:] = [t for t in calls if now - t < 60]
        if len(calls) >= self._max:
            return ToolCallResult(allowed=False, reason="Rate limit exceeded")
        calls.append(now)
        return ToolCallResult(allowed=True)


# Wire into the governed proxy's call_tool method:
policy = GovernancePolicy(allowed_tools=["search", "summarize"], max_tool_calls=10)
composite = CompositeInterceptor([
    PolicyInterceptor(policy),  # pass ExecutionContext as 2nd arg to enforce max_tool_calls
    RateLimitInterceptor(max_per_minute=20),
])
result = composite.intercept(tool_request)  # all must allow
```

### 3.4 Register event listeners

Event listeners connect your kernel to alerting, logging, or dashboards. This
is also how to make drift detection blocking:

```python
policy = GovernancePolicy(
    name="production",
    allowed_tools=["search", "summarize"],
    drift_threshold=0.15,
    log_all_calls=True,
)
kernel = MyFrameworkKernel(policy=policy)

# Alert on policy violations
kernel.on(GovernanceEventType.POLICY_VIOLATION, lambda data: (
    print(f"VIOLATION: {data['agent_id']} — {data['reason']}")
))

# Log blocked tool calls
kernel.on(GovernanceEventType.TOOL_CALL_BLOCKED, lambda data: (
    print(f"BLOCKED: {data['tool_name']} — {data['reason']}")
))

# Make drift detection blocking (optional)
def on_drift(data):
    raise PolicyViolationError(
        f"Drift {data['drift_score']:.2f} exceeds threshold"
    )

kernel.on(GovernanceEventType.DRIFT_DETECTED, on_drift)

governed = kernel.wrap(my_agent)
```

---

## 4. Wiring Trust into the Kernel

A production integration uses both layers: the trust integration gates *which
agents* can act, the kernel gates *what they do*. The cleanest approach wires
trust verification directly into the governed proxy.

```
┌───────────────┐     ┌──────────────────┐     ┌──────────────┐
│ ActionGuard   │ ──► │ MyFrameworkKernel │ ──► │  Framework   │
│ (trust gate)  │     │ (policy gate)    │     │  (LLM call)  │
│               │     │                  │     │              │
│ who can act?  │     │ pre_execute      │     │              │
│ capabilities? │     │ tool intercept   │     │              │
│ trust score?  │     │ drift detection  │     │              │
└───────────────┘     └──────────────────┘     └──────────────┘
```

```python
from __future__ import annotations

from myframework_agentmesh import AgentProfile, ActionGuard
from agent_os.integrations.base import (
    BaseIntegration,
    ExecutionContext,
    GovernanceEventType,
    GovernancePolicy,
    PolicyInterceptor,
    ToolCallRequest,
    ToolCallResult,
)
from agent_os.exceptions import PolicyViolationError


class TrustAwareKernel(BaseIntegration):
    """Kernel that checks trust before enforcing policy."""

    def __init__(
        self,
        policy: GovernancePolicy | None = None,
        guard: ActionGuard | None = None,
    ) -> None:
        super().__init__(policy)
        self.guard = guard or ActionGuard()

    def wrap(self, agent, profile: AgentProfile):
        """Wrap an agent with both trust verification and policy enforcement."""
        # agent_id must match ^[a-zA-Z0-9_-]+$ — DIDs contain colons,
        # so extract the final segment as the identifier.
        agent_id = profile.did.rsplit(":", 1)[-1]
        ctx = self.create_context(agent_id=agent_id)
        return _TrustGovernedAgent(agent, self, ctx, profile)

    def unwrap(self, governed_agent):
        return governed_agent._original


class _TrustGovernedAgent:
    def __init__(self, original, kernel: TrustAwareKernel,
                 ctx: ExecutionContext, profile: AgentProfile):
        self._original = original
        self._kernel = kernel
        self._ctx = ctx
        self._profile = profile

    def run(self, prompt: str, action: str = "execute", **kwargs):
        # Trust gate: is this agent allowed to perform this action?
        trust_result = self._kernel.guard.check(self._profile, action)
        if not trust_result.allowed:
            raise PolicyViolationError(
                f"Trust check failed for {self._profile.did}: {trust_result.reason}"
            )

        # Policy gate: does the input comply with governance rules?
        allowed, reason = self._kernel.pre_execute(self._ctx, prompt)
        if not allowed:
            raise PolicyViolationError(reason)

        result = self._original.run(prompt, **kwargs)
        self._kernel.post_execute(self._ctx, result)
        return result
```

Usage:

```python
guard = ActionGuard(
    min_trust_score=600,
    sensitive_actions={"deploy": 900, "delete": 800},
    blocked_actions=["drop_database"],
)

policy = GovernancePolicy(
    name="deploy-restricted",
    max_tool_calls=5,
    allowed_tools=["kubectl_apply", "helm_upgrade"],
    blocked_patterns=["--force", "delete namespace"],
    timeout_seconds=120,
    log_all_calls=True,
)

agent_profile = AgentProfile(
    did="did:agentmesh:deployer",
    name="Deployer",
    capabilities=["deploy", "rollback"],
    trust_score=750,
)

kernel = TrustAwareKernel(policy=policy, guard=guard)
governed = kernel.wrap(deploy_agent, profile=agent_profile)
governed.run("Deploy v2.1.0 to staging", action="deploy")
```

---

## 5. Publishing Your Integration

### 5.1 Package placement

Trust integrations belong in `agent-governance-python/agentmesh-integrations/yourframework-agentmesh/`.
Kernel adapters belong in `agent-governance-python/agent-os/src/agent_os/integrations/yourframework_adapter.py`.

### 5.2 PR requirements

The `CONTRIBUTING.md` checklist applies. Key items:

- Feature branch — never commit directly to `main`
- Conventional commit messages — `feat: add MyFramework governance integration`
- Tests — `pytest tests/ -x -q --tb=short` must pass
- Lint — `ruff check src/ --select E,F,W --ignore E501`
- Type hints and docstrings on all public APIs
- Microsoft CLA signed
- PR template (`.github/pull_request_template.md`) completed

### 5.3 Versioning

Follow the existing packages: start at `0.1.0`, use semantic versioning.
Trust integrations in `agent-governance-python/agentmesh-integrations/` ship at the current toolkit
release version (check `pyproject.toml` in any existing integration for the
current number). New community integrations start at `0.1.0` and are bumped
to match the toolkit version on acceptance.

### 5.4 Publishing checklist

- [ ] Package builds with `hatchling` and installs with `pip install -e ".[dev]"`
- [ ] Zero hard runtime deps on the target framework (preferred)
- [ ] Tests pass without the target framework SDK installed
- [ ] `__init__.py` exports all public types in `__all__`
- [ ] Uses `did:agentmesh:` format for agent identifiers
- [ ] Trust scores use 0-1000 integer scale
- [ ] Gate returns a result dataclass with `allowed`, `reason`, and `trust_score`
- [ ] Kernel adapter extends `BaseIntegration` with `wrap()`/`unwrap()`
- [ ] README has a Quick Start code block
- [ ] All public functions and classes have docstrings and type hints
- [ ] `CONTRIBUTING.md` checklist completed

---

## Next Steps

- [Tutorial 01 — Policy Engine](01-policy-engine.md) — Policy rules, operators,
  conflict resolution
- [Tutorial 02 — Trust & Identity](02-trust-and-identity.md) — Ed25519
  credentials, DIDs, trust scoring
- [Tutorial 03 — Framework Integrations](03-framework-integrations.md) — Built-in
  adapters for OpenAI, LangChain, CrewAI, and more
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — Contribution requirements

---

## Reference

| Resource | Path |
|----------|------|
| `BaseIntegration` interface | `agent-governance-python/agent-os/src/agent_os/integrations/base.py` |
| CrewAI trust integration | `agent-governance-python/agentmesh-integrations/crewai-agentmesh/` |
| LangChain trust integration | `agent-governance-python/agentmesh-integrations/langchain-agentmesh/` |
| OpenAI Agents trust integration | `agent-governance-python/agentmesh-integrations/openai-agents-agentmesh/` |
| Framework integrations tutorial | `docs/tutorials/03-framework-integrations.md` |
| Template integration (copy this) | `agent-governance-python/agentmesh-integrations/template-agentmesh/` |
| GovernancePolicy patterns | Tutorial 03, Section 7 |

---

## Next Steps

- [Tutorial 03 — Framework Integrations](03-framework-integrations.md)
- [Tutorial 02 — Trust & Identity](02-trust-and-identity.md)
- [Tutorial 04 — Audit & Compliance](04-audit-and-compliance.md)
