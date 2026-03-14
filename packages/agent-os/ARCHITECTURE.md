# Agent-OS Architecture

> **agent-os** is a governance-first kernel for AI agents — a Python framework providing policy enforcement, semantic intent classification, identity management, and execution control for autonomous AI agents.

## 4-Layer Kernel Architecture

Agent-OS follows a strict layered architecture where lower layers never depend on higher layers.

```mermaid
block-beta
  columns 1

  block:L4["Layer 4 — Intelligence"]
    scak["modules/scak\nSelf-Correcting Agent Kernel"]
    mute["modules/mute-agent\nFace/Hands Architecture"]
    mcp["modules/mcp-kernel-server\nMCP Kernel Server"]
  end

  block:L3["Layer 3 — Framework"]
    cp["modules/control-plane\nPolicy Engine · Signals · VFS\nKernel/User Space"]
    obs["modules/observability\nPrometheus + OTel"]
  end

  block:L2["Layer 2 — Infrastructure"]
    iatp["modules/iatp\nInter-Agent Trust Protocol\n(+ Sidecar)"]
    amb["modules/amb\nAgent Message Bus"]
    atr["modules/atr\nAgent Tool Registry"]
  end

  block:L1["Layer 1 — Primitives"]
    prim["modules/primitives\nCore Primitives"]
    cmvk["modules/cmvk\nCMVK — Verification Kernel"]
    emk["modules/emk\nEpisodic Memory Kernel"]
    caas["modules/caas\nContext-as-a-Service"]
  end

  L4 --> L3
  L3 --> L2
  L2 --> L1
```

## Module Dependency Graph

Dependencies derived from each module's `pyproject.toml` and import analysis:

```mermaid
graph TD
    subgraph "Layer 4 — Intelligence"
        scak[scak]
        mute[mute-agent]
        mcp[mcp-kernel-server]
    end

    subgraph "Layer 3 — Framework"
        cp[control-plane]
        obs[observability]
        nexus[nexus]
    end

    subgraph "Layer 2 — Infrastructure"
        iatp[iatp]
        amb[amb]
        atr[atr]
        runtime[runtime]
    end

    subgraph "Layer 1 — Primitives"
        prim[primitives]
        cmvk[cmvk]
        emk[emk]
        caas[caas]
    end

    %% Declared dependencies
    scak --> prim
    scak -.->|optional| cp
    scak -.->|optional| cmvk
    iatp --> prim
    nexus --> iatp
    runtime --> nexus
    runtime --> iatp
    mcp -.->|optional| cp
    mcp -.->|optional| cmvk
    mcp -.->|optional| iatp

    style prim fill:#4a9eff,color:#fff
    style cmvk fill:#4a9eff,color:#fff
    style emk fill:#4a9eff,color:#fff
    style caas fill:#4a9eff,color:#fff
```

> **Solid arrows** = declared dependencies. **Dashed arrows** = optional/soft dependencies.

## Integration Adapter Lifecycle

Framework integrations (LangChain, CrewAI, etc.) follow a governed execution lifecycle via `BaseIntegration`:

```mermaid
sequenceDiagram
    participant Agent
    participant Integration as BaseIntegration
    participant Policy as GovernancePolicy
    participant Context as ExecutionContext

    Agent->>Integration: execute(input)
    Integration->>Integration: pre_execute(ctx, input)
    Integration->>Policy: validate()
    Integration->>Policy: matches_pattern(input)

    alt Policy Violation
        Policy-->>Integration: blocked_patterns matched
        Integration->>Context: emit(POLICY_VIOLATION)
        Integration-->>Agent: (blocked, reason)
    else Policy Passed
        Policy-->>Integration: OK
        Integration->>Context: emit(POLICY_CHECK)
        Integration->>Integration: execute(ctx, input)
        Integration->>Integration: post_execute(ctx, output)
        Integration->>Context: increment call_count
        Integration->>Context: emit(CHECKPOINT_CREATED)
        Integration-->>Agent: result
    end
```

## Policy Decision Flow

`GovernancePolicy` enforces constraints at every execution boundary:

```mermaid
flowchart LR
    subgraph Evaluate
        A[Receive Request] --> B{allowed_tools?}
        B -->|not in list| C[TOOL_CALL_BLOCKED]
        B -->|allowed| D{blocked_patterns?}
        D -->|SUBSTRING/REGEX/GLOB match| E[POLICY_VIOLATION]
        D -->|clean| F{limits exceeded?}
        F -->|max_tokens / max_tool_calls| G[POLICY_VIOLATION]
        F -->|within limits| H[POLICY_CHECK ✓]
    end

    subgraph Enforce
        H --> I[Execute Action]
        I --> J{confidence_threshold?}
        J -->|below threshold| K[DRIFT_DETECTED]
        J -->|above threshold| L[Increment Counters]
    end

    subgraph Audit
        L --> M[Create AuditEntry]
        K --> M
        C --> M
        E --> M
        M --> N[CHECKPOINT_CREATED]
    end
```

**GovernancePolicy fields:**

| Field | Type | Purpose |
|-------|------|---------|
| `max_tokens_per_request` | `int` | Token budget per execution |
| `max_tool_calls_per_request` | `int` | Tool call limit per execution |
| `blocked_patterns` | `list[BlockedPattern]` | SUBSTRING, REGEX, or GLOB patterns to reject |
| `allowed_tools` | `list[str]` | Allowlist of permitted tool names |
| `confidence_threshold` | `float` | Minimum confidence before drift is flagged |

## State Backend Abstraction

Agent-OS uses a pluggable `StateBackend` protocol for execution state persistence:

```mermaid
classDiagram
    class StateBackend {
        <<protocol>>
        +get(key: str) Optional~Dict~
        +set(key: str, value: Dict, ttl: Optional~int~) None
        +delete(key: str) None
    }

    class MemoryBackend {
        -_store: Dict
        +get(key)
        +set(key, value, ttl)
        +delete(key)
    }

    class RedisBackend {
        -_url: str
        -_key_prefix: str
        +get(key)
        +set(key, value, ttl)
        +delete(key)
    }

    class DynamoDBBackend {
        -_table_name: str
        +get(key)
        +set(key, value, ttl)
        +delete(key)
    }

    StateBackend <|.. MemoryBackend : implements
    StateBackend <|.. RedisBackend : implements
    StateBackend <|.. DynamoDBBackend : implements

    StatelessKernel --> StateBackend : uses

    class StatelessKernel {
        +execute(action, params, context) ExecutionResult
        -_check_policies(action, params, policies) Dict
        -_execute_action(action, params, state) Dict
    }
```

**Usage:** `MemoryBackend` for development/testing, `RedisBackend` for production, `DynamoDBBackend` for serverless deployments.

## Cross-Repo Ecosystem

Agent-OS is one component of a three-repo ecosystem:

```mermaid
graph TB
    subgraph agent-os ["agent-os — Governance Kernel"]
        gov[Policy Enforcement]
        exec[Execution Control]
        state[State Management]
        integ[Framework Integrations]
    end

    subgraph agent-mesh ["agent-mesh — Identity & Trust"]
        id[Cryptographic Identity\nEd25519 / DID]
        trust[Trust Scoring\n5 Dimensions]
        deleg[Scope Chains]
        mesh-net[Mesh Networking]
    end

    subgraph agent-sre ["agent-sre — Reliability"]
        slo[SLO Tracking]
        budget[Error Budgets]
        chaos[Chaos Testing]
        incident[Incident Management]
        progressive[Progressive Delivery]
    end

    agent-mesh -->|"identity & trust\nscoring"| agent-os
    agent-sre -->|"reliability signals\n& SLO data"| agent-os

    agent-os -->|"governance policy\n& audit events"| agent-mesh
    agent-os -->|"execution metrics\n& policy decisions"| agent-sre

    agent-mesh <-->|"trust-informed\ndeployment gates"| agent-sre
```

| Repository | Provides | Consumes |
|-----------|----------|----------|
| **agent-os** | Governance kernel, policy enforcement, execution control | Identity from agent-mesh, reliability signals from agent-sre |
| **agent-mesh** | Cryptographic identity (Ed25519/DID), trust scoring (5 dimensions), scope chains | Governance policies and audit events from agent-os |
| **agent-sre** | SLO tracking, error budgets, chaos testing, incident management, progressive delivery | Execution metrics from agent-os, trust data from agent-mesh |
