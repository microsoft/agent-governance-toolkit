# IATP Architecture

## Overview

The Inter-Agent Trust Protocol (IATP) implements a **Zero-Config Sidecar Architecture** that extracts trust, security, and governance concerns from AI agents. Just like Envoy transformed microservices by extracting networking concerns into a sidecar, IATP extracts trust concerns into a lightweight proxy.

## Core Architecture: "The Agent Mesh"

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│ Your Agent  │ ──────> │ IATP Sidecar │ ──────> │ Other Agent │
│ (Internal)  │         │   (Local)    │         │  (External) │
└─────────────┘         └──────────────┘         └─────────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
              ┌─────▼─────┐      ┌──────▼──────┐
              │  Policy   │      │  Recovery   │
              │  Engine   │      │   Engine    │
              └───────────┘      └─────────────┘
```

## The "Invisible Sidecar" Pattern

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Client    │ ──────> │ IATP Sidecar │ ──────> │ Your Agent  │
│             │         │  (Port 8081) │         │ (Port 8000) │
└─────────────┘         └──────────────┘         └─────────────┘
                              ▼
                    ┌─────────────────────┐
                    │  Security Checks    │
                    │  Privacy Validation │
                    │  Trace Logging      │
                    │  Rate Limiting      │
                    └─────────────────────┘
```

## Components

### 1. Sidecar Proxy (`iatp/sidecar/` and `iatp/main.py`)

**FastAPI-based Proxy Server**

The sidecar intercepts all incoming requests before they reach the agent:
- Exchanges capability manifests via `.well-known/agent-manifest` endpoint
- Validates requests against privacy policies
- Routes validated requests to backend agent
- Injects distributed trace IDs (`X-Agent-Trace-ID`)

**Endpoints:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/agent-manifest` | GET | Handshake endpoint |
| `/proxy` | POST | Main proxy endpoint with validation |
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus-compatible metrics |
| `/trace/{trace_id}` | GET | Retrieve audit logs |
| `/quarantine/{trace_id}` | GET | Get quarantine session info |

**Headers:**
- Request: `X-User-Override` (bypass warnings), `X-Agent-Trace-ID` (tracing)
- Response: `X-Agent-Trace-ID`, `X-Agent-Trust-Score`, `X-Agent-Latency-Ms`, `X-Agent-Quarantined`

### 2. Policy Engine (`iatp/policy_engine.py`)

Built-in policy validation engine:

- Validates capability manifests against customizable policy rules
- Provides warn vs. block decision logic
- Supports custom rule addition at runtime
- Integrates with existing SecurityValidator
- Uses Protocol classes for extensibility (duck typing)

### 3. Recovery Engine (`iatp/recovery.py`)

Wraps `scak` (Self-Correcting Agent Kernel) for failure recovery:

- Structured failure tracking using scak's AgentFailure models
- Intelligent recovery strategies (rollback, retry, give-up)
- Compensation transaction support
- Async/sync callback support

### 4. Security & Privacy Layer (`iatp/security/`)

**SecurityValidator:**
- Detects sensitive data (credit cards with Luhn validation, SSNs, emails)
- Validates privacy policies against request contents
- Generates warnings for risky requests
- **Blocks** dangerous requests (e.g., credit cards to untrusted agents)

**Privacy Rules:**
- Credit cards → BLOCKED if agent has permanent retention
- SSNs → BLOCKED if agent has non-ephemeral retention
- Warnings for low trust scores, no reversibility, permanent storage, human review

### 5. Telemetry & Flight Recorder (`iatp/telemetry/`)

**FlightRecorder** - The "Black Box":
- Records all requests with timestamps
- Logs responses with latency metrics
- Tracks errors and timeouts
- Logs blocked requests with reasons
- Records user override decisions
- All logs include scrubbed payloads

## Request Flow

```
1. Request arrives at sidecar
   ↓
2. Policy Engine validation (agent-control-plane)
   - Validates manifest against rules
   - Checks trust level, retention, reversibility
   ↓
3. Security validation (SecurityValidator)
   - Detects sensitive data (credit cards, SSN)
   - Checks privacy policies
   ↓
4. Route to backend agent
   ↓
5. On error → Recovery Engine (scak)
   - Creates AgentFailure record
   - Determines recovery strategy
   - Executes compensation if available
   - Returns recovery information
```

## Key Architectural Decisions

### 1. The Sidecar Pattern

**Decision**: Extract trust logic from agents into a separate sidecar process.

**Rationale**:
- Agents stay simple (just business logic)
- Security is centralized (one sidecar, many agents)
- Policies are uniform (same rules for all agents)
- Language-agnostic (works with any agent)

### 2. Trust Score (0-10)

**Decision**: Calculate a simple numeric trust score instead of binary allow/deny.

**Algorithm**:
```
Base = trust_level (verified_partner=10, trusted=7, standard=5, unknown=2, untrusted=0)
+2 if reversibility != "none"
+1 if retention == "ephemeral"
-1 if retention == "permanent"
-2 if human_in_loop
-1 if training_consent
Min: 0, Max: 10
```

### 3. Three-Tier Policy Enforcement

**Rules**:
- **Allow** (trust >= 7): Immediate execution
- **Warn** (trust < 7): 449 status, requires `X-User-Override: true`
- **Block** (critical violations): 403 Forbidden, no override

### 4. Flight Recorder (JSONL Logs)

**Format**:
```json
{"type":"request","trace_id":"...","timestamp":"...","payload":"<scrubbed>"}
{"type":"response","trace_id":"...","timestamp":"...","latency_ms":123.45}
{"type":"blocked","trace_id":"...","timestamp":"...","reason":"..."}
{"type":"quarantine","trace_id":"...","timestamp":"...","override":true}
```

### 5. Status Code 449 for Warnings

**Rationale**:
- Semantic meaning: "retry with additional info"
- Distinguishes from errors (4xx/5xx)
- Client knows to retry with `X-User-Override: true`

## Performance Targets

| Implementation | Latency (p99) | Throughput | Memory |
|----------------|---------------|------------|--------|
| Python Sidecar | < 10ms | ~1k RPS | ~50MB |
| Go Sidecar | < 1ms | > 10k RPS | ~10MB |

## Deployment Patterns

### Kubernetes Sidecar
```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: my-agent
        image: my-agent:latest
        ports:
        - containerPort: 8000
      - name: iatp-sidecar
        image: iatp-sidecar:latest
        ports:
        - containerPort: 8081
        env:
        - name: IATP_AGENT_URL
          value: "http://localhost:8000"
```

### Docker Compose
```yaml
services:
  my-agent:
    image: my-agent:latest
  iatp-sidecar:
    image: iatp-sidecar:latest
    environment:
      - IATP_AGENT_URL=http://my-agent:8000
    ports:
      - "8081:8081"
```

### Standalone Binary
```bash
# Go sidecar
./iatp-sidecar --agent-url=http://localhost:8000 --port=8081
```

## Integration with External Libraries

### agent-control-plane

Used for policy validation in `IATPPolicyEngine`:
- Rule-based policy engine
- Custom conditions and actions
- Manifest validation

### scak (Self-Correcting Agent Kernel)

Used for failure recovery in `IATPRecoveryEngine`:
- Structured failure tracking
- Recovery strategies
- Compensation transactions
