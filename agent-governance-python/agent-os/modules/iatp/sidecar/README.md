# IATP Reference Sidecar Architecture

This document describes the reference implementation architecture for IATP sidecars. While the Python SDK provides a working implementation, this guide is for building production-grade sidecars in Go, Rust, or other systems languages.

## Overview

The IATP Sidecar is a lightweight binary that:
1. Sits in front of your agent (like Envoy sits in front of microservices)
2. Intercepts all incoming requests
3. Validates against trust and privacy policies
4. Proxies validated requests to your agent
5. Logs everything for audit and reversibility

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   IATP Sidecar                       │
├──────────────────────────────────────────────────────┤
│                                                      │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │   Proxy     │  │   Policy     │  │  Telemetry │ │
│  │   Layer     │  │   Engine     │  │            │ │
│  └─────────────┘  └──────────────┘  └────────────┘ │
│         ▲                ▲                  ▲        │
│         │                │                  │        │
│         └────────────────┴──────────────────┘        │
│                          │                           │
│                  ┌───────┴────────┐                  │
│                  │  Core Library  │                  │
│                  │  - Manifest    │                  │
│                  │  - Security    │                  │
│                  │  - Trace       │                  │
│                  └────────────────┘                  │
└──────────────────────────────────────────────────────┘
                         ▼
              ┌──────────────────┐
              │   Your Agent     │
              │  (Any Language)  │
              └──────────────────┘
```

## Component Breakdown

### 1. Proxy Layer (`/proxy`)

**Responsibilities:**
- Accept HTTP/gRPC connections
- Route to policy engine for validation
- Forward validated requests to backend agent
- Return responses with trace headers

**Key Files:**
```
/sidecar/proxy/
├── server.go           # HTTP/gRPC server
├── router.go           # Request routing
├── middleware.go       # Trace ID injection, CORS, etc.
└── manifest_handler.go # /.well-known/agent-manifest endpoint
```

**Performance Requirements:**
- Latency overhead: < 5ms (p99)
- Memory: < 50MB baseline
- CPU: < 1% at idle, < 10% under load

### 2. Policy Engine (`/policy`)

**Responsibilities:**
- Load and parse capability manifests
- Evaluate trust scores
- Detect sensitive data (credit cards, SSNs, etc.)
- Apply privacy rules
- Generate warnings or blocks

**Key Files:**
```
/sidecar/policy/
├── evaluator.go        # Main policy evaluation
├── trust_score.go      # Trust score calculation
├── sensitive_data.go   # PII detection (Luhn, regex)
├── privacy_rules.go    # Blocking rules
└── config.go           # Policy configuration
```

**Trust Score Algorithm:**
```go
func CalculateTrustScore(manifest *CapabilityManifest) int {
    score := manifest.TrustLevel.BaseScore() // 0-10
    
    if manifest.Reversibility.Level != "none" {
        score += 2
    }
    if manifest.Privacy.Retention == "ephemeral" {
        score += 1
    }
    if manifest.Privacy.Retention == "permanent" || 
       manifest.Privacy.Retention == "forever" {
        score -= 1
    }
    if manifest.Privacy.HumanInLoop {
        score -= 2
    }
    if manifest.Privacy.TrainingConsent {
        score -= 1
    }
    
    return clamp(score, 0, 10)
}
```

### 3. Telemetry Layer (`/telemetry`)

**Responsibilities:**
- Generate unique trace IDs (UUIDs)
- Log requests, responses, errors, blocks
- Scrub sensitive data before logging
- Support distributed tracing (OpenTelemetry)
- Provide trace retrieval API

**Key Files:**
```
/sidecar/telemetry/
├── flight_recorder.go  # Append-only audit log
├── trace_id.go         # Trace ID generation
├── scrubber.go         # PII scrubbing for logs
├── otel_bridge.go      # OpenTelemetry integration
└── metrics.go          # Prometheus metrics
```

**Log Format (JSONL):**
```json
{"type":"request","trace_id":"abc-123","timestamp":"2026-01-23T12:34:56Z","payload":"<scrubbed>"}
{"type":"response","trace_id":"abc-123","timestamp":"2026-01-23T12:34:57Z","latency_ms":1243.56}
{"type":"error","trace_id":"abc-123","timestamp":"2026-01-23T12:34:57Z","error":"timeout"}
{"type":"blocked","trace_id":"abc-123","timestamp":"2026-01-23T12:34:56Z","reason":"credit_card_to_untrusted"}
```

### 4. Core Library (`/core`)

**Shared data structures and utilities:**

```
/sidecar/core/
├── manifest.go         # CapabilityManifest struct
├── trust_levels.go     # TrustLevel enum
├── reversibility.go    # Reversibility types
├── privacy.go          # Privacy policy types
└── validation.go       # Manifest JSON validation
```

**Example (Go):**
```go
type CapabilityManifest struct {
    Schema   string   `json:"$schema"`
    Identity Identity `json:"identity"`
    
    TrustLevel      TrustLevel      `json:"trust_level"`
    Capabilities    Capabilities    `json:"capabilities,omitempty"`
    Reversibility   Reversibility   `json:"reversibility,omitempty"`
    Privacy         Privacy         `json:"privacy,omitempty"`
    Authentication  Authentication  `json:"authentication,omitempty"`
    RateLimiting    RateLimiting    `json:"rate_limiting,omitempty"`
    
    ProtocolVersion string `json:"protocol_version"`
    ManifestVersion string `json:"manifest_version,omitempty"`
    UpdatedAt       string `json:"updated_at,omitempty"`
}

type TrustLevel string

const (
    TrustLevelVerifiedPartner TrustLevel = "verified_partner"
    TrustLevelTrusted         TrustLevel = "trusted"
    TrustLevelStandard        TrustLevel = "standard"
    TrustLevelUnknown         TrustLevel = "unknown"
    TrustLevelUntrusted       TrustLevel = "untrusted"
)

func (t TrustLevel) BaseScore() int {
    switch t {
    case TrustLevelVerifiedPartner: return 10
    case TrustLevelTrusted:         return 7
    case TrustLevelStandard:        return 5
    case TrustLevelUnknown:         return 2
    case TrustLevelUntrusted:       return 0
    default:                        return 0
    }
}
```

## Implementation Roadmap

### Phase 1: Minimal Viable Sidecar (Week 1-2)
- [ ] HTTP server with manifest endpoint
- [ ] Basic proxy to backend agent
- [ ] Trace ID generation
- [ ] Trust score calculation
- [ ] Simple logging (stdout)

### Phase 2: Security & Privacy (Week 3-4)
- [ ] Sensitive data detection (Luhn algorithm for credit cards)
- [ ] Privacy rule evaluation
- [ ] Warning/block responses (449/403)
- [ ] User override mechanism (X-User-Override header)
- [ ] Flight recorder (JSONL files)

### Phase 3: Production Hardening (Week 5-6)
- [ ] OpenTelemetry integration
- [ ] Prometheus metrics
- [ ] Rate limiting
- [ ] Connection pooling
- [ ] Graceful shutdown
- [ ] Health checks

### Phase 4: Advanced Features (Week 7-8)
- [ ] gRPC support
- [ ] mTLS between sidecars
- [ ] Manifest caching (1-hour TTL)
- [ ] Distributed saga coordination
- [ ] Kubernetes deployment manifests

## Configuration

### Environment Variables

```bash
# Backend agent configuration
IATP_BACKEND_URL=http://localhost:8000
IATP_BACKEND_TIMEOUT=30s

# Sidecar server configuration
IATP_PORT=8001
IATP_LOG_LEVEL=info

# Telemetry
IATP_LOG_DIR=/var/log/iatp
IATP_OTEL_ENDPOINT=http://localhost:4318
IATP_METRICS_PORT=9090

# Policy
IATP_TRUST_THRESHOLD=3
IATP_ALLOW_OVERRIDE=true
```

### Config File (YAML)

```yaml
# iatp.yaml
backend:
  url: http://localhost:8000
  timeout: 30s
  
server:
  port: 8001
  log_level: info
  
telemetry:
  log_dir: /var/log/iatp
  otel_endpoint: http://localhost:4318
  metrics_port: 9090
  
policy:
  trust_threshold: 3
  allow_override: true
  block_rules:
    - name: credit_card_to_untrusted
      condition: "has_credit_card && trust_level == 'untrusted'"
      action: block
    - name: ssn_to_permanent
      condition: "has_ssn && retention == 'permanent'"
      action: block
```

## Deployment Patterns

### 1. Sidecar Container (Kubernetes)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: booking-agent
spec:
  containers:
  - name: agent
    image: my-agent:v1.0.0
    ports:
    - containerPort: 8000
  
  - name: iatp-sidecar
    image: iatp-sidecar:v1.0.0
    ports:
    - containerPort: 8001
    env:
    - name: IATP_BACKEND_URL
      value: "http://localhost:8000"
    - name: IATP_PORT
      value: "8001"
```

### 2. Standalone Binary

```bash
# Build
go build -o iatp-sidecar ./cmd/sidecar

# Run
./iatp-sidecar \
  --backend-url=http://localhost:8000 \
  --port=8001 \
  --manifest=/etc/iatp/manifest.json
```

### 3. Systemd Service

```ini
[Unit]
Description=IATP Sidecar
After=network.target

[Service]
Type=simple
User=iatp
ExecStart=/usr/local/bin/iatp-sidecar \
  --backend-url=http://localhost:8000 \
  --port=8001 \
  --manifest=/etc/iatp/manifest.json
Restart=always

[Install]
WantedBy=multi-user.target
```

## Testing

### Unit Tests

```go
func TestTrustScoreCalculation(t *testing.T) {
    manifest := &CapabilityManifest{
        TrustLevel: TrustLevelVerifiedPartner,
        Reversibility: Reversibility{Level: "partial"},
        Privacy: Privacy{Retention: "ephemeral"},
    }
    
    score := CalculateTrustScore(manifest)
    assert.Equal(t, 10, score) // 10 + 2 + 1 = 13, clamped to 10
}
```

### Integration Tests

```go
func TestProxyFlow(t *testing.T) {
    // Start mock backend
    backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(200)
        w.Write([]byte(`{"result":"success"}`))
    }))
    defer backend.Close()
    
    // Start sidecar
    sidecar := NewSidecar(backend.URL, manifest)
    go sidecar.Run()
    
    // Make request
    resp, err := http.Post("http://localhost:8001/proxy", "application/json", 
        strings.NewReader(`{"task":"test"}`))
    
    assert.NoError(t, err)
    assert.Equal(t, 200, resp.StatusCode)
}
```

### Load Tests

```bash
# Using Apache Bench
ab -n 10000 -c 100 http://localhost:8001/proxy

# Using vegeta
echo "POST http://localhost:8001/proxy" | \
  vegeta attack -duration=60s -rate=1000 | \
  vegeta report
```

## Performance Benchmarks

Target metrics for a production sidecar:

| Metric | Target | Notes |
|--------|--------|-------|
| Latency (p50) | < 1ms | Proxy overhead only |
| Latency (p99) | < 5ms | Including policy evaluation |
| Throughput | > 10k RPS | On 2-core machine |
| Memory | < 50MB | At idle |
| Memory | < 200MB | Under load (10k RPS) |
| CPU | < 1% | At idle |
| CPU | < 50% | At 10k RPS |

## Security Considerations

### 1. Input Validation

- Validate all JSON payloads against schema
- Reject requests larger than 10MB (configurable)
- Sanitize log output to prevent log injection

### 2. Denial of Service

- Rate limiting (token bucket algorithm)
- Connection limits per IP
- Request timeout enforcement

### 3. Authentication

Support multiple auth methods:
- API keys (custom header)
- OAuth 2.0 (Bearer tokens)
- Mutual TLS (certificate-based)
- JWT (signed tokens)

### 4. Secrets Management

- Never log secrets or API keys
- Support external secret stores (Vault, AWS Secrets Manager)
- Rotate keys regularly

## Monitoring & Observability

### Prometheus Metrics

```
# Requests
iatp_requests_total{status="200|449|403|500"} counter
iatp_request_duration_seconds{quantile="0.5|0.9|0.99"} histogram

# Policy
iatp_policy_evaluations_total{result="allow|warn|block"} counter
iatp_trust_score_distribution{score="0-10"} histogram

# Telemetry
iatp_logs_written_total counter
iatp_trace_storage_bytes gauge
```

### OpenTelemetry Traces

```
Span: iatp.proxy
├── Span: iatp.policy.evaluate
│   ├── Span: iatp.policy.detect_sensitive_data
│   └── Span: iatp.policy.calculate_trust_score
├── Span: iatp.proxy.forward
└── Span: iatp.telemetry.log_request
```

## Contributing

To contribute to the reference sidecar:

1. Implement in Go (preferred) or Rust
2. Follow the architecture described here
3. Add comprehensive tests (unit + integration)
4. Benchmark performance
5. Submit PR with documentation

## Future Enhancements

- [ ] WebAssembly plugin system for custom policies
- [ ] Multi-region deployment support
- [ ] Federated trust networks
- [ ] Blockchain-based manifest verification
- [ ] AI-powered anomaly detection

## References

- Envoy Proxy: https://www.envoyproxy.io/
- Service Mesh Pattern: https://www.nginx.com/blog/what-is-a-service-mesh/
- Istio Architecture: https://istio.io/latest/docs/ops/deployment/architecture/
- OpenTelemetry: https://opentelemetry.io/
- Protocol Buffers: https://protobuf.dev/

---

**Status:** Reference architecture for implementation. Python SDK provides a working proof-of-concept.
