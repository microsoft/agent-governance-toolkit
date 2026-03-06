# IATP Deployment Guide

This guide covers all deployment methods for the Inter-Agent Trust Protocol.

## Quick Start

### One-Line Docker Deploy

```bash
docker compose up -d
```

This starts:
- **Secure Bank Agent** + Sidecar at `http://localhost:8081`
- **Honeypot Agent** + Sidecar at `http://localhost:9001`

Test it:
```bash
# Check sidecar health
curl http://localhost:8081/health

# Get agent capabilities (the IATP handshake)
curl http://localhost:8081/.well-known/agent-manifest

# Send a request through the sidecar
curl -X POST http://localhost:8081/proxy \
  -H "Content-Type: application/json" \
  -d '{"action": "check_balance", "account": "12345"}'
```

## Installation Methods

### Option 1: PyPI (Recommended)

```bash
pip install inter-agent-trust-protocol
```

### Option 2: From Source

```bash
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd inter-agent-trust-protocol
pip install -e .
```

### Option 3: Docker

```bash
docker build -t iatp-sidecar .
docker run -p 8081:8081 \
  -e IATP_AGENT_URL=http://my-agent:8000 \
  -e IATP_AGENT_ID=my-agent \
  -e IATP_TRUST_LEVEL=trusted \
  iatp-sidecar
```

## Running the Sidecar

### Method 1: Direct (uvicorn)

```bash
# Set environment variables
export IATP_AGENT_URL=http://localhost:8000
export IATP_AGENT_ID=my-agent
export IATP_TRUST_LEVEL=trusted

# Run the sidecar
uvicorn iatp.main:app --host 0.0.0.0 --port 8081
```

### Method 2: Docker

```bash
docker run -p 8081:8081 \
  -e IATP_AGENT_URL=http://my-agent:8000 \
  iatp-sidecar
```

### Method 3: Docker Compose

```yaml
services:
  my-agent:
    build: .
    ports:
      - "8000:8000"
  
  iatp-sidecar:
    image: iatp-sidecar:latest
    environment:
      - IATP_AGENT_URL=http://my-agent:8000
      - IATP_AGENT_ID=my-agent
      - IATP_TRUST_LEVEL=trusted
    ports:
      - "8081:8081"
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IATP_AGENT_URL` | `http://localhost:8000` | Backend agent URL |
| `IATP_PORT` | `8081` | Sidecar port |
| `IATP_AGENT_ID` | `default-agent` | Agent identifier |
| `IATP_TRUST_LEVEL` | `standard` | Trust level (verified_partner, trusted, standard, unknown, untrusted) |
| `IATP_REVERSIBILITY` | `partial` | Reversibility level (full, partial, none) |
| `IATP_RETENTION` | `ephemeral` | Data retention policy (ephemeral, temporary, permanent) |
| `IATP_HUMAN_REVIEW` | `false` | Whether humans review data |
| `IATP_TRAINING_CONSENT` | `false` | Use data for ML training |

## Service Ports

| Service | Port | Purpose |
|---------|------|---------|
| Your Agent | 8000 | Backend agent (internal) |
| IATP Sidecar | 8081 | Sidecar proxy (public) |
| Go Sidecar | 8002 | High-performance sidecar (production) |

## Pre-Deployment Checklist

### Define Capability Manifest

```python
manifest = CapabilityManifest(
    agent_id="production-agent-v1",
    trust_level=TrustLevel.TRUSTED,
    capabilities=AgentCapabilities(
        reversibility=ReversibilityLevel.FULL,
        idempotency=True,
        concurrency_limit=100,
        sla_latency_ms=2000
    ),
    privacy_contract=PrivacyContract(
        retention=RetentionPolicy.EPHEMERAL,
        human_in_loop=False,
        training_consent=False
    )
)
```

### Security Review

- [ ] Review sensitive data patterns (credit cards, SSNs)
- [ ] Verify Luhn validation is working
- [ ] Test privacy policy enforcement
- [ ] Ensure sensitive data scrubbing in logs

### Performance Testing

**Python Sidecar:**
- [ ] Test with 100 concurrent requests
- [ ] Measure latency overhead (<10ms expected)
- [ ] Check memory usage (~50MB expected)

**Go Sidecar (Recommended for Production):**
- [ ] Test with 10,000 concurrent requests
- [ ] Measure latency overhead (<1ms expected)
- [ ] Check memory usage (~10MB expected)

## Kubernetes Deployment

### Basic Sidecar Pattern

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-deployment
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: agent
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

### Resource Limits

**Python Sidecar:**
```yaml
resources:
  limits:
    memory: "128Mi"
    cpu: "200m"
  requests:
    memory: "64Mi"
    cpu: "100m"
```

**Go Sidecar:**
```yaml
resources:
  limits:
    memory: "32Mi"
    cpu: "100m"
  requests:
    memory: "16Mi"
    cpu: "50m"
```

## Testing the Deployment

### Health Check

```bash
curl http://localhost:8081/health
```

### Capability Discovery

```bash
curl http://localhost:8081/.well-known/agent-manifest
```

### Secure Transaction

```bash
curl -X POST http://localhost:8081/proxy \
  -H "Content-Type: application/json" \
  -d '{"task": "transfer", "data": {"amount": 100}}'
```

### Using the CLI

```bash
# Scan an agent for trust score
iatp scan http://localhost:8081

# Verify a manifest file
iatp verify examples/manifests/secure_bank.json
```

## Troubleshooting

### Sidecar Won't Start

1. Check agent URL is accessible
2. Verify port not already in use
3. Check environment variables
4. Review sidecar logs

### High Latency

1. Switch to Go sidecar if using Python
2. Check network latency to agent
3. Verify agent performance
4. Review trust score calculation overhead

### Requests Being Blocked

1. Review manifest configuration
2. Check trust score calculation
3. Verify privacy policy settings
4. Test with user override: `X-User-Override: true`

## Security Hardening

### Network Security

- Use HTTPS between sidecar and external callers
- Keep sidecar <-> agent on localhost
- Implement mTLS for inter-agent communication
- Use network policies (Kubernetes)

### Data Protection

- Encrypt logs at rest
- Use secret management for sensitive config
- Rotate credentials regularly
- Audit access to trace data

## Monitoring

### Key Metrics

- Requests blocked per day
- Sensitive data detected per day
- Trust score distribution
- P50/P95/P99 latency
- Error rate

### Health Endpoints

- `GET /health` - Basic health check
- `GET /metrics` - Prometheus-compatible metrics
- `GET /trace/{trace_id}` - Audit log retrieval

## Additional Resources

- [Architecture Guide](ARCHITECTURE.md)
- [CLI Guide](CLI_GUIDE.md)
- [Main README](../README.md)
- [Changelog](../CHANGELOG.md)
