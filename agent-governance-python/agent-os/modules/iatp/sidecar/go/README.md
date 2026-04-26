# Go Sidecar - High-Performance IATP Implementation

This is the production-ready Go implementation of the IATP sidecar. It provides:

- **High Concurrency**: Handles 10k+ concurrent requests using Go's goroutines
- **Zero-Copy Proxying**: Efficient byte transfer between caller and agent
- **Minimal Resource Usage**: ~10MB memory footprint, negligible CPU usage
- **Single Static Binary**: No runtime dependencies, easy deployment

## Building the Sidecar

### Local Build

```bash
cd sidecar/go
go mod download
go build -o iatp-sidecar main.go
```

### Docker Build

```bash
cd sidecar/go
docker build -t iatp-sidecar:latest .
```

## Running the Sidecar

### Environment Variables

Configure the sidecar using environment variables:

- `IATP_AGENT_URL`: Backend agent URL (default: `http://localhost:8000`)
- `IATP_PORT`: Sidecar port (default: `8001`)
- `IATP_AGENT_ID`: Agent identifier (default: `default-agent`)
- `IATP_TRUST_LEVEL`: Trust level - `verified_partner`, `trusted`, `standard`, `unknown`, `untrusted` (default: `standard`)
- `IATP_REVERSIBILITY`: Reversibility level - `full`, `partial`, `none` (default: `partial`)
- `IATP_RETENTION`: Retention policy - `ephemeral`, `temporary`, `permanent` (default: `temporary`)
- `IATP_HUMAN_IN_LOOP`: Enable human review - `true`, `false` (default: `false`)
- `IATP_TRAINING_CONSENT`: Allow training data - `true`, `false` (default: `false`)

### Local Execution

```bash
# Default configuration
./iatp-sidecar

# Custom configuration
export IATP_AGENT_URL=http://localhost:8000
export IATP_PORT=8001
export IATP_AGENT_ID=my-agent
export IATP_TRUST_LEVEL=trusted
export IATP_REVERSIBILITY=full
export IATP_RETENTION=ephemeral
./iatp-sidecar
```

### Docker Execution

```bash
docker run -p 8001:8001 \
  -e IATP_AGENT_URL=http://host.docker.internal:8000 \
  -e IATP_AGENT_ID=my-agent \
  -e IATP_TRUST_LEVEL=trusted \
  -e IATP_REVERSIBILITY=full \
  -e IATP_RETENTION=ephemeral \
  iatp-sidecar:latest
```

## API Endpoints

### Health Check

```bash
curl http://localhost:8001/health
```

Response:
```json
{"status": "healthy"}
```

### Capability Manifest

```bash
curl http://localhost:8001/capabilities
```

Response:
```json
{
  "identity": {
    "agent_id": "my-agent"
  },
  "trust_level": "trusted",
  "capabilities": {
    "idempotency": true,
    "concurrency_limit": 100,
    "sla_latency_ms": 2000
  },
  "reversibility": {
    "level": "full",
    "undo_window_seconds": 3600
  },
  "privacy": {
    "retention_policy": "ephemeral",
    "human_in_loop": false,
    "training_consent": false
  }
}
```

### Proxy Request

```bash
curl -X POST http://localhost:8001/proxy \
  -H 'Content-Type: application/json' \
  -d '{"task": "example", "data": {"key": "value"}}'
```

### Trace Logs

```bash
curl http://localhost:8001/trace/{trace_id}
```

## Features

### Automatic Security Validation

- **Credit Card Detection**: Uses Luhn algorithm for validation
- **SSN Detection**: Regex-based SSN pattern matching
- **Sensitive Data Scrubbing**: Automatic redaction in logs

### Trust Score Calculation

Base score from trust level:
- `verified_partner`: 10
- `trusted`: 7
- `standard`: 5
- `unknown`: 2
- `untrusted`: 0

Adjustments:
- +2 if reversibility != `none`
- +1 if retention == `ephemeral`
- -1 if retention == `permanent`
- -2 if human_in_loop == `true`
- -1 if training_consent == `true`

### Policy Enforcement

| Condition | Action |
|-----------|--------|
| Trust score >= 7 | ✅ Allow immediately |
| Trust score 3-6 | ⚠️ Warn (requires override) |
| Trust score < 3 | ⚠️ Warn (requires override) |
| Credit card + permanent retention | 🚫 Block (403 Forbidden) |
| SSN + non-ephemeral retention | 🚫 Block (403 Forbidden) |

### Flight Recorder

All requests are logged with:
- Unique trace ID
- Request/response payloads (scrubbed)
- Latency measurements
- Security warnings and blocks
- Quarantine decisions

## Performance

The Go sidecar is designed for production workloads:

- **Latency**: <1ms overhead per request
- **Memory**: ~10MB base footprint
- **Concurrency**: 10k+ concurrent connections
- **Throughput**: 50k+ requests/second on modern hardware

## Deployment

See the main repository's Docker Compose examples for deployment patterns.

### Kubernetes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: agent-with-sidecar
spec:
  containers:
  - name: agent
    image: my-agent:latest
    ports:
    - containerPort: 8000
  - name: iatp-sidecar
    image: iatp-sidecar:latest
    ports:
    - containerPort: 8001
    env:
    - name: IATP_AGENT_URL
      value: "http://localhost:8000"
    - name: IATP_TRUST_LEVEL
      value: "trusted"
```

## Comparison to Python Sidecar

| Feature | Python Sidecar | Go Sidecar |
|---------|----------------|------------|
| Concurrency | ~1k connections | 10k+ connections |
| Memory | ~50MB | ~10MB |
| Startup Time | ~2s | ~100ms |
| Binary Size | N/A (needs Python) | ~15MB static binary |
| Dependencies | Python + packages | None (static binary) |

## Development

### Running Tests

```bash
go test -v ./...
```

### Hot Reload (Development)

```bash
# Install air for hot reload
go install github.com/cosmtrek/air@latest

# Run with hot reload
air
```

## License

MIT License - See main repository LICENSE file
