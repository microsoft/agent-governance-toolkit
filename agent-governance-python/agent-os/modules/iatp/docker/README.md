# Docker Deployment for IATP

This directory contains Docker configurations for deploying IATP-protected agents.

## Quick Start

### Start Everything

```bash
docker-compose up
```

This starts:
- Secure Bank Agent (port 8000)
- Python IATP Sidecar (port 8001)
- Go IATP Sidecar (port 8002)
- Honeypot Agent (port 8100)
- Honeypot Sidecar (port 8101)

### Start Just the Secure Bank Agent

```bash
docker-compose up bank-agent iatp-sidecar-python
```

### Start Just the Honeypot

```bash
docker-compose up honeypot-agent honeypot-sidecar
```

## Testing

### Test Secure Bank Agent (High Trust)

```bash
# Direct request (should succeed immediately)
curl -X POST http://localhost:8001/proxy \
  -H 'Content-Type: application/json' \
  -d '{"task":"transfer","data":{"amount":100,"from":"123","to":"456"}}'
```

### Test Honeypot Agent (Low Trust)

```bash
# Request with sensitive data (should be BLOCKED)
curl -X POST http://localhost:8101/proxy \
  -H 'Content-Type: application/json' \
  -d '{"task":"book","data":{"payment":"4532-0151-1283-0366"}}'

# Request without sensitive data (should WARN)
curl -X POST http://localhost:8101/proxy \
  -H 'Content-Type: application/json' \
  -d '{"task":"book","data":{"destination":"NYC"}}'

# With override
curl -X POST http://localhost:8101/proxy \
  -H 'Content-Type: application/json' \
  -H 'X-User-Override: true' \
  -d '{"task":"book","data":{"destination":"NYC"}}'
```

### Check Health

```bash
# Python sidecar
curl http://localhost:8001/health

# Go sidecar
curl http://localhost:8002/health

# Honeypot sidecar
curl http://localhost:8101/health
```

### Get Capability Manifests

```bash
# Python sidecar
curl http://localhost:8001/capabilities

# Go sidecar
curl http://localhost:8002/capabilities

# Honeypot sidecar
curl http://localhost:8101/capabilities
```

## Building Individual Images

### Build Agent Image

```bash
docker build -f docker/Dockerfile.agent -t iatp-agent:latest .
```

### Build Python Sidecar

```bash
docker build -f docker/Dockerfile.sidecar-python -t iatp-sidecar-python:latest .
```

### Build Go Sidecar

```bash
cd sidecar/go
docker build -t iatp-sidecar-go:latest .
```

## Publishing to Docker Hub

```bash
# Tag images
docker tag iatp-sidecar-go:latest your-username/iatp-sidecar:latest
docker tag iatp-agent:latest your-username/iatp-honeypot:latest

# Push images
docker push your-username/iatp-sidecar:latest
docker push your-username/iatp-honeypot:latest
```

## Using in Your Own Projects

### Option 1: Docker Compose

```yaml
version: '3.8'

services:
  my-agent:
    image: my-agent:latest
    ports:
      - "8000:8000"
  
  iatp-sidecar:
    image: your-username/iatp-sidecar:latest
    ports:
      - "8001:8001"
    environment:
      - IATP_AGENT_URL=http://my-agent:8000
      - IATP_AGENT_ID=my-agent
      - IATP_TRUST_LEVEL=trusted
      - IATP_REVERSIBILITY=full
      - IATP_RETENTION=ephemeral
    depends_on:
      - my-agent
```

### Option 2: Kubernetes

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
    image: your-username/iatp-sidecar:latest
    ports:
    - containerPort: 8001
    env:
    - name: IATP_AGENT_URL
      value: "http://localhost:8000"
    - name: IATP_TRUST_LEVEL
      value: "trusted"
```

### Option 3: Network Sharing (Advanced)

For true sidecar pattern with shared network namespace:

```yaml
version: '3.8'

services:
  my-agent:
    image: my-agent:latest
    ports:
      - "8000:8000"
  
  iatp-sidecar:
    image: your-username/iatp-sidecar:latest
    network_mode: "service:my-agent"  # Share network with agent
    environment:
      - IATP_AGENT_URL=http://localhost:8000
      - IATP_PORT=8001
```

With this setup, the sidecar shares the same network namespace as the agent, allowing for true zero-latency communication.

## Environment Variables

### Agent Variables

- `AGENT_TYPE`: Type of agent to run (`secure_bank`, `untrusted`, or default `backend`)

### Sidecar Variables

- `IATP_AGENT_URL`: Backend agent URL (default: `http://localhost:8000`)
- `IATP_PORT`: Sidecar port (default: `8001`)
- `IATP_AGENT_ID`: Agent identifier
- `IATP_TRUST_LEVEL`: Trust level (`verified_partner`, `trusted`, `standard`, `unknown`, `untrusted`)
- `IATP_REVERSIBILITY`: Reversibility level (`full`, `partial`, `none`)
- `IATP_RETENTION`: Data retention policy (`ephemeral`, `temporary`, `permanent`)
- `IATP_HUMAN_IN_LOOP`: Enable human review (`true`, `false`)
- `IATP_TRAINING_CONSENT`: Allow training data usage (`true`, `false`)

## Troubleshooting

### Sidecar can't reach agent

Make sure both containers are on the same network and use the correct service name:

```yaml
environment:
  - IATP_AGENT_URL=http://agent-service-name:8000
```

### Health checks failing

Check logs:
```bash
docker-compose logs iatp-sidecar-python
```

Increase health check timeout:
```yaml
healthcheck:
  timeout: 10s
  retries: 5
```

### Port conflicts

Change exposed ports in docker-compose.yml:
```yaml
ports:
  - "9001:8001"  # Map container port 8001 to host port 9001
```

## Cleaning Up

```bash
# Stop all containers
docker-compose down

# Remove volumes
docker-compose down -v

# Remove images
docker-compose down --rmi all
```
