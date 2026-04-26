# AgentMesh Public API

REST API for agent registration, trust verification, handshake protocol, and trust scoring.

## Quick Start

```bash
# Install dependencies
npm install

# Development
npm run dev

# Build & start
npm run build && npm start

# Run tests
npm test
```

The server starts on port `3000` by default (override with `PORT` env var).

## API Endpoints

### Health Check

```bash
curl http://localhost:3000/api/health
```

```json
{ "status": "ok", "service": "agentmesh-api", "version": "0.1.0" }
```

### Register Agent

```bash
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -H "x-api-key: <your-api-key>" \
  -d '{
    "name": "MyAgent",
    "sponsor_email": "owner@example.com",
    "capabilities": ["read", "write", "execute"]
  }'
```

```json
{
  "agent_did": "did:mesh:550e8400-e29b-41d4-a716-446655440000",
  "api_key": "amesh_abc123...",
  "public_key": "MCowBQYDK2VwAyEA...",
  "verification_url": "/api/verify/did:mesh:550e8400-e29b-41d4-a716-446655440000"
}
```

### Verify Agent

```bash
curl http://localhost:3000/api/verify/did:mesh:550e8400-e29b-41d4-a716-446655440000
```

```json
{
  "registered": true,
  "trust_score": 435,
  "sponsor": "owner@example.com",
  "status": "active",
  "capabilities": ["read", "write", "execute"]
}
```

### Trust Handshake

```bash
curl -X POST http://localhost:3000/api/handshake \
  -H "Content-Type: application/json" \
  -H "x-api-key: <your-api-key>" \
  -d '{
    "agent_did": "did:mesh:550e8400-e29b-41d4-a716-446655440000",
    "challenge": "random-nonce-value",
    "capabilities_requested": ["read", "execute"]
  }'
```

```json
{
  "verified": true,
  "trust_score": 435,
  "capabilities_granted": ["read", "execute"],
  "signature": "base64-ed25519-signature..."
}
```

### Trust Score Breakdown

```bash
curl http://localhost:3000/api/score/did:mesh:550e8400-e29b-41d4-a716-446655440000
```

```json
{
  "total": 435,
  "dimensions": {
    "policy_compliance": 50,
    "interaction_success": 50,
    "verification_depth": 30,
    "community_vouching": 0,
    "uptime_reliability": 50
  },
  "tier": "Verified",
  "history": [
    { "timestamp": "2025-01-01T00:00:00.000Z", "event": "initial_registration", "score_delta": 435 }
  ]
}
```

## Authentication

Write endpoints (`POST /api/register`, `POST /api/handshake`) require an API key in the `x-api-key` header. API keys are issued during agent registration and use the `amesh_` prefix.

Read endpoints (`GET /api/health`, `GET /api/verify/:agentDid`, `GET /api/score/:agentDid`) are public.

## Rate Limiting

All endpoints are rate-limited to **100 requests per minute** per IP address. Rate limit headers are included in every response:

- `X-RateLimit-Limit` — Maximum requests per window
- `X-RateLimit-Remaining` — Remaining requests
- `X-RateLimit-Reset` — Window reset time (Unix timestamp)

## Trust Scoring

Trust scores range from 0–1000 and are computed from five weighted dimensions:

| Dimension | Weight | Description |
|-----------|--------|-------------|
| Policy Compliance | 2.5× | Adherence to mesh governance policies |
| Interaction Success | 2.5× | Success rate of agent interactions |
| Verification Depth | 2.0× | Depth of identity verification |
| Community Vouching | 1.5× | Endorsements from other agents |
| Uptime Reliability | 1.5× | Service availability and responsiveness |

**Trust Tiers:**

| Tier | Score Range |
|------|-------------|
| Highly Trusted | 900–1000 |
| Trusted | 750–899 |
| Verified | 500–749 |
| Basic | 250–499 |
| Untrusted | 0–249 |

## Deployment

### Local

```bash
npm install && npm run build && npm start
```

### Docker

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY dist/ ./dist/
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

```bash
docker build -t agentmesh-api .
docker run -p 3000:3000 agentmesh-api
```

### Vercel

Deploy as a Vercel serverless function:

```bash
npm i -g vercel
vercel
```

## Architecture

- **Registry**: In-memory store (Map) for agent records, keyed by DID
- **Identity**: Ed25519 keypair generation and signing via Node.js `crypto`
- **Trust Engine**: Weighted multi-dimensional scoring with tier classification
- **Audit Log**: hash-chained append-only log for tamper-evident audit trail
