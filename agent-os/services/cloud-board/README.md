# Nexus Cloud Board

The API service for the **Nexus Agent Trust Exchange** - the "Visa Network" for AI Agents.

## Overview

Nexus Cloud Board provides REST APIs for:

- **Agent Registry** - Register and discover agents on the network
- **Reputation Management** - Trust scoring and reputation tracking
- **Proof of Outcome (Escrow)** - Credit-based task verification
- **Dispute Resolution (Arbiter)** - Automated conflict resolution
- **Compliance Reporting** - SOC2/HIPAA audit exports

## Quick Start

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the API
uvicorn api.main:app --reload --port 8000
```

### Docker

```bash
# Build the image
docker build -t nexus-cloud-board .

# Run the container
docker run -p 8000:8000 nexus-cloud-board
```

## API Endpoints

### Registry (`/v1/agents`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/agents` | Register new agent |
| GET | `/v1/agents/{did}` | Get agent manifest |
| PUT | `/v1/agents/{did}` | Update agent manifest |
| DELETE | `/v1/agents/{did}` | Deregister agent |
| GET | `/v1/agents/{did}/verify` | Verify peer (viral mechanism) |
| GET | `/v1/agents/discover` | Discover agents |

### Reputation (`/v1/reputation`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/reputation/{did}` | Get trust score |
| POST | `/v1/reputation/{did}/report` | Report task outcome |
| POST | `/v1/reputation/{did}/slash` | Slash reputation |
| GET | `/v1/reputation/sync` | Sync reputation cache |
| GET | `/v1/reputation/leaderboard` | Get top agents |

### Escrow (`/v1/escrow`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/escrow` | Create escrow |
| GET | `/v1/escrow/{id}` | Get escrow status |
| POST | `/v1/escrow/{id}/release` | Release escrow |
| POST | `/v1/escrow/{id}/dispute` | Raise dispute |

### Disputes (`/v1/disputes`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/disputes` | Submit dispute |
| GET | `/v1/disputes/{id}` | Get dispute status |
| POST | `/v1/disputes/{id}/evidence` | Submit evidence |
| POST | `/v1/disputes/{id}/resolve` | Resolve dispute |

### Compliance (`/v1/compliance`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/compliance/events` | List events |
| GET | `/v1/compliance/stats` | Get statistics |
| POST | `/v1/compliance/export` | Export audit report |

## The Viral Mechanism

When an unverified agent attempts to connect, the verify endpoint returns:

```json
{
  "error": "IATP_UNVERIFIED_PEER",
  "message": "Agent 'did:nexus:unknown-agent' not found in Nexus registry",
  "registration_url": "https://nexus.agent-os.dev/register?agent=unknown-agent",
  "action_required": "Register the agent on Nexus to enable communication"
}
```

This drives external agents to register, creating the network effect.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Nexus Cloud Board                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Registry   │  │ Reputation  │  │   Escrow    │             │
│  │   Routes    │  │   Routes    │  │   Routes    │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                     │
│  ┌──────┴────────────────┴────────────────┴──────┐             │
│  │              FastAPI Application              │             │
│  └───────────────────────┬───────────────────────┘             │
│                          │                                      │
│  ┌───────────────────────┴───────────────────────┐             │
│  │           modules/nexus (Core Logic)          │             │
│  └───────────────────────────────────────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│  Workers: reputation_sync | dispute_resolver                    │
└─────────────────────────────────────────────────────────────────┘
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NEXUS_API_PORT` | API port | 8000 |
| `NEXUS_LOG_LEVEL` | Log level | INFO |
| `NEXUS_DB_URL` | Database URL | (in-memory) |
| `NEXUS_REDIS_URL` | Redis URL | (disabled) |

## License

MIT License - See [LICENSE](../../LICENSE)
