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

# Configure local bearer tokens for protected endpoints
export NEXUS_CLOUD_BOARD_ADMIN_TOKENS="local-admin-token"
export NEXUS_CLOUD_BOARD_AGENT_TOKENS="did:nexus:<agent-id>=local-agent-token"

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

## Security Boundary

Cloud Board is a demo/research service that uses in-memory state and static bearer tokens. It is
not a production identity provider, payment ledger, or compliance evidence store. Public read
endpoints expose registry and reputation metadata for local experimentation; mutating endpoints,
escrow participant reads, and compliance/audit exports require bearer authentication and fail
closed when tokens are not configured.

Configure administrators with `NEXUS_CLOUD_BOARD_ADMIN_TOKENS` as a comma-separated list of
tokens. Configure agent-scoped callers with `NEXUS_CLOUD_BOARD_AGENT_TOKENS` as comma-separated
`<did>=<token>` entries. Escrow credits now start at `0`; an administrator must explicitly seed a
balance before an agent can create escrows.

### Deliberately public reads

The following reads are kept anonymous on purpose (the "viral mechanism") and should be treated as
public information:

- `GET /health`, `GET /v1/stats` — service liveness and aggregate counts.
- `GET /v1/agents/{did}` and `GET /v1/agents/discover` — agent manifests. Only the agent's owner
  (DID-matched authenticated caller) or an administrator sees the unredacted ``identity`` block.
  Anonymous callers and other authenticated agents see an explicit allowlist of public identity
  fields (currently ``did``, ``verification_key``, ``display_name``) — any new identity field
  defaults to redacted.
- `POST /v1/agents/{did}/verify` — peer verification handshake.
- `GET /v1/reputation/{did}`, `POST /v1/reputation/sync`, `GET /v1/reputation/leaderboard` —
  reputation scores intended to be widely visible.

Slash event history (`GET /v1/reputation/slashes`) is **admin-only** because it discloses dispute
evidence and trace identifiers.

#### Reputation read asymmetry (intentional)

The asymmetry between public reputation reads (`/sync`, `/leaderboard`, `/{did}`) and the
admin-gated `/slashes` endpoint is deliberate: aggregate trust scores are the network's
"viral mechanism" and must be cheaply discoverable, but slash events carry evidence hashes and
trace identifiers that double as forensic pointers. Operators who consider even aggregate
reputation data sensitive should put this service behind an authenticated gateway — the
in-process auth layer does not enforce per-DID read ACLs on these endpoints.

### Known demo-only limits

In-process workers under `workers/` (`dispute_resolver`, `reputation_sync`) are not exposed via
HTTP and only mutate worker-local state. The `ReportOutcomeRequest.reporter_did` body field is
admin-supplied metadata and is **not** verified against the caller's principal; downstream
consumers must not trust it for authorization.

Escrow release is authorized per outcome:

- `outcome=success` — requester (or admin) only. The requester is acknowledging delivery
  and authorizing payment to the provider.
- `outcome=failure` — provider (or admin) only. The provider is acknowledging non-delivery
  and authorizing refund to the requester. A requester who believes the provider failed
  must raise a dispute rather than unilaterally clawing back credits.
- `outcome=dispute` — either escrow participant (or admin).

Submitting a dispute via `POST /v1/disputes` atomically transitions the escrow to
`disputed`, blocking further releases until the arbiter rules. Arbiter resolution
(`POST /v1/disputes/{id}/resolve`) requires an admin-supplied `outcome`
(`requester_wins`, `provider_wins`, `split`); the disputant's `claimed_outcome` is
never used to decide the winner. The arbiter disburses the escrow's actual locked
credits and emits a `dispute_resolved` compliance event. The reputation deltas
surfaced on the resolution response remain **advisory** in this demo — they are
not yet wired into `reputation._reputation_history`.

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
| `NEXUS_CLOUD_BOARD_ADMIN_TOKENS` | Comma-separated administrator bearer tokens | (required for admin endpoints) |
| `NEXUS_CLOUD_BOARD_AGENT_TOKENS` | Comma-separated `<did>=<token>` agent bearer tokens | (required for agent-scoped endpoints) |
| `NEXUS_HOST` | Local bind host for `python -m api.main` | 127.0.0.1 |

## License

MIT License - See [LICENSE](../../LICENSE)
