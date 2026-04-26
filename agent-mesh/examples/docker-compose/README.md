# AgentMesh — Docker Compose Multi-Agent Example

A self-contained, multi-container deployment of AgentMesh with two sample
agents, Redis for state/pub-sub, and a full observability stack (Prometheus +
Grafana).

## Architecture

```
┌─────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  Researcher │◄────►│   Mesh Server   │◄────►│     Writer      │
│   Agent     │      │ (trust registry │      │     Agent       │
│  :8081      │      │  + identity)    │      │    :8082        │
└──────┬──────┘      │    :8080        │      └──────┬──────────┘
       │             └────────┬────────┘             │
       │                      │                      │
       └──────────┬───────────┘──────────────────────┘
                  │
           ┌──────▼──────┐
           │    Redis     │
           │   :6379      │
           └──────────────┘

       ┌──────────────┐     ┌──────────────┐
       │  Prometheus  │────►│   Grafana    │
       │  :9093       │     │   :3000      │
       └──────────────┘     └──────────────┘
```

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) ≥ 24.0
- [Docker Compose](https://docs.docker.com/compose/) ≥ 2.20

## Quick Start

```bash
# Start everything
docker compose up -d

# Verify services are healthy
docker compose ps

# Check mesh server health
curl http://localhost:8080/health
```

## Service Endpoints

| Service            | URL                        | Description               |
| ------------------ | -------------------------- | ------------------------- |
| Mesh Server API    | http://localhost:8080       | Trust registry & identity |
| Researcher Agent   | http://localhost:8081       | Sidecar proxy             |
| Writer Agent       | http://localhost:8082       | Sidecar proxy             |
| Prometheus         | http://localhost:9093       | Metrics UI                |
| Grafana            | http://localhost:3000       | Dashboards (admin/agentmesh) |

## Registering Agents

Agents register automatically on startup. To manually register an agent:

```bash
curl -X POST http://localhost:8080/agents/register \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "custom-agent-01",
    "name": "Custom Agent",
    "capabilities": ["analyze", "report"],
    "endpoint": "http://host.docker.internal:9000"
  }'
```

## Viewing Trust Scores

```bash
# All trust scores
curl http://localhost:8080/trust/scores

# Single agent
curl http://localhost:8080/agents/researcher-agent-01/trust

# List registered agents
curl http://localhost:8080/agents
```

## Submitting Tasks

Submit a task to an agent through the mesh server (trust is validated):

```bash
curl -X POST http://localhost:8080/agents/researcher-agent-01/task \
  -H "Content-Type: application/json" \
  -d '{"description": "Summarize recent news on AI governance"}'
```

Each successful task increases the agent's trust score.

## Viewing Grafana Dashboards

1. Open http://localhost:3000
2. Log in with **admin** / **agentmesh**
3. The **AgentMesh — Trust Metrics** dashboard is pre-provisioned and shows:
   - Registered agent count
   - Average and per-agent trust scores
   - Task completion rates
   - Handshake latency (p50/p95)
   - Policy violations
   - Agent heartbeat freshness

## Metrics (Prometheus)

Raw Prometheus metrics are available at:

- Mesh server: http://localhost:9090/metrics
- Researcher agent: http://localhost:9091/metrics
- Writer agent: http://localhost:9092/metrics
- Prometheus UI: http://localhost:9093

Key metrics:

| Metric                                    | Type      | Description                |
| ----------------------------------------- | --------- | -------------------------- |
| `agentmesh_registered_agents`             | Gauge     | Total registered agents    |
| `agentmesh_trust_score`                   | Gauge     | Per-agent trust score      |
| `agentmesh_tasks_total`                   | Counter   | Tasks by agent and status  |
| `agentmesh_handshake_duration_seconds`    | Histogram | Registration latency       |
| `agentmesh_policy_violations_total`       | Counter   | Policy violations          |
| `agentmesh_agent_last_heartbeat`          | Gauge     | Last heartbeat timestamp   |

## Configuration

Mesh configuration is in [`config/mesh-config.yaml`](config/mesh-config.yaml).
Key settings:

```yaml
trust:
  default_threshold: 0.6   # minimum score for agent communication
  initial_score: 0.5       # score given to new agents
  scoring:
    successful_task: 0.05   # trust gained per task
    failed_task: -0.10      # trust lost on failure
    policy_violation: -0.25 # trust lost on violation
```

## Teardown

```bash
# Stop and remove containers
docker compose down

# Stop and remove containers + volumes (reset all data)
docker compose down -v
```

## Troubleshooting

```bash
# View logs for all services
docker compose logs -f

# View logs for a specific service
docker compose logs -f mesh-server

# Restart a single service
docker compose restart researcher-agent

# Rebuild after code changes
docker compose up -d --build
```
