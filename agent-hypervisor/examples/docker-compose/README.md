# Docker Compose Example — Agent Hypervisor

Multi-container setup demonstrating the Agent Hypervisor REST API with sample
agents, Redis state storage, and an optional web dashboard.

## Services

| Service            | Port  | Description                                    |
| ------------------ | ----- | ---------------------------------------------- |
| `hypervisor-api`   | 8000  | FastAPI server with agent registration & rings  |
| `sample-agents`    | —     | Registers demo agents and runs a saga workflow  |
| `redis`            | 6379  | State storage backend                           |
| `dashboard`        | 8501  | Auto-refreshing HTML dashboard (optional)       |

## Quick Start

```bash
cd examples/docker-compose
docker compose up --build
```

The API will be available at **http://localhost:8000** and the dashboard at
**http://localhost:8501**.

## API Endpoints

| Method | Path       | Description                            |
| ------ | ---------- | -------------------------------------- |
| POST   | `/agents`  | Register an agent with execution ring  |
| GET    | `/agents`  | List agents with ring assignments      |
| POST   | `/kill`    | Emergency kill switch                  |
| GET    | `/health`  | Health check                           |
| GET    | `/audit`   | Audit log                              |

### Register an Agent

```bash
curl -X POST http://localhost:8000/agents \
  -H "Content-Type: application/json" \
  -d '{"agent_did": "did:mesh:my-agent", "sigma_raw": 0.85}'
```

### Kill Switch

```bash
curl -X POST http://localhost:8000/kill \
  -H "Content-Type: application/json" \
  -d '{"agent_did": "did:mesh:my-agent", "reason": "manual"}'
```

## Configuration

Edit `config/hypervisor.yaml` to adjust ring thresholds, session defaults, and
logging. Environment variables in `docker-compose.yml` override file settings.

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌───────┐
│   Dashboard  │────▶│  Hypervisor API   │────▶│ Redis │
│  (port 8501) │     │   (port 8000)     │     │       │
└──────────────┘     └──────────────────┘     └───────┘
                            ▲
                     ┌──────┴───────┐
                     │ Sample Agents │
                     └──────────────┘
```

## Stopping

```bash
docker compose down
```
