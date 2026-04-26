# Scaling Guide

How to scale the Agent Governance stack from a handful of agents to thousands.

---

## Horizontal Scaling

The Agent OS governance API is stateless — all state lives in the audit store (Postgres) and policy configuration (ConfigMaps or API). This means you can scale horizontally by adding replicas behind a load balancer with no session affinity required.

```bash
# Scale the governance API
kubectl scale deployment agent-os --replicas=5 -n agent-governance

# Or use a HorizontalPodAutoscaler
kubectl apply -f - <<EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: agent-os-hpa
  namespace: agent-governance
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: agent-os
  minReplicas: 2
  maxReplicas: 20
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
EOF
```

### What Scales Independently

| Component | Stateless? | Scale Strategy |
|-----------|-----------|----------------|
| Agent OS API | Yes | Horizontal replicas + HPA |
| AgentMesh Gateway | Yes | Horizontal replicas per BU |
| Agent Runtime | Stateful (agent sessions) | Scale with agent count; sticky sessions |
| Agent SRE | Yes | Single replica per cluster usually sufficient |
| Audit Store (Postgres) | Stateful | Vertical scaling or read replicas |

---

## Metrics to Watch

Monitor these metrics to know when to scale and to detect performance degradation:

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `governance_requests_per_second` | Total request throughput | >80% of benchmarked capacity |
| `governance_p99_latency_ms` | 99th percentile response time | >50ms |
| `governance_detection_rate` | Prompt injection detection accuracy | <99% |
| `governance_policy_eval_time_ms` | Time to evaluate a policy decision | >10ms |
| `governance_audit_write_latency_ms` | Time to persist audit record | >20ms |
| `governance_active_agents` | Number of connected agents | Approaching licensed/capacity limit |
| `governance_error_rate` | 5xx responses / total requests | >0.1% |

### Grafana Dashboard Query Examples

```promql
# Request throughput
rate(governance_requests_total[5m])

# p99 latency
histogram_quantile(0.99, rate(governance_request_duration_seconds_bucket[5m]))

# Error rate
rate(governance_requests_total{status=~"5.."}[5m]) / rate(governance_requests_total[5m])
```

---

## Benchmarks

Synthetic benchmarks on a standard Kubernetes cluster (8-core nodes, 32GB RAM). Results will vary based on policy complexity and payload size.

| Agents | Replicas | Requests/sec | p99 Latency | Memory/Pod |
|--------|----------|-------------|-------------|------------|
| 10 | 1 | 500 | 12ms | 256MB |
| 50 | 3 | 2,500 | 18ms | 512MB |
| 200 | 5 | 10,000 | 25ms | 1GB |
| 1000 | 10 | 50,000 | 35ms | 2GB |

**Methodology:** Each agent sends 50 requests/sec with a mixed workload (60% policy evaluation, 25% prompt injection detection, 15% audit writes). Measured with k6 over a 10-minute sustained run.

> **Note:** These are approximate benchmarks for capacity planning. Run your own load tests with your specific policies and payloads to get accurate numbers for your deployment.

---

## Resource Sizing by Tier

### Starter (≤20 agents)

For teams getting started. Minimal infrastructure footprint.

| Component | Replicas | CPU Request | Memory Request | Storage |
|-----------|----------|-------------|----------------|---------|
| Agent OS | 1 | 250m | 256Mi | — |
| AgentMesh | 1 | 100m | 128Mi | — |
| Agent Runtime | 1 | 250m | 256Mi | — |
| Agent SRE | 1 | 100m | 128Mi | — |
| Postgres | 1 | 250m | 512Mi | 10Gi |
| **Total** | **5 pods** | **950m** | **1.3Gi** | **10Gi** |

### Growth (≤200 agents)

For multiple teams with centralized governance.

| Component | Replicas | CPU Request | Memory Request | Storage |
|-----------|----------|-------------|----------------|---------|
| Agent OS | 3 | 500m | 512Mi | — |
| AgentMesh | 2 | 250m | 256Mi | — |
| Agent Runtime | 2 | 500m | 512Mi | — |
| Agent SRE | 1 | 250m | 256Mi | — |
| Postgres | 2 (primary + replica) | 1 | 2Gi | 100Gi |
| **Total** | **10 pods** | **4.25** | **5.8Gi** | **100Gi** |

### Enterprise (200+ agents)

For large organizations with federated governance.

| Component | Replicas | CPU Request | Memory Request | Storage |
|-----------|----------|-------------|----------------|---------|
| Agent OS | 5–10 | 1 | 1Gi | — |
| AgentMesh | 3–5 | 500m | 512Mi | — |
| Agent Runtime | 3–5 | 1 | 1Gi | — |
| Agent SRE | 2 | 500m | 512Mi | — |
| Postgres | 3 (primary + 2 replicas) | 2 | 4Gi | 500Gi |
| **Total** | **16–25 pods** | **14–22** | **16–26Gi** | **500Gi** |

---

## Database Recommendations for Audit Logs at Scale

The audit store is the primary bottleneck at scale. Choose your database based on query patterns and retention requirements.

### PostgreSQL (Recommended for Most)

The default choice. Use table partitioning for large audit tables and create indexes on `agent_id`, `timestamp`, and `action_type`.

```sql
-- Partition by month for efficient retention management
CREATE TABLE audit_log (
    id UUID DEFAULT gen_random_uuid(),
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB
) PARTITION BY RANGE (timestamp);

-- Create monthly partitions
CREATE TABLE audit_log_2025_01 PARTITION OF audit_log
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

-- Drop old partitions for retention (faster than DELETE)
DROP TABLE audit_log_2024_01;
```

### TimescaleDB (For High-Volume Time-Series Queries)

If you need fast time-range queries over audit data (e.g., "show all injection attempts in the last hour"), TimescaleDB provides automatic partitioning and compression.

```sql
-- Convert audit_log to a TimescaleDB hypertable
SELECT create_hypertable('audit_log', 'timestamp');

-- Enable compression for older data
ALTER TABLE audit_log SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'agent_id'
);
SELECT add_compression_policy('audit_log', INTERVAL '7 days');

-- Automatic retention
SELECT add_retention_policy('audit_log', INTERVAL '90 days');
```

### Sizing Estimates

| Agents | Events/Day | Storage/Month | Recommendation |
|--------|-----------|---------------|----------------|
| 10 | ~50K | ~500MB | Single Postgres |
| 50 | ~250K | ~2.5GB | Postgres with partitioning |
| 200 | ~1M | ~10GB | Postgres with read replicas |
| 1000 | ~5M | ~50GB | TimescaleDB with compression |

---

## Caching

Policy evaluation results are deterministic for a given input — the same agent, action, and context will always produce the same policy decision (until policies change). Cache evaluation results to reduce load on the governance API.

```yaml
# Agent OS caching configuration
cache:
  enabled: true
  type: in-memory  # or "redis" for shared cache across replicas
  policyEvaluation:
    ttl: 300s        # 5 minutes — invalidate when policies change
    maxEntries: 10000
  injectionDetection:
    ttl: 60s         # Shorter TTL for detection results
    maxEntries: 5000
```

**Cache invalidation strategy:**
- Policy evaluation cache is invalidated when policies are updated (publish/subscribe via ConfigMap watch or Redis pub/sub)
- Injection detection cache uses a shorter TTL because detection models may be updated more frequently
- Cache hit rates >90% are typical for stable policy sets

```bash
# Monitor cache performance
curl http://governance.internal:8080/metrics | grep governance_cache
# governance_cache_hit_total 45230
# governance_cache_miss_total 4980
# governance_cache_hit_rate 0.901
```

---

## Rate Limiting

Apply per-agent rate limits to prevent a single noisy agent from consuming all governance API capacity. This protects the system from both misbehaving agents and denial-of-service conditions.

```yaml
# Agent OS rate limiting configuration
rateLimiting:
  enabled: true
  defaultLimits:
    requestsPerSecond: 100
    burstSize: 200
  perAgent:
    # Override for specific high-traffic agents
    "batch-processor-agent":
      requestsPerSecond: 500
      burstSize: 1000
  response:
    statusCode: 429
    retryAfterSeconds: 5
```

**Rate limiting strategy by tier:**

| Tier | Default RPS/Agent | Burst | Notes |
|------|-------------------|-------|-------|
| Starter | 50 | 100 | Generous for development |
| Growth | 100 | 200 | Standard production limit |
| Enterprise | 200 | 500 | Higher base, per-agent overrides |

**What to do when agents are rate limited:**
1. Check if the agent genuinely needs higher throughput (increase its limit)
2. Implement client-side caching in the agent to reduce redundant governance calls
3. Batch multiple policy evaluations into a single request (batch API)

---

## Scaling Checklist

Before scaling, verify these items:

- [ ] HorizontalPodAutoscaler configured with appropriate thresholds
- [ ] Database connection pooling enabled (PgBouncer or built-in)
- [ ] Policy evaluation caching enabled
- [ ] Rate limiting configured per agent
- [ ] Monitoring dashboards showing all key metrics
- [ ] Load test completed at 2× expected peak traffic
- [ ] Audit log partitioning/compression configured
- [ ] Network policies updated for new replica counts

---

*Part of the [Enterprise Deployment Guide](README.md)*
