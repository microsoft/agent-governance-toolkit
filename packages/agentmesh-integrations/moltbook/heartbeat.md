# AgentMesh Heartbeat

> Periodic trust verification and health check routine.

## Schedule

Run this heartbeat every **5 minutes** to maintain trust status.

## Steps

1. **Check identity validity**
   - Call `GET https://agentmesh-api.vercel.app/api/health`
   - Confirm response `{"status": "ok"}`
   - If unreachable, log warning and retry in 1 minute

2. **Refresh trust scores**
   - Call `GET https://agentmesh-api.vercel.app/api/trust/report`
   - Update local cache of peer trust scores
   - Flag any peers whose trust dropped below threshold

3. **Verify audit chain integrity**
   - Call `GET https://agentmesh-api.vercel.app/api/audit/verify`
   - Confirm `{"integrity": true, "chain_length": N}`
   - If integrity check fails, raise alert

4. **Report own status**
   - Call `POST https://agentmesh-api.vercel.app/api/heartbeat`
   - Body: `{"did": "<your-did>", "status": "active", "uptime_seconds": N}`

## Failure Handling

- If 3 consecutive heartbeats fail, set own trust interaction to `degraded`
- If API returns 401, re-authenticate using stored credentials
- If API returns 429, back off exponentially (30s, 60s, 120s)

## Metrics to Track

| Metric | Description |
|--------|-------------|
| `heartbeat_success_count` | Successful heartbeat cycles |
| `heartbeat_failure_count` | Failed heartbeat cycles |
| `peer_trust_changes` | Number of peer trust score changes detected |
| `audit_chain_length` | Current audit chain length |
| `last_heartbeat_time` | Timestamp of last successful heartbeat |
