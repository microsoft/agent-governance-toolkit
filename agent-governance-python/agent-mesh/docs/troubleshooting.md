# AgentMesh Troubleshooting Guide

This guide covers common issues encountered when running AgentMesh, organized by symptom → diagnosis → solution.

---

## Table of Contents

- [Handshake Failures](#handshake-failures)
- [Identity Mismatch](#identity-mismatch)
- [Scope Chain Errors](#scope-chain-errors)
- [Trust Score Issues](#trust-score-issues)
- [Proxy Connection Problems](#proxy-connection-problems)
- [Performance Issues](#performance-issues)
- [Getting Help](#getting-help)

---

## Handshake Failures

### Symptoms

- `HandshakeError` raised during trust establishment
- `HandshakeTimeoutError` after 30 seconds (default timeout)
- Connection drops during the handshake protocol exchange

### Common Causes

| Cause | Details |
|-------|---------|
| **Network connectivity** | Firewall rules blocking ports 8080 (API) or 8081 (sidecar proxy) |
| **Clock skew** | Timestamps in handshake messages differ by more than the allowed tolerance |
| **Expired credentials** | Agent identity keys or certificates have expired |
| **Protocol version mismatch** | Agents running different AgentMesh versions with incompatible handshake protocols |

### Diagnosis Steps

**1. Check agent logs for the specific error:**

```bash
# If running in Kubernetes
kubectl logs <pod-name> -n agentmesh | grep -i "handshake"

# If running locally
agentmesh logs --level DEBUG 2>&1 | grep -i "handshake"
```

**2. Verify DID format is correct:**

The DID must follow the `did:mesh:<hex>` format derived from the agent's Ed25519 public key.

```python
from agentmesh.identity import AgentIdentity

identity = AgentIdentity(name="my-agent")
print(identity.did)  # Should print did:mesh:<64-char-hex>
```

**3. Test network connectivity between agents:**

```bash
# Check if the target agent's API is reachable
curl -v http://<agent-host>:8080/health

# Check proxy endpoint
curl -v http://<agent-host>:8081/health
```

**4. Verify clock synchronization:**

```bash
# Compare timestamps across nodes
date -u
# Ensure NTP is running
timedatectl status
```

### Solutions

- **Network issues:** Ensure ports 8080 and 8081 are open between agents. In Kubernetes, verify NetworkPolicy allows inter-pod communication.
- **Clock skew:** Enable NTP synchronization on all nodes. In Kubernetes, the node clock is shared so pod-level skew is rare.
- **Expired credentials:** Regenerate the agent identity and re-establish trust relationships.
- **Version mismatch:** Upgrade all agents to the same AgentMesh version. Check with `agentmesh --version`.

---

## Identity Mismatch

### Symptoms

- `IdentityError` raised during agent verification
- DID verification fails when validating signatures
- Trust handshake rejected with "identity mismatch" message

### Common Causes

| Cause | Details |
|-------|---------|
| **Key rotation mid-handshake** | Agent keys were rotated while a handshake was in progress |
| **Wrong DID format** | DID does not match the expected `did:mesh:<hex>` derivation from the public key |
| **Corrupted key material** | Private key file is damaged or the key pair is inconsistent |
| **Stale identity cache** | Cached identity data does not match the agent's current keys |

### Diagnosis Steps

**1. Verify the key pair is consistent:**

```python
from agentmesh.identity import AgentIdentity

identity = AgentIdentity(name="my-agent")

# Sign and verify round-trip
message = b"test message"
signature = identity.sign(message)
is_valid = identity.verify(message, signature)
print(f"Key pair valid: {is_valid}")  # Must be True
```

**2. Check DID derivation from the public key:**

```python
from agentmesh.identity import AgentDID

# DID should be deterministically derived from the public key
did = AgentDID.from_public_key(identity.public_key)
print(f"Expected DID: {did}")
print(f"Agent DID:    {identity.did}")
assert str(did) == str(identity.did), "DID mismatch!"
```

**3. Inspect the exported identity:**

```python
# Export identity (never includes private key)
exported = identity.export()
print(exported)
# Verify the exported DID and public key match
```

### Solutions

- **Key rotation:** Ensure all peers are notified of key rotation before it takes effect. Complete in-flight handshakes first.
- **Wrong DID format:** Regenerate the DID from the current public key using `AgentDID.from_public_key()`.
- **Corrupted keys:** Delete the key material and regenerate the agent identity. Re-establish trust with all peers.
- **Stale cache:** Clear the Redis cache (`FLUSHDB` on the AgentMesh Redis instance) or restart the agent with `--clear-cache`.

---

## Scope Chain Errors

### Symptoms

- `DelegationError` when creating or verifying scope chains
- `DelegationDepthError` when the chain exceeds the maximum allowed depth
- Delegation verification fails despite apparently valid chains

### Common Causes

| Cause | Details |
|-------|---------|
| **Expired delegation** | A delegation token in the chain has passed its expiry time |
| **Depth exceeded** | Chain depth exceeds the maximum of 5 (`DEFAULT_DELEGATION_MAX_DEPTH`) |
| **Broken chain** | An intermediate link's signature does not verify against the parent |
| **Revoked delegator** | An agent in the chain has been revoked or has a trust score below threshold |
| **Capability narrowing violation** | A delegation attempts to grant capabilities broader than its parent |

### Diagnosis Steps

**1. Inspect the scope chain:**

```python
from agentmesh.trust import ScopeChain

chain = ScopeChain.load("chain_id")

# Print each link in the chain
for i, link in enumerate(chain.links):
    print(f"Link {i}: delegator={link.delegator_did}, "
          f"delegate={link.delegate_did}, "
          f"depth={link.depth}, "
          f"expires={link.expires_at}")
```

**2. Check current chain depth:**

```python
print(f"Chain depth: {chain.depth}")
print(f"Max allowed: 5")

if chain.depth >= 5:
    print("ERROR: Cannot add more links — max depth reached")
```

**3. Verify intermediate signatures:**

```python
# Validate the entire chain
try:
    chain.verify()
    print("Chain is valid")
except DelegationError as e:
    print(f"Chain verification failed: {e}")
```

**4. Check for revoked agents in the chain:**

```python
for link in chain.links:
    # Verify each delegator is still trusted
    score = trust_engine.get_score(link.delegator_did)
    print(f"{link.delegator_did}: score={score}")
```

### Solutions

- **Expired delegation:** Re-issue the delegation from the root delegator with a new expiry time.
- **Depth exceeded:** Restructure the delegation hierarchy to reduce depth. Consider direct delegation from a higher-level agent.
- **Broken chain:** Rebuild the chain from the last valid link. Investigate why the intermediate agent's signature is invalid.
- **Revoked delegator:** Remove the revoked agent from the chain. The root delegator must re-issue a new chain that excludes the revoked agent.
- **Capability narrowing:** Ensure each delegation only narrows (never broadens) the capabilities from its parent. Review the capability set at each level.

---

## Trust Score Issues

### Symptoms

- Unexpected trust score values (too low or not updating)
- Agent suddenly revoked or demoted to a lower trust tier
- Trust scores not decaying as expected
- Dimension scores seem misconfigured

### Trust Score Tiers

| Tier | Score Range | Meaning |
|------|-------------|---------|
| Verified Partner | ≥ 900 | Highest trust level |
| Trusted | ≥ 700 | Standard trusted agent |
| Standard | ≥ 500 | Default operating level |
| Probationary | ≥ 300 | Under observation |
| Untrusted | < 300 | Blocked from operations |

### Common Causes

| Cause | Details |
|-------|---------|
| **Trust decay** | Score decays at 2.0 points/hour without positive signals (floor at 100) |
| **Insufficient interactions** | Not enough positive interactions to maintain score |
| **Dimension weight misconfiguration** | The 5 trust dimensions are weighted incorrectly |
| **Behavioral regime shift** | KL divergence exceeded 0.5 threshold, triggering score penalty |
| **Policy violations** | Each blocked operation costs -10 points; allowed operations earn +1 |

### Diagnosis Steps

**1. Check current dimension scores:**

The five trust dimensions are:
- **Policy Compliance** — adherence to governance policies
- **Resource Efficiency** — responsible resource usage
- **Output Quality** — quality of agent outputs
- **Security Posture** — security behavior
- **Collaboration Health** — cooperation with other agents

```python
from agentmesh.trust import TrustScore

score = trust_engine.get_score(agent_did)
print(f"Overall: {score.overall}")
for dim, value in score.dimensions.items():
    print(f"  {dim}: {value}")
```

**2. Review interaction history:**

```python
# Check recent interactions and their impact on trust
history = trust_engine.get_interaction_history(agent_did, limit=50)
for event in history:
    print(f"{event.timestamp}: {event.action} -> {event.score_delta:+d}")
```

**3. Verify dimension weights:**

```python
# Weights should sum to 1.0
weights = trust_engine.get_dimension_weights()
print(f"Weights: {weights}")
print(f"Sum: {sum(weights.values())}")
```

**4. Check decay status:**

```python
# Trust decay: 2.0 points/hour, floor at 100
last_interaction = trust_engine.get_last_interaction_time(agent_did)
hours_idle = (now - last_interaction).total_seconds() / 3600
estimated_decay = min(hours_idle * 2.0, score.overall - 100)
print(f"Hours idle: {hours_idle:.1f}")
print(f"Estimated decay: {estimated_decay:.1f} points")
```

### Solutions

- **Trust decay:** Ensure agents have regular positive interactions. Consider implementing a heartbeat mechanism.
- **Insufficient interactions:** Increase the agent's activity or lower the trust threshold for its role.
- **Weight misconfiguration:** Review and adjust dimension weights in the trust engine configuration. Weights must sum to 1.0.
- **Regime shift:** Investigate the behavioral change. If the agent's behavior is legitimate, reset the baseline window.
- **Policy violations:** Review the agent's actions and adjust policies if they are too restrictive, or fix the agent's behavior.

---

## Proxy Connection Problems

### Symptoms

- `Connection refused` when agents try to communicate through the proxy
- `429 Too Many Requests` — rate limited by the proxy
- `403 Forbidden` — request rejected by the proxy

### Common Causes

| Cause | Details |
|-------|---------|
| **Proxy not running** | The AgentMesh sidecar or standalone proxy is not started |
| **Rate limits exceeded** | The agent has exceeded the allowed request rate |
| **Trust below threshold** | The agent's trust score is below the minimum for the requested operation |
| **Missing agent DID header** | The `X-Agent-DID` header is not set on the request |
| **Invalid capabilities** | The agent does not have the required capabilities for the operation |

### Diagnosis Steps

**1. Check proxy health:**

```bash
# Standalone proxy (port 8080)
curl http://localhost:8080/health

# Sidecar proxy (port 8081)
curl http://localhost:8081/health

# In Kubernetes
kubectl port-forward -n agentmesh svc/agentmesh 8080:8080
curl http://localhost:8080/health
```

**2. Inspect rate limit headers:**

```bash
curl -v http://localhost:8081/api/v1/endpoint \
  -H "X-Agent-DID: did:mesh:abc123..." \
  -H "X-Agent-Public-Key: <base64-pubkey>"

# Check response headers:
# X-RateLimit-Limit: 100
# X-RateLimit-Remaining: 0
# X-RateLimit-Reset: 1234567890
```

**3. Verify agent DID header is set:**

```bash
# All requests through the proxy must include:
curl http://localhost:8081/api/v1/endpoint \
  -H "X-Agent-DID: did:mesh:<your-agent-hex>" \
  -H "X-Agent-Public-Key: <base64-encoded-public-key>" \
  -H "X-Agent-Capabilities: read,write"
```

**4. Check the agent's trust score:**

```bash
curl http://localhost:8080/api/v1/trust/score \
  -H "X-Agent-DID: did:mesh:abc123..."
```

### Solutions

- **Proxy not running:** Start the proxy with `agentmesh proxy --policy strict --target <server>`. In Kubernetes, check the sidecar container status with `kubectl describe pod`.
- **Rate limited:** Wait for the rate limit window to reset (check `X-RateLimit-Reset` header). If limits are too low, adjust the proxy configuration.
- **Trust below threshold:** Improve the agent's trust score through positive interactions. If the agent is legitimate, review and adjust trust thresholds.
- **Missing headers:** Ensure every request includes `X-Agent-DID` and `X-Agent-Public-Key` headers.
- **Invalid capabilities:** Verify the agent's capabilities match what is required. Update the agent's capability set or scope chain.

---

## Performance Issues

### Symptoms

- Slow handshakes (> 5 seconds for trust establishment)
- High latency on proxied requests (> 100ms overhead)
- Memory usage growing over time
- CPU spikes during trust operations

### Common Causes

| Cause | Details |
|-------|---------|
| **Large revocation lists** | Checking revocation status against a large list is slow |
| **Missing Redis cache** | Trust scores and identity data re-computed on every request |
| **Excessive delegation depth** | Deep chains (approaching the max of 5) require more signature verifications |
| **Unoptimized policy evaluation** | Complex policy rules with many conditions |
| **No connection pooling** | Creating new connections for each inter-agent request |

### Diagnosis Steps

**1. Measure handshake duration:**

```python
import time
from agentmesh.trust import TrustHandshake

start = time.monotonic()
result = await handshake.establish(target_did)
duration = time.monotonic() - start
print(f"Handshake took {duration:.3f}s")
```

**2. Check Prometheus metrics:**

```bash
# Port-forward to metrics endpoint
kubectl port-forward -n agentmesh svc/agentmesh 9090:9090

# Key performance metrics
curl -s http://localhost:9090/metrics | grep agentmesh_api_request_duration
curl -s http://localhost:9090/metrics | grep agentmesh_handshake_total
```

**3. Verify Redis cache is running and connected:**

```bash
# In Kubernetes
kubectl exec -it -n agentmesh <agentmesh-pod> -- \
  redis-cli -h agentmesh-redis-master ping
# Expected: PONG

# Check cache hit rate
redis-cli -h agentmesh-redis-master INFO stats | grep keyspace
```

**4. Profile scope chain verification:**

```python
import time

start = time.monotonic()
chain.verify()
duration = time.monotonic() - start
print(f"Chain verification ({chain.depth} links): {duration:.3f}s")
```

### Solutions

- **Large revocation lists:** Use a Bloom filter or Redis set for revocation checks. Consider partitioning revocation lists by time window.
- **Missing Redis cache:** Deploy Redis and enable caching in the configuration:
  ```yaml
  storage:
    backend: redis
    cacheEnabled: true
    cacheTTL: 300
  ```
- **Excessive delegation depth:** Flatten the delegation hierarchy where possible. The maximum depth is 5 for security, but shallower chains are faster.
- **Policy evaluation:** Simplify policy rules. Use high-priority deny rules to short-circuit evaluation. Target < 5ms per evaluation.
- **Connection pooling:** Enable connection pooling in the proxy configuration to reuse TCP connections between agents.

---

## Getting Help

If your issue is not covered here:

1. **Search existing issues:** [github.com/microsoft/agent-governance-toolkit/issues](https://github.com/microsoft/agent-governance-toolkit/issues)
2. **Enable debug logging:** Set `AGENTMESH_LOG_LEVEL=DEBUG` or configure `observability.logs.level: DEBUG` in your deployment
3. **Collect diagnostics:**
   ```bash
   # Kubernetes
   kubectl get pods -n agentmesh -o wide
   kubectl describe pod <pod-name> -n agentmesh
   kubectl logs <pod-name> -n agentmesh --tail=100

   # Local
   agentmesh --version
   agentmesh health
   ```
4. **Open an issue:** Include the error message, AgentMesh version, deployment mode (standalone/sidecar/Kubernetes), and relevant logs
