# CloudEvents Audit Log Schema

AgentMesh audit logs follow the [CloudEvents v1.0](https://cloudevents.io/) specification for interoperability with enterprise event systems.

## Overview

CloudEvents is a specification for describing event data in a common way. By adopting CloudEvents, AgentMesh audit logs can be natively ingested by:

- **Azure Event Grid**
- **AWS EventBridge**
- **Google Cloud Eventarc**
- **Apache Kafka**
- **Splunk**
- **Datadog**
- **Any CloudEvents-compatible system**

## Event Types

| Event Type | Description |
|------------|-------------|
| `ai.agentmesh.agent.registered` | New agent registered |
| `ai.agentmesh.agent.verified` | Agent identity verified |
| `ai.agentmesh.policy.evaluation` | Policy was evaluated |
| `ai.agentmesh.policy.violation` | Policy violation detected |
| `ai.agentmesh.tool.invoked` | Tool was invoked |
| `ai.agentmesh.tool.blocked` | Tool invocation blocked |
| `ai.agentmesh.trust.handshake` | Trust handshake performed |
| `ai.agentmesh.trust.score.updated` | Trust score changed |
| `ai.agentmesh.audit.integrity.verified` | Audit log integrity checked |

## Schema

### Base CloudEvent Structure

```json
{
  "specversion": "1.0",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "ai.agentmesh.policy.violation",
  "source": "did:mesh:agent123",
  "time": "2026-02-03T12:00:00.000Z",
  "datacontenttype": "application/json",
  "subject": "tool:filesystem:read",
  "data": {
    // Event-specific payload
  }
}
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `specversion` | String | Always "1.0" |
| `id` | String | Unique event ID (UUID) |
| `type` | String | Event type from list above |
| `source` | URI | Agent DID or service identifier |
| `time` | Timestamp | ISO 8601 timestamp |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `subject` | String | Specific subject (tool name, resource) |
| `datacontenttype` | String | Always "application/json" |
| `dataschema` | URI | Link to JSON schema |

## Event Payloads

### Policy Violation

```json
{
  "specversion": "1.0",
  "id": "event-uuid-here",
  "type": "ai.agentmesh.policy.violation",
  "source": "did:mesh:agent-abc123",
  "time": "2026-02-03T12:00:00.000Z",
  "datacontenttype": "application/json",
  "subject": "tool:shell:execute",
  "data": {
    "trace_id": "trace-uuid-here",
    "agent_id": "agent-abc123",
    "agent_name": "CustomerServiceBot",
    "tool_name": "shell:execute",
    "tool_args": {
      "command": "rm -rf /",
      "args_hash": "sha256:abc123..."
    },
    "policy_id": "policy-no-destructive-commands",
    "policy_name": "No Destructive Commands",
    "violation_reason": "Command matches destructive pattern",
    "severity": "critical",
    "action_taken": "blocked",
    "hash_chain_proof": {
      "entry_hash": "sha256:...",
      "previous_hash": "sha256:...",
      "chain_position": 1542
    }
  }
}
```

### Tool Invoked (Success)

```json
{
  "specversion": "1.0",
  "id": "event-uuid-here",
  "type": "ai.agentmesh.tool.invoked",
  "source": "did:mesh:agent-abc123",
  "time": "2026-02-03T12:00:00.000Z",
  "subject": "tool:database:query",
  "data": {
    "trace_id": "trace-uuid-here",
    "agent_id": "agent-abc123",
    "tool_name": "database:query",
    "tool_args_hash": "sha256:...",
    "execution_time_ms": 45.2,
    "result_hash": "sha256:...",
    "policy_verdict": "allowed",
    "policies_evaluated": ["policy-read-only", "policy-no-pii"],
    "hash_chain_proof": {
      "entry_hash": "sha256:...",
      "previous_hash": "sha256:..."
    }
  }
}
```

### Trust Handshake

```json
{
  "specversion": "1.0",
  "id": "event-uuid-here",
  "type": "ai.agentmesh.trust.handshake",
  "source": "did:mesh:agent-requester",
  "time": "2026-02-03T12:00:00.000Z",
  "subject": "did:mesh:agent-provider",
  "data": {
    "requester_did": "did:mesh:agent-requester",
    "provider_did": "did:mesh:agent-provider",
    "capabilities_requested": ["database:read", "api:call"],
    "capabilities_granted": ["database:read"],
    "capabilities_denied": ["api:call"],
    "requester_trust_score": 847,
    "provider_trust_score": 920,
    "handshake_result": "partial",
    "signature": "base64:..."
  }
}
```

### Trust Score Updated

```json
{
  "specversion": "1.0",
  "id": "event-uuid-here",
  "type": "ai.agentmesh.trust.score.updated",
  "source": "did:mesh:agent-abc123",
  "time": "2026-02-03T12:00:00.000Z",
  "data": {
    "agent_did": "did:mesh:agent-abc123",
    "previous_score": 850,
    "new_score": 835,
    "change": -15,
    "reason": "policy_violation",
    "dimensions": {
      "policy_compliance": 75,
      "resource_efficiency": 90,
      "output_quality": 85,
      "security_posture": 80,
      "collaboration_health": 88
    },
    "tier_change": {
      "from": "Trusted",
      "to": "Trusted"
    }
  }
}
```

## Extension Attributes

AgentMesh defines these extension attributes:

| Attribute | Type | Description |
|-----------|------|-------------|
| `agentmeshhashchainroot` | String | Current hash chain tree root hash |
| `agentmeshtrustscope` | String | Trust scope (local, federated) |
| `agentmeshpolicyversion` | String | Policy engine version |

## JSON Schema

Full JSON Schema for validation:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://agentmesh.dev/schemas/cloudevents/v1/policy-violation.json",
  "title": "AgentMesh Policy Violation Event",
  "type": "object",
  "required": ["specversion", "id", "type", "source", "time", "data"],
  "properties": {
    "specversion": { "const": "1.0" },
    "id": { "type": "string", "format": "uuid" },
    "type": { "const": "ai.agentmesh.policy.violation" },
    "source": { "type": "string", "format": "uri" },
    "time": { "type": "string", "format": "date-time" },
    "data": {
      "type": "object",
      "required": ["trace_id", "agent_id", "tool_name", "violation_reason"],
      "properties": {
        "trace_id": { "type": "string" },
        "agent_id": { "type": "string" },
        "tool_name": { "type": "string" },
        "violation_reason": { "type": "string" },
        "severity": { "enum": ["low", "medium", "high", "critical"] }
      }
    }
  }
}
```

## Integration Examples

### Azure Event Grid

```python
from azure.eventgrid import EventGridPublisherClient
from azure.core.credentials import AzureKeyCredential

client = EventGridPublisherClient(endpoint, AzureKeyCredential(key))
client.send([cloud_event])  # AgentMesh CloudEvent
```

### AWS EventBridge

```python
import boto3

client = boto3.client('events')
client.put_events(Entries=[{
    'Source': cloud_event['source'],
    'DetailType': cloud_event['type'],
    'Detail': json.dumps(cloud_event['data']),
    'EventBusName': 'agentmesh-audit'
}])
```

### Splunk HEC

```bash
curl -X POST https://splunk:8088/services/collector/event \
  -H "Authorization: Splunk $TOKEN" \
  -d '{"event": <cloudevent-json>}'
```

## Migration from Legacy Format

If upgrading from pre-CloudEvents audit logs:

```python
def migrate_to_cloudevent(legacy_log):
    return {
        "specversion": "1.0",
        "id": legacy_log["trace_id"],
        "type": f"ai.agentmesh.tool.{legacy_log['policy_verdict']}",
        "source": f"did:mesh:{legacy_log['agent_id']}",
        "time": legacy_log["timestamp"],
        "datacontenttype": "application/json",
        "data": legacy_log
    }
```

---

*Schema Version: 1.0*
*Last Updated: February 2026*
