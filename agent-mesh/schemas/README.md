# AgentMesh JSON Schemas

This directory contains JSON Schema definitions for the AgentMesh registration and identity management protocol.

## Overview

These schemas provide JSON-based API contracts for systems that prefer REST/JSON over gRPC/Protocol Buffers. The schemas are functionally equivalent to the Protocol Buffer definitions in the `../proto` directory.

## Available Schemas

### registration.json

Complete JSON Schema for agent registration, including:

- **RegistrationRequest**: Agent registration request with human sponsor
- **RegistrationResponse**: Registration response with SVID and trust score
- **TrustScoreDimensions**: Breakdown of five trust dimensions
- **CredentialRotationRequest/Response**: Credential rotation for expiring credentials
- **TrustVerificationRequest/Response**: Peer trust verification

## Usage

### Validating JSON Against Schema

```python
import json
import jsonschema

# Load schema
with open("schemas/registration.json") as f:
    schema = json.load(f)

# Your registration request
request = {
    "agent_name": "my-agent",
    "public_key": "MCowBQYDK2VwAyEA...",
    "sponsor_email": "alice@company.com",
    "capabilities": ["read:data", "write:reports"]
}

# Validate
jsonschema.validate(request, schema["definitions"]["RegistrationRequest"])
```

### Example Registration Request

```json
{
  "agent_name": "data-processor-agent",
  "agent_description": "Processes customer data for analytics",
  "organization": "Acme Corp",
  "public_key": "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lP...",
  "key_algorithm": "Ed25519",
  "sponsor_email": "alice@company.com",
  "sponsor_id": "sponsor_alice_001",
  "sponsor_signature": "ZXlKaGJHY2lPaUpGWkRJMU5URTVJaX...",
  "capabilities": [
    "read:customer_data",
    "write:analytics_reports",
    "execute:sql_queries"
  ],
  "supported_protocols": ["a2a", "mcp", "iatp"],
  "requested_at": "2026-02-01T10:30:00Z"
}
```

### Example Registration Response

```json
{
  "agent_did": "did:mesh:a3f8c2e1d4b6h9k2m5n7p1q4r8s2t6u9",
  "agent_name": "data-processor-agent",
  "svid_certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t...",
  "svid_key_id": "key_a3f8c2e1",
  "svid_expires_at": "2026-02-01T10:45:00Z",
  "initial_trust_score": 500,
  "trust_dimensions": {
    "policy_compliance": 80,
    "resource_efficiency": 50,
    "output_quality": 50,
    "security_posture": 70,
    "collaboration_health": 50
  },
  "access_token": "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0...",
  "refresh_token": "refresh_a3f8c2e1d4b6h9k2m5n7p1q4r8s2t6u9",
  "token_ttl_seconds": 900,
  "registry_endpoint": "https://registry.agentmesh.io",
  "ca_certificate": "-----BEGIN CERTIFICATE-----\nMIIC...",
  "status": "success",
  "registered_at": "2026-02-01T10:30:05Z",
  "next_rotation_at": "2026-02-01T10:45:00Z"
}
```

## REST API Endpoints

When using JSON schemas, typical REST endpoints would be:

```
POST   /v1/identity/register          - Register new agent
POST   /v1/identity/rotate             - Rotate credentials
GET    /v1/identity/{did}              - Get agent identity
POST   /v1/trust/verify                - Verify peer trust
GET    /v1/trust/score/{did}           - Get trust score
```

## Field Constraints

### Agent Name
- **Type**: string
- **Min Length**: 1
- **Max Length**: 255
- **Pattern**: `^[a-z0-9-]+$` (lowercase, numbers, hyphens)

### Capabilities
- **Format**: `<action>:<resource>`
- **Example**: `read:data`, `write:reports`, `execute:queries`
- **Pattern**: `^[a-z_]+:[a-z_]+$`

### Agent DID
- **Format**: `did:mesh:<32-char-hex>`
- **Pattern**: `^did:mesh:[a-z0-9]{32}$`
- **Example**: `did:mesh:a3f8c2e1d4b6h9k2m5n7p1q4r8s2t6u9`

### Trust Score
- **Range**: 0-1000
- **Default**: 500 (new agents)
- **Thresholds**:
  - 900+: Verified Partner
  - 700-899: Trusted
  - 400-699: Standard
  - 0-399: Untrusted (may be revoked)

### Dimension Scores
- **Range**: 0-100 for each dimension
- **Dimensions**:
  1. Policy Compliance
  2. Resource Efficiency
  3. Output Quality
  4. Security Posture
  5. Collaboration Health

## Error Responses

### Registration Errors

```json
{
  "error_code": "INVALID_SPONSOR",
  "error_message": "Sponsor email not verified",
  "validation_errors": [
    "sponsor_email: alice@company.com is not a verified sponsor"
  ],
  "timestamp": "2026-02-01T10:30:05Z"
}
```

Common error codes:
- `INVALID_SPONSOR`: Sponsor not verified
- `INVALID_KEY`: Public key format invalid
- `DUPLICATE_AGENT`: Agent name already registered
- `POLICY_VIOLATION`: Registration violates policy
- `INVALID_SIGNATURE`: Sponsor signature verification failed

## Schema Versioning

Schemas follow semantic versioning:
- **Major**: Breaking changes (field removal, type changes)
- **Minor**: Additions (new optional fields)
- **Patch**: Documentation, examples

Current version: `1.0.0`

## OpenAPI Integration

To use with OpenAPI 3.0:

```yaml
openapi: 3.0.0
info:
  title: AgentMesh Identity API
  version: 1.0.0

paths:
  /v1/identity/register:
    post:
      summary: Register new agent
      requestBody:
        content:
          application/json:
            schema:
              $ref: 'schemas/registration.json#/definitions/RegistrationRequest'
      responses:
        '200':
          description: Registration successful
          content:
            application/json:
              schema:
                $ref: 'schemas/registration.json#/definitions/RegistrationResponse'
```

## Compliance

These schemas support compliance automation:

- **EU AI Act**: Capabilities provide risk classification
- **SOC 2**: Audit trails via registration metadata
- **HIPAA**: PHI handling via capability scoping
- **GDPR**: Data processing transparency

## See Also

- [Protocol Buffers](../proto/registration.proto)
- [Proto Documentation](../proto/README.md)
- [Registration Example](../examples/00-registration-hello-world/)
- [Full API Documentation](https://docs.agentmesh.io)
