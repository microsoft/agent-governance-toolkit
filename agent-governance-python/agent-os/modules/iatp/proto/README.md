# IATP Protocol Buffers

This directory contains Protocol Buffer definitions for the Inter-Agent Trust Protocol (IATP),
enabling cross-language interoperability via gRPC.

## Overview

IATP provides a standardized protocol for:
- **Trust Handshake**: Exchanging capability manifests between agents
- **Action Execution**: Executing actions with reversibility support
- **Reputation Management**: Tracking agent behavior and trust scores
- **Attestation**: Verifying agent codebase integrity

## Files

- `iatp.proto` - Main protocol definitions including:
  - Core messages (CapabilityManifest, PrivacyContract, etc.)
  - Handshake messages for trust negotiation
  - Action messages with undo support
  - Reputation tracking messages
  - gRPC service definitions

## Generating Code

### Prerequisites

Install the Protocol Buffers compiler and language-specific plugins:

```bash
# Protocol Buffers compiler
# macOS
brew install protobuf

# Ubuntu/Debian
apt-get install protobuf-compiler

# Windows (via Chocolatey)
choco install protoc
```

### Python

```bash
# Install gRPC tools
pip install grpcio-tools

# Generate Python code
python -m grpc_tools.protoc \
    -I. \
    --python_out=../iatp/generated \
    --pyi_out=../iatp/generated \
    --grpc_python_out=../iatp/generated \
    iatp.proto
```

### Node.js / TypeScript

```bash
# Install gRPC tools
npm install -g grpc-tools @grpc/proto-loader

# Generate JavaScript code
grpc_tools_node_protoc \
    --js_out=import_style=commonjs:./generated \
    --grpc_out=grpc_js:./generated \
    iatp.proto

# For TypeScript, use ts-proto
npm install ts-proto
protoc \
    --plugin=./node_modules/.bin/protoc-gen-ts_proto \
    --ts_proto_out=./generated \
    iatp.proto
```

### Go

```bash
# Install Go plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate Go code
protoc \
    --go_out=./generated \
    --go-grpc_out=./generated \
    iatp.proto
```

### Rust

```bash
# Add to Cargo.toml:
# [build-dependencies]
# tonic-build = "0.9"

# In build.rs:
# tonic_build::compile_protos("proto/iatp.proto")?;
```

### Java

```bash
# Using gradle protobuf plugin
protoc \
    --java_out=./generated \
    --grpc-java_out=./generated \
    iatp.proto
```

## Service Definitions

### TrustProtocol

The main service for agent-to-agent communication:

```protobuf
service TrustProtocol {
  // Initiate trust handshake between agents
  rpc Handshake(HandshakeRequest) returns (HandshakeResponse);
  
  // Execute an action on the remote agent
  rpc ExecuteAction(ActionRequest) returns (ActionResponse);
  
  // Undo a previous action
  rpc UndoAction(UndoRequest) returns (UndoResponse);
  
  // Health check
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}
```

### ReputationService

Service for managing agent reputations:

```protobuf
service ReputationService {
  rpc GetReputation(GetReputationRequest) returns (GetReputationResponse);
  rpc ReportEvent(ReportEventRequest) returns (ReportEventResponse);
  rpc StreamReputationUpdates(GetReputationRequest) returns (stream ReputationScore);
}
```

### AttestationService

Service for codebase verification:

```protobuf
service AttestationService {
  rpc RequestAttestation(AttestationRequest) returns (AttestationResponse);
  rpc VerifyAttestation(VerifyAttestationRequest) returns (VerifyAttestationResponse);
}
```

## Usage Example (Python)

```python
import grpc
from iatp.generated import iatp_pb2, iatp_pb2_grpc

# Create a channel to the agent
channel = grpc.insecure_channel('localhost:50051')
stub = iatp_pb2_grpc.TrustProtocolStub(channel)

# Create capability manifest
manifest = iatp_pb2.CapabilityManifest(
    agent_id="my-agent",
    trust_level=iatp_pb2.TRUST_LEVEL_STANDARD,
    capabilities=iatp_pb2.AgentCapabilities(
        idempotency=True,
        reversibility=iatp_pb2.REVERSIBILITY_LEVEL_FULL,
    ),
    privacy_contract=iatp_pb2.PrivacyContract(
        retention=iatp_pb2.RETENTION_POLICY_EPHEMERAL,
    ),
)

# Perform handshake
request = iatp_pb2.HandshakeRequest(manifest=manifest)
response = stub.Handshake(request)

if response.accepted:
    print(f"Handshake accepted! Session: {response.session_token}")
    print(f"Negotiated trust: {response.negotiated_trust}")
```

## Versioning

The protocol follows semantic versioning. Breaking changes will only occur
in major version increments. The `package iatp.v1` indicates version 1 of the protocol.

## Contributing

When modifying the protocol:

1. Update `iatp.proto` with your changes
2. Regenerate code for all supported languages
3. Update tests in each language SDK
4. Document breaking changes in CHANGELOG.md
