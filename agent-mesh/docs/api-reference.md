# AgentMesh API Reference

> Auto-generated reference for the AgentMesh public API.
> All classes use [Pydantic](https://docs.pydantic.dev/) `BaseModel` unless noted.

---

## Layer 1 — Identity (`agentmesh.identity`)

Cryptographic agent identity, credentials, delegation, and key management.

### `AgentDID`

Decentralized Identifier for an agent. Format: `did:mesh:<unique-id>`.

| Method | Signature | Description |
|--------|-----------|-------------|
| `generate` | `(name: str, org: str \| None = None) → AgentDID` | Generate a new DID for an agent. |
| `from_string` | `(did_string: str) → AgentDID` | Parse a `did:mesh:…` string. |

### `AgentIdentity`

First-class identity for an AI agent with Ed25519 cryptographic binding.

| Method | Signature | Description |
|--------|-----------|-------------|
| `create` | `(name, sponsor, capabilities?, organization?, description?) → AgentIdentity` | Factory method — generates keypair, DID, and identity. |
| `sign` | `(data: bytes) → str` | Sign data with the agent's private key (base64 result). |
| `verify_signature` | `(data: bytes, signature: str) → bool` | Verify a base64 Ed25519 signature. |
| `delegate` | `(name, capabilities, description?) → AgentIdentity` | Create a child agent with narrowed capabilities. |
| `revoke` | `(reason: str) → None` | Permanently revoke this identity. |
| `suspend` | `(reason: str) → None` | Temporarily suspend this identity. |
| `reactivate` | `() → None` | Reactivate a suspended identity. |
| `is_active` | `() → bool` | Check active status and expiration. |
| `has_capability` | `(capability: str) → bool` | Check capability (supports wildcards). |
| `to_jwk` | `(include_private: bool = False) → dict` | Export as JWK (RFC 7517). |
| `from_jwk` | `(jwk: dict) → AgentIdentity` | Import from JWK. |
| `to_jwks` | `(include_private: bool = False) → dict` | Export as JWK Set. |
| `from_jwks` | `(jwks: dict, kid?: str) → AgentIdentity` | Import from JWK Set. |
| `to_did_document` | `() → dict` | Export as W3C DID Document. |

### `IdentityRegistry`

In-memory registry for agent identities.

| Method | Signature | Description |
|--------|-----------|-------------|
| `register` | `(identity: AgentIdentity) → None` | Register an identity. |
| `get` | `(did: str \| AgentDID) → AgentIdentity \| None` | Look up by DID. |
| `revoke` | `(did: str \| AgentDID, reason: str) → bool` | Revoke identity and all delegates. |
| `get_by_sponsor` | `(sponsor_email: str) → list[AgentIdentity]` | Get all identities for a sponsor. |
| `list_active` | `() → list[AgentIdentity]` | List all active identities. |

### `Credential`

Ephemeral credential with configurable TTL (default 15 min).

| Method | Signature | Description |
|--------|-----------|-------------|
| `issue` | `(agent_did, capabilities?, resources?, ttl_seconds?, issued_for?) → Credential` | Issue a new credential. |
| `is_valid` | `() → bool` | Check validity (not expired, not revoked). |
| `is_expiring_soon` | `(threshold_seconds: int = 300) → bool` | Check if nearing expiration. |
| `verify_token` | `(token: str) → bool` | Verify a bearer token. |
| `revoke` | `(reason: str) → None` | Revoke this credential. |
| `rotate` | `() → Credential` | Create a replacement credential. |
| `has_capability` | `(capability: str) → bool` | Check if credential grants a capability. |
| `can_access_resource` | `(resource: str) → bool` | Check resource access. |
| `time_remaining` | `() → timedelta` | Time until expiration. |
| `to_bearer_token` | `() → str` | Serialize as a bearer token string. |

### `CredentialManager`

Manages credential lifecycle — issuance, validation, rotation, revocation.

| Method | Signature | Description |
|--------|-----------|-------------|
| `issue` | `(agent_did, capabilities?, resources?, ttl_seconds?, issued_for?) → Credential` | Issue a managed credential. |
| `validate` | `(token: str) → Credential \| None` | Validate a bearer token. |
| `rotate` | `(credential_id: str) → Credential \| None` | Rotate a credential. |
| `rotate_if_needed` | `(credential_id: str) → Credential` | Rotate only if expiring soon. |
| `revoke` | `(credential_id: str, reason: str) → bool` | Revoke by ID. |
| `revoke_all_for_agent` | `(agent_did: str, reason: str) → int` | Revoke all credentials for an agent. |
| `get_active_for_agent` | `(agent_did: str) → list[Credential]` | Get active credentials. |
| `cleanup_expired` | `() → int` | Remove expired credentials. |
| `on_revocation` | `(callback: Callable) → None` | Register a revocation callback. |

### `ScopeChain` / `DelegationLink`

Cryptographic scope chains that can only narrow capabilities.

| Method | Signature | Description |
|--------|-----------|-------------|
| `ScopeChain.create_root` | `(sponsor_email, root_agent_did, capabilities, sponsor_verified?) → tuple` | Create the root of a chain. |
| `ScopeChain.add_link` | `(link: DelegationLink) → None` | Append a delegation link. |
| `ScopeChain.verify` | `() → tuple[bool, str \| None]` | Verify entire chain integrity. |
| `ScopeChain.get_effective_capabilities` | `() → list[str]` | Compute narrowed capabilities. |
| `ScopeChain.trace_capability` | `(capability: str) → list[dict]` | Trace a capability through the chain. |
| `DelegationLink.verify_capability_narrowing` | `() → bool` | Verify child caps ⊆ parent caps. |
| `DelegationLink.is_valid` | `() → bool` | Check link validity. |

### `UserContext`

Represents the human user context attached to a delegation.

| Method | Signature | Description |
|--------|-----------|-------------|
| `create` | `(user_id, user_email?, roles?, permissions?, ttl_seconds?) → UserContext` | Factory method. |
| `is_valid` | `() → bool` | Check expiration. |
| `has_permission` | `(permission: str) → bool` | Check permission. |
| `has_role` | `(role: str) → bool` | Check role membership. |

### `HumanSponsor`

Human accountability link for agent identities.

| Method | Signature | Description |
|--------|-----------|-------------|
| `create` | `(email, name?, organization?, allowed_capabilities?) → HumanSponsor` | Factory method. |
| `verify` | `(method: str = "email") → None` | Mark sponsor as verified. |
| `can_sponsor_agent` | `() → bool` | Check if sponsor can create agents. |
| `can_grant_capability` | `(capability: str) → bool` | Check if capability is allowed. |
| `add_agent` / `remove_agent` | `(agent_did: str) → None` | Manage sponsored agents. |
| `suspend` / `reactivate` | `(reason?: str) → None` | Suspend or reactivate. |

### `KeyStore` (abstract), `SoftwareKeyStore`, `PKCS11KeyStore`

Pluggable cryptographic key storage backends.

| Method | Signature | Description |
|--------|-----------|-------------|
| `generate_keypair` | `(agent_id: str) → bytes` | Generate Ed25519 keypair; return raw public key. |
| `sign` | `(agent_id: str, data: bytes) → bytes` | Sign data with agent's private key. |
| `verify` | `(public_key: bytes, data: bytes, signature: bytes) → bool` | Verify an Ed25519 signature. |
| `get_public_key` | `(agent_id: str) → bytes` | Retrieve raw public key bytes. |
| `delete_key` | `(agent_id: str) → None` | Delete keypair. |

**`SoftwareKeyStore`** — In-memory Ed25519 keys (default).
**`PKCS11KeyStore(library_path, slot=0, pin=None)`** — HSM-backed via PKCS#11.

### `RiskScorer` / `RiskScore`

Continuous risk scoring for agent behavior.

| Method | Signature | Description |
|--------|-----------|-------------|
| `RiskScorer.get_score` | `(agent_did: str) → RiskScore` | Get current risk score. |
| `RiskScorer.add_signal` | `(agent_did: str, signal: RiskSignal) → None` | Add a risk signal. |
| `RiskScorer.recalculate` | `(agent_did: str) → RiskScore` | Recalculate from signals. |
| `RiskScorer.get_high_risk_agents` | `(threshold?: int) → list[RiskScore]` | Find high-risk agents. |
| `RiskScore.get_risk_level` | `(score: int) → str` | Map score to level string. |

### `SPIFFEIdentity` / `SVID`

SPIFFE/SVID workload identity integration.

| Method | Signature | Description |
|--------|-----------|-------------|
| `SPIFFEIdentity.create` | `(agent_did, agent_name, trust_domain?, organization?) → SPIFFEIdentity` | Create SPIFFE identity. |
| `SPIFFEIdentity.issue_svid` | `(ttl_hours?, svid_type?) → SVID` | Issue a new SVID. |
| `SPIFFEIdentity.get_valid_svid` | `() → SVID \| None` | Get current valid SVID. |
| `SVID.is_valid` | `() → bool` | Check SVID validity. |

### `RevocationList`

Manages revoked agent identities.

| Method | Signature | Description |
|--------|-----------|-------------|
| `revoke` | `(agent_did, reason, revoked_by?, ttl_seconds?) → RevocationEntry` | Revoke an agent. |
| `unrevoke` | `(agent_did: str) → bool` | Remove from revocation list. |
| `is_revoked` | `(agent_did: str) → bool` | Check revocation status. |
| `save` / `load` | `(path: str) → None` | Persist to / load from file. |

### `KeyRotationManager`

Ed25519 key rotation with cryptographic continuity proofs.

| Method | Signature | Description |
|--------|-----------|-------------|
| `rotate` | `() → AgentIdentity` | Rotate keys and return updated identity. |
| `needs_rotation` | `() → bool` | Check if rotation is due. |
| `get_rotation_proof` | `() → dict` | Get proof linking old → new key. |
| `verify_rotation` | `(old_pk, new_pk, proof) → bool` | Verify a rotation proof (static). |

### `NamespaceManager`

Manages agent communication namespaces and cross-namespace rules.

| Method | Signature | Description |
|--------|-----------|-------------|
| `create_namespace` | `(name, description, parent?) → AgentNamespace` | Create a namespace. |
| `add_member` / `remove_member` | `(namespace_name, agent_did) → None` | Manage members. |
| `can_communicate` | `(from_did, to_did) → bool` | Check if two agents can communicate. |
| `can_delegate` | `(from_did, to_did) → bool` | Check cross-namespace delegation. |

### `MTLSIdentityVerifier`

Mutual TLS identity verification for agent connections.

| Method | Signature | Description |
|--------|-----------|-------------|
| `create_self_signed_cert` | `() → tuple[bytes, bytes]` | Generate self-signed cert + key. |
| `create_ssl_context` | `(server_side: bool = False) → ssl.SSLContext` | Create configured SSL context. |
| `verify_peer_certificate` | `(cert_pem: bytes) → dict` | Verify and extract peer cert info. |
| `extract_did_from_cert` | `(cert_pem: bytes) → str \| None` | Extract DID from certificate SAN. |

### JWK Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `to_jwk` | `(identity, include_private?) → dict` | Export identity as JWK. |
| `from_jwk` | `(jwk: dict) → AgentIdentity` | Import identity from JWK. |
| `to_jwks` | `(identity, include_private?) → dict` | Export as JWK Set. |
| `from_jwks` | `(jwks: dict, kid?: str) → AgentIdentity` | Import from JWK Set. |

---

## Layer 2 — Trust (`agentmesh.trust`)

Trust scoring, protocol bridges, capabilities, and agent cards.

### `TrustBridge`

Manages peer trust relationships and handshake verification.

| Method | Signature | Description |
|--------|-----------|-------------|
| `verify_peer` | `(peer_did, protocol?, required_trust_score?, required_capabilities?) → HandshakeResult` | Verify and establish trust with a peer. |
| `is_peer_trusted` | `(peer_did, required_score?) → bool` | Check if a peer is trusted. |
| `get_peer` | `(peer_did: str) → PeerInfo \| None` | Get peer information. |
| `get_trusted_peers` | `(min_score?: int) → list[PeerInfo]` | List trusted peers. |
| `revoke_peer_trust` | `(peer_did, reason) → bool` | Revoke trust for a peer. |

### `ProtocolBridge`

Translates messages between A2A, MCP, and IATP protocols.

| Method | Signature | Description |
|--------|-----------|-------------|
| `send_message` | `(peer_did, message, source_protocol, target_protocol?) → Any` | Send cross-protocol message. |
| `add_verification_footer` | `(content, trust_score, agent_did, metadata?) → str` | Append trust verification footer. |
| `get_protocol_for_peer` | `(peer_did: str) → str \| None` | Get preferred protocol for a peer. |

### `TrustHandshake`

Implements the IATP trust handshake protocol.

| Method | Signature | Description |
|--------|-----------|-------------|
| `initiate` | `(peer_did, protocol?, required_trust_score?, required_capabilities?, use_cache?) → HandshakeResult` | Initiate async handshake. |
| `respond` | `(challenge, my_capabilities, my_trust_score, private_key?, identity?, user_context?) → HandshakeResponse` | Respond to a challenge. |
| `create_challenge` | `() → HandshakeChallenge` | Create a new challenge. |
| `validate_challenge` | `(challenge_id: str) → bool` | Validate a pending challenge. |
| `clear_cache` | `() → None` | Clear handshake result cache. |

### `HandshakeResult`

Result of a trust handshake.

| Method | Signature | Description |
|--------|-----------|-------------|
| `success` | `(peer_did, trust_score, capabilities, …) → HandshakeResult` | Create a successful result. |
| `failure` | `(peer_did, reason, …) → HandshakeResult` | Create a failure result. |

### `CapabilityScope` / `CapabilityGrant`

Fine-grained capability management with `action:resource:instance` format.

| Method | Signature | Description |
|--------|-----------|-------------|
| `CapabilityGrant.create` | `(capability, granted_to, granted_by, resource_ids?, expires_at?) → CapabilityGrant` | Create a grant. |
| `CapabilityGrant.is_valid` | `() → bool` | Check validity. |
| `CapabilityGrant.matches` | `(requested, resource_id?) → bool` | Check if grant covers a request. |
| `CapabilityScope.add_grant` | `(grant: CapabilityGrant) → None` | Add a grant to scope. |
| `CapabilityScope.has_capability` | `(capability, resource_id?) → bool` | Check capability in scope. |
| `CapabilityScope.filter_capabilities` | `(requested: list[str]) → list[str]` | Filter to granted capabilities. |
| `CapabilityScope.revoke_all` | `() → int` | Revoke all grants. |

### `CapabilityRegistry`

Global registry for capability grants across agents.

| Method | Signature | Description |
|--------|-----------|-------------|
| `grant` | `(capability, to_agent, from_agent, resource_ids?) → CapabilityGrant` | Grant a capability. |
| `check` | `(agent_did, capability, resource_id?) → bool` | Check if agent has capability. |
| `revoke_all_from` | `(grantor_did: str) → int` | Revoke all grants from a grantor. |

### `TrustedAgentCard` / `CardRegistry`

Signed agent cards for discovery and verification.

| Method | Signature | Description |
|--------|-----------|-------------|
| `TrustedAgentCard.from_identity` | `(identity: AgentIdentity) → TrustedAgentCard` | Create card from identity. |
| `TrustedAgentCard.sign` | `(identity: AgentIdentity) → None` | Sign the card. |
| `TrustedAgentCard.verify_signature` | `(identity?: AgentIdentity) → bool` | Verify card signature. |
| `CardRegistry.register` | `(card: TrustedAgentCard) → bool` | Register a card. |
| `CardRegistry.get` | `(agent_did: str) → TrustedAgentCard \| None` | Look up a card. |
| `CardRegistry.find_by_capability` | `(capability: str) → list[TrustedAgentCard]` | Find cards by capability. |

---

## Layer 3 — Governance (`agentmesh.governance`)

Policy enforcement, compliance mapping, and tamper-evident audit.

### `PolicyEngine`

Declarative policy engine supporting YAML, JSON, and Rego policies.

| Method | Signature | Description |
|--------|-----------|-------------|
| `load_policy` | `(policy: Policy) → None` | Load a policy into the engine. |
| `load_yaml` | `(yaml_content: str) → Policy` | Load from YAML string. |
| `load_json` | `(json_content: str) → Policy` | Load from JSON string. |
| `load_rego` | `(rego_path?, rego_content?, package?) → OPAEvaluator` | Load OPA Rego policy. |
| `evaluate` | `(agent_did: str, context: dict) → PolicyDecision` | Evaluate all policies. |
| `get_policy` | `(name: str) → Policy \| None` | Get policy by name. |
| `list_policies` | `() → list[str]` | List loaded policy names. |
| `remove_policy` | `(name: str) → bool` | Remove a policy. |

### `Policy` / `PolicyRule`

Individual policy definitions with YAML/JSON serialization.

| Method | Signature | Description |
|--------|-----------|-------------|
| `Policy.from_yaml` | `(yaml_content: str) → Policy` | Parse from YAML. |
| `Policy.from_json` | `(json_content: str) → Policy` | Parse from JSON. |
| `Policy.applies_to` | `(agent_did: str) → bool` | Check if policy applies. |
| `Policy.to_yaml` | `() → str` | Serialize to YAML. |
| `PolicyRule.evaluate` | `(context: dict) → bool` | Evaluate a single rule. |

### `ComplianceEngine`

Automated compliance mapping for SOC 2, HIPAA, EU AI Act, and NIST.

| Method | Signature | Description |
|--------|-----------|-------------|
| `map_action` | `(action_type: str) → ComplianceMapping \| None` | Map action to controls. |
| `check_compliance` | `(agent_did, action_type, context) → list[ComplianceViolation]` | Check for violations. |
| `generate_report` | `(framework, period_start, period_end, agent_ids?) → ComplianceReport` | Generate compliance report. |
| `remediate_violation` | `(violation_id, notes) → bool` | Mark violation as remediated. |
| `get_violations` | `(framework?, agent_did?, remediated?) → list[ComplianceViolation]` | Query violations. |

### `AuditLog` / `HashChainAuditLog`

Tamper-evident audit logging with hash-chain integrity.

| Method | Signature | Description |
|--------|-----------|-------------|
| `AuditLog.log` | `(event_type, agent_did, action, resource?, data?, outcome?, …) → AuditEntry` | Log an audit entry. |
| `AuditLog.query` | `(agent_did?, event_type?, start_time?, end_time?, outcome?, limit?) → list[AuditEntry]` | Query entries. |
| `AuditLog.verify_integrity` | `() → tuple[bool, str \| None]` | Verify hash chain integrity. |
| `AuditLog.export_cloudevents` | `(start_time?, end_time?) → list[dict]` | Export as CloudEvents. |
| `HashChainAuditLog.add_entry` | `(entry: AuditEntry) → None` | Add entry to chain. |
| `HashChainAuditLog.get_proof` | `(entry_id: str) → list[tuple] \| None` | Get hash chain proof. |
| `HashChainAuditLog.verify_chain` | `() → tuple[bool, str \| None]` | Verify full chain. |

### `PersistentAuditLog`

Async file-backed audit log with hash chain integrity.

| Method | Signature | Description |
|--------|-----------|-------------|
| `append` | `(event_type, agent_did, action, …) → AuditEntry` | Append entry (async). |
| `load` | `() → int` | Load entries from storage (async). |
| `verify_integrity` | `() → tuple[bool, str \| None]` | Verify in-memory chain (async). |
| `verify_against_storage` | `() → tuple[bool, str \| None]` | Verify against persisted data (async). |

### `ShadowMode`

Shadow/dry-run policy evaluation for safe policy rollout.

| Method | Signature | Description |
|--------|-----------|-------------|
| `start_session` | `(agent_dids?, policy_names?) → ShadowSession` | Start a shadow session. |
| `evaluate` | `(action, production_decision?) → ShadowResult` | Evaluate action in shadow mode. |
| `replay_batch` | `(actions, production_decisions?) → list[ShadowResult]` | Batch replay. |
| `end_session` | `(session_id?) → ShadowSession` | End a session. |
| `get_divergence_report` | `(session_id?) → dict` | Get divergence statistics. |
| `is_ready_for_production` | `(session_id?) → bool` | Check if policy is production-ready. |

### `OPAEvaluator`

Open Policy Agent (Rego) evaluator.

| Method | Signature | Description |
|--------|-----------|-------------|
| `evaluate` | `(query: str, input_data: dict) → OPADecision` | Evaluate a Rego query. |

### `TrustPolicy` / `TrustRule` / `PolicyEvaluator`

Trust-specific policy definitions and evaluation.

| Method | Signature | Description |
|--------|-----------|-------------|
| `TrustPolicy.from_yaml` | `(path: str \| Path) → TrustPolicy` | Load from YAML file. |
| `TrustPolicy.to_yaml` | `(path: str \| Path) → None` | Save to YAML file. |
| `TrustCondition.evaluate` | `(context: dict) → bool` | Evaluate a condition. |
| `PolicyEvaluator.evaluate` | `(context: dict) → TrustPolicyDecision` | Evaluate trust policies. |
| `load_policies` | `(directory: str \| Path) → list[TrustPolicy]` | Load all policies from directory. |

---

## Enumerations

| Enum | Module | Values |
|------|--------|--------|
| `ComplianceFramework` | `governance.compliance` | `SOC2`, `HIPAA`, `EU_AI_ACT`, `NIST_AI_RMF` |
| `ConditionOperator` | `governance.trust_policy` | `EQUALS`, `NOT_EQUALS`, `GREATER_THAN`, `LESS_THAN`, `IN`, `NOT_IN`, `CONTAINS`, `MATCHES` |

---

## Data Models (fields only)

| Model | Module | Key Fields |
|-------|--------|------------|
| `PeerInfo` | `trust.bridge` | `did`, `name`, `protocol`, `trust_score`, `capabilities`, `verified_at` |
| `HandshakeChallenge` | `trust.handshake` | `challenge_id`, `nonce`, `timestamp`, `expires_at`, `protocol` |
| `HandshakeResponse` | `trust.handshake` | `challenge_id`, `responder_did`, `signature`, `capabilities`, `trust_score` |
| `PolicyDecision` | `governance.policy` | `allowed`, `policy_name`, `matched_rules`, `reason`, `timestamp` |
| `ComplianceViolation` | `governance.compliance` | `violation_id`, `framework`, `control_id`, `agent_did`, `severity` |
| `ComplianceReport` | `governance.compliance` | `framework`, `period_start`, `period_end`, `total_controls`, `violations` |
| `AuditEntry` | `governance.audit` | `entry_id`, `event_type`, `agent_did`, `action`, `resource`, `outcome`, `hash` |
| `ShadowResult` | `governance.shadow` | `action_id`, `shadow_decision`, `production_decision`, `diverged` |
| `OPADecision` | `governance.opa` | `result`, `allowed`, `reason` |
| `TrustPolicyDecision` | `governance.policy_evaluator` | `allowed`, `trust_score_required`, `matched_rules` |
| `AgentNamespace` | `identity.namespace` | `name`, `description`, `parent`, `members`, `created_at` |
| `NamespaceRule` | `identity.namespace` | `source_namespace`, `target_namespace`, `allow_communication`, `allow_delegation` |
| `RevocationEntry` | `identity.revocation` | `agent_did`, `reason`, `revoked_by`, `revoked_at`, `expires_at` |
| `RiskSignal` | `identity.risk` | `signal_type`, `severity`, `source`, `description` |
| `RiskScore` | `identity.risk` | `agent_did`, `overall`, `identity`, `behavior`, `network`, `compliance` |
| `MTLSConfig` | `identity.mtls` | `cert_path`, `key_path`, `ca_path`, `verify_client` |
