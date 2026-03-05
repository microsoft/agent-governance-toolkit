# RFC: AI-BOM — AI Bill of Materials for Agentic Systems

**Status:** Draft v2.0  
**Author:** Imran Siddique (Microsoft)  
**Created:** 2026-02-03  
**Updated:** 2026-03-04  
**Target:** LF AI & Data Foundation, OWASP AI SBOM Initiative  
**Supersedes:** Agent-SBOM v1.0

## Abstract

This RFC proposes the **AI-BOM** (AI Bill of Materials), a comprehensive standard for describing the full supply chain of AI agents — including model provenance, dataset lineage, weights versioning, tool capabilities, and governance policies.

AI-BOM extends the Agent-SBOM v1.0 concept beyond software dependencies to cover the complete AI supply chain:

- **Model provenance** — training lineage, fine-tuning history, base model ancestry
- **Dataset tracking** — training data, RAG sources, evaluation benchmarks with data cards
- **Weights versioning** — cryptographic hashes, quantization records, adapter metadata
- **Tool capabilities** — enumerated access, delegation rules, human-in-the-loop
- **Human sponsor accountability** — organizational ownership chain
- **Trust boundaries** — attestations, compliance mappings, risk profiles

## Motivation

### The Problem

Modern AI agents are opaque at every layer. When an organization deploys an agent, they have no standard way to answer:

1. **What model powers this agent?** (GPT-4, Claude, Llama, fine-tuned?)
2. **What data was it trained on?** (Licensed datasets? PII-contaminated? Evaluation benchmarks?)
3. **What version of weights is running?** (Original, quantized, LoRA-adapted?)
4. **What tools can it access?** (Filesystem, network, databases, APIs?)
5. **Who is accountable?** (Which human/organization sponsors this agent?)
6. **What are its trust boundaries?** (Can it delegate? To whom?)

### Why This Matters

- **Security teams** need to assess agent risk across the full AI supply chain
- **Compliance officers** need model and data lineage for regulatory audits (EU AI Act, NIST AI RMF)
- **Platform operators** need to enforce capability boundaries at runtime
- **Supply chain security** requires provenance verification for models, datasets, and weights
- **Other agents** need to verify trust before interaction
- **OWASP ASI-04** (Insecure Agent Supply Chain) identifies this as a top-10 agentic security risk

### Prior Art

| Standard | Domain | Gap for Agents |
|----------|--------|----------------|
| SBOM (SPDX, CycloneDX) | Software dependencies | No model/capability/data info |
| Model Cards (Google) | ML model documentation | No tool/delegation/runtime info |
| Data Cards (Google) | Dataset documentation | No agent integration |
| SLSA | Build provenance | No runtime behavior or AI artifacts |
| OAuth Scopes | API permissions | No AI-specific semantics |
| OWASP AI SBOM | AI supply chain (emerging) | No agent-specific capabilities |
| CycloneDX ML-BOM | ML component BOM | No agentic delegation/policy info |
| GLACIS AI Supply Chain | Industry guidance | Framework, not machine-readable |

## Specification

### AI-BOM Schema (v2.0)

```json
{
  "$schema": "https://agentmesh.dev/schemas/ai-bom/v2.json",
  "bomVersion": "2.0",
  "agentId": "did:mesh:abc123",
  "agentName": "CustomerServiceBot",
  "version": "2.1.0",
  "created": "2026-03-04T12:00:00Z",
  
  "sponsor": {
    "type": "organization",
    "name": "Acme Corp",
    "contact": "ai-governance@acme.com",
    "verificationMethod": "dns-txt",
    "entraObjectId": "00000000-0000-0000-0000-000000000001",
    "tenantId": "contoso.onmicrosoft.com"
  },
  
  "modelProvenance": {
    "primary": {
      "provider": "anthropic",
      "model": "claude-3-sonnet",
      "version": "20240229",
      "baseModel": "claude-3-sonnet-base",
      "family": "claude-3",
      "license": "Anthropic Terms of Service",
      "trainingCutoff": "2024-08-01",
      "safetyCard": "https://docs.anthropic.com/claude-3-safety"
    },
    "fineTuning": {
      "applied": true,
      "method": "LoRA",
      "baseCheckpoint": "claude-3-sonnet-20240229",
      "fineTunedBy": "Acme Corp AI Team",
      "fineTunedDate": "2026-01-15",
      "hyperparameters": {
        "learningRate": 2e-5,
        "epochs": 3,
        "rank": 16
      },
      "evaluationMetrics": {
        "accuracy": 0.94,
        "f1Score": 0.92,
        "hallucinationRate": 0.02
      }
    },
    "ancestry": [
      {
        "model": "claude-3-sonnet-base",
        "version": "20240229",
        "provider": "anthropic",
        "relationship": "base-model"
      }
    ]
  },
  
  "datasets": [
    {
      "id": "ds-customer-faq",
      "name": "Customer FAQ Knowledge Base",
      "version": "3.2",
      "type": "fine-tuning",
      "source": "internal",
      "size": "50,000 examples",
      "format": "JSONL",
      "hash": "sha256:abc123...",
      "dataCard": {
        "description": "Curated Q&A pairs from customer support interactions",
        "piiStatus": "redacted",
        "piiMethod": "presidio-v2",
        "license": "proprietary",
        "biasAssessment": "reviewed-2026-01",
        "dataClassification": "confidential",
        "collectionMethod": "manual-curation",
        "consentStatus": "obtained"
      }
    },
    {
      "id": "ds-product-docs",
      "name": "Product Documentation",
      "version": "2026.03",
      "type": "rag-source",
      "source": "internal",
      "format": "Markdown",
      "hash": "sha256:def456...",
      "updateFrequency": "weekly",
      "vectorStore": {
        "provider": "Pinecone",
        "index": "product-docs-v3",
        "embeddingModel": "text-embedding-3-large",
        "dimensions": 3072
      },
      "dataCard": {
        "description": "Official product documentation for RAG retrieval",
        "piiStatus": "none",
        "license": "proprietary",
        "dataClassification": "internal"
      }
    },
    {
      "id": "ds-eval-benchmark",
      "name": "Customer Service Benchmark",
      "version": "1.0",
      "type": "evaluation",
      "source": "internal",
      "size": "2,000 test cases",
      "hash": "sha256:ghi789...",
      "dataCard": {
        "description": "Human-labeled evaluation set for response quality",
        "piiStatus": "synthetic",
        "license": "proprietary"
      }
    }
  ],
  
  "weights": {
    "format": "safetensors",
    "precision": "bf16",
    "hash": "sha256:weights123...",
    "size": "14.2 GB",
    "quantization": null,
    "adapters": [
      {
        "type": "LoRA",
        "name": "customer-service-lora",
        "version": "1.3",
        "hash": "sha256:lora456...",
        "size": "48 MB",
        "rank": 16,
        "targetModules": ["q_proj", "v_proj"]
      }
    ],
    "slsaProvenance": {
      "builder": "acme-ml-pipeline/v2",
      "buildType": "fine-tune",
      "invocation": "sha256:build789...",
      "materials": ["ds-customer-faq@v3.2"]
    }
  },
  
  "capabilities": {
    "tools": [
      {
        "name": "database:query",
        "access": "read",
        "constraints": ["no-pii-columns"]
      },
      {
        "name": "api:http",
        "access": "invoke",
        "constraints": ["allowlist-only"],
        "allowlist": ["api.acme.com", "api.partner.com"]
      }
    ],
    "delegation": {
      "canDelegate": true,
      "maxDepth": 2,
      "narrowingRequired": true
    },
    "humanInLoop": {
      "required": ["financial-transactions", "pii-access"],
      "timeout": "5m"
    }
  },
  
  "policies": [
    {
      "id": "policy-no-pii",
      "name": "No PII Exposure",
      "version": "1.0",
      "hash": "sha256:abc123..."
    }
  ],
  
  "trust": {
    "initialScore": 800,
    "tier": "Verified",
    "attestations": [
      {
        "type": "security-audit",
        "auditor": "SecureCo",
        "date": "2026-01-15",
        "reportUrl": "https://..."
      }
    ]
  },
  
  "compliance": {
    "frameworks": [
      {
        "name": "OWASP Agentic Top 10",
        "version": "2026",
        "coverage": ["ASI-01", "ASI-02", "ASI-03", "ASI-04", "ASI-05"]
      },
      {
        "name": "CSA Agentic Trust Framework",
        "version": "0.1.0",
        "coverage": ["IM-01", "IM-02", "BM-01", "DG-01"]
      },
      {
        "name": "EU AI Act",
        "riskCategory": "limited",
        "transparencyObligations": true
      }
    ]
  },
  
  "dependencies": {
    "agents": [
      {
        "did": "did:mesh:helper123",
        "relationship": "delegates-to",
        "capabilities": ["search:web"]
      }
    ],
    "services": [
      {
        "name": "VectorDB",
        "provider": "Pinecone",
        "dataClassification": "internal"
      }
    ],
    "software": [
      {
        "name": "langchain",
        "version": "0.3.x",
        "license": "MIT",
        "spdxId": "SPDXRef-langchain"
      }
    ]
  },
  
  "riskProfile": {
    "dataAccess": ["internal", "confidential"],
    "networkAccess": true,
    "fileSystemAccess": "read-only",
    "codeExecution": false,
    "estimatedRiskLevel": "medium",
    "dataExfiltrationRisk": "low",
    "modelInversionRisk": "low",
    "promptInjectionMitigations": ["input-filtering", "output-guardrails"]
  },
  
  "signatures": {
    "sponsor": "base64:...",
    "platform": "base64:...",
    "algorithm": "Ed25519"
  }
}
```

### Required Fields

| Field | Description |
|-------|-------------|
| `bomVersion` | Schema version (for forward compatibility) |
| `agentId` | Unique identifier (DID recommended) |
| `agentName` | Human-readable name |
| `sponsor` | Accountable human/organization |
| `modelProvenance.primary` | Primary AI model information |
| `capabilities.tools` | Enumerated tool access |

### Optional Fields

| Field | Description |
|-------|-------------|
| `modelProvenance.fineTuning` | Fine-tuning provenance and metrics |
| `modelProvenance.ancestry` | Base model lineage chain |
| `datasets` | Training, RAG, and evaluation data sources |
| `weights` | Model weights metadata with cryptographic hashes |
| `capabilities.delegation` | Delegation rules |
| `capabilities.humanInLoop` | HITL requirements |
| `policies` | Attached governance policies |
| `trust` | Trust attestations |
| `compliance` | Regulatory framework coverage |
| `dependencies` | Other agents, services, and software used |
| `riskProfile` | Risk assessment summary |
| `signatures` | Cryptographic signatures |

### New in v2.0: Model Provenance

The `modelProvenance` section tracks the complete lineage of the AI model:

| Sub-field | Purpose |
|-----------|---------|
| `primary.baseModel` | Identifies the upstream base model |
| `primary.trainingCutoff` | When the model's training data ends |
| `primary.safetyCard` | Link to the model's safety evaluation |
| `fineTuning.method` | Fine-tuning technique (LoRA, full, QLoRA, etc.) |
| `fineTuning.evaluationMetrics` | Post-training evaluation results |
| `ancestry[]` | Chain of model derivations from base to current |

### New in v2.0: Dataset Tracking

The `datasets` array supports three dataset types:

| Type | Purpose | Key Fields |
|------|---------|------------|
| `fine-tuning` | Training data | size, format, PII status, bias assessment |
| `rag-source` | Retrieval data | vector store config, update frequency |
| `evaluation` | Test benchmarks | size, synthetic/real labels |

Each dataset includes a **data card** inspired by Google Data Cards:

| Data Card Field | Purpose |
|-----------------|---------|
| `piiStatus` | none / redacted / synthetic / present |
| `piiMethod` | Anonymization technique used |
| `biasAssessment` | When bias was last reviewed |
| `consentStatus` | Data subject consent tracking |
| `dataClassification` | public / internal / confidential / restricted |

### New in v2.0: Weights Versioning

The `weights` section provides cryptographic verification of model artifacts:

| Field | Purpose |
|-------|---------|
| `hash` | SHA-256 of the complete weights file |
| `format` | safetensors / GGUF / PyTorch / etc. |
| `precision` | bf16 / fp16 / fp32 / int8 / int4 |
| `quantization` | Quantization method and parameters |
| `adapters[]` | LoRA/QLoRA adapter metadata with hashes |
| `slsaProvenance` | SLSA-compatible build provenance |

## Use Cases

### 1. Pre-Deployment Risk Assessment

```
Security Team receives Agent-SBOM
→ Checks: Does model meet our approved list?
→ Checks: Are tools within allowed scope?
→ Checks: Is sponsor from trusted organization?
→ Decision: Approve/Deny deployment
```

### 2. Runtime Capability Enforcement

```
Agent attempts to call tool
→ Platform checks Agent-SBOM
→ Tool in capabilities list? 
→ Constraints satisfied?
→ Allow/Block execution
```

### 3. Inter-Agent Trust Verification

```
Agent A wants to delegate to Agent B
→ Agent A retrieves Agent B's SBOM
→ Verifies: Can B handle requested capability?
→ Verifies: Is B's sponsor trusted?
→ Verifies: Does B have required attestations?
→ Proceed/Refuse delegation
```

### 4. Compliance Auditing

```
Auditor requests: "Show all agents with PII access"
→ Query all Agent-SBOMs
→ Filter: riskProfile.dataAccess includes "pii"
→ Generate compliance report
```

## Verification

### Sponsor Verification Methods

| Method | Description |
|--------|-------------|
| `dns-txt` | TXT record at _agentmesh.domain.com |
| `well-known` | /.well-known/agentmesh-sponsor.json |
| `x509` | X.509 certificate chain |
| `did-web` | DID Web resolution |

### SBOM Signing

Agent-SBOMs SHOULD be signed by:
1. **Sponsor:** Attests to agent ownership
2. **Platform:** Attests to capability enforcement

Signature format: JSON Web Signature (JWS)

## Distribution

### Discovery

Agent-SBOMs can be discovered via:

1. **DID Resolution:** `did:mesh:abc123` → SBOM URL
2. **Well-Known:** `https://agent.example.com/.well-known/agent-sbom.json`
3. **Registry:** Query AgentMesh registry by agent ID

### Updates

When agent capabilities change:
1. New SBOM version is published
2. Previous versions remain available (immutable)
3. Changelog included in new version

## Security Considerations

### Tampering
- SBOMs MUST be signed
- Signature verification required before trust decisions

### Information Disclosure
- SBOMs may reveal internal architecture
- Organizations can publish "public" subset
- Full SBOM shared only with authorized parties

### Stale Data
- SBOMs have `created` timestamp
- Consumers SHOULD reject SBOMs older than policy threshold

## Relationship to Other Standards

| Standard | Relationship |
|----------|--------------|
| SPDX 3.0 | AI-BOM extends SBOM concept; `dependencies.software` uses SPDX IDs |
| CycloneDX ML-BOM | `modelProvenance` and `weights` align with ML-BOM components |
| Model Cards (Google) | `modelProvenance.primary` inspired by Model Cards |
| Data Cards (Google) | `datasets[].dataCard` structure based on Data Cards |
| SLSA | `weights.slsaProvenance` uses SLSA v1.0 provenance format |
| OWASP AI SBOM | AI-BOM is a superset covering agentic-specific fields |
| CloudEvents | Audit logs in CloudEvents reference AI-BOM |
| OPA | Policies can be OPA Rego files |
| CSA ATF | `compliance.frameworks` maps to ATF requirements |
| EU AI Act | `compliance.frameworks` tracks AI Act risk categories |

## Alignment with OWASP Agentic Top 10

| OWASP Risk | AI-BOM Coverage |
|------------|-----------------|
| ASI-01: Excessive Agency | `capabilities.tools` + `capabilities.delegation` |
| ASI-02: Privilege Escalation | `capabilities.humanInLoop` + `policies` |
| ASI-03: Supply Chain | `dependencies.software` + traditional SBOM fields |
| **ASI-04: AI Supply Chain** | **`modelProvenance` + `datasets` + `weights` (NEW in v2.0)** |
| ASI-05: Identity Spoofing | `sponsor` + `signatures` + Entra Agent ID |
| ASI-06: Memory Poisoning | `datasets[type=rag-source]` tracking |
| ASI-07: Prompt Injection | `riskProfile.promptInjectionMitigations` |
| ASI-08: Cascading Hallucination | `modelProvenance.fineTuning.evaluationMetrics.hallucinationRate` |
| ASI-09: Insufficient Logging | `trust.attestations` + audit trail |
| ASI-10: Unmonitored Behavior | `riskProfile` + `compliance.frameworks` |

## Roadmap

### v1.0 (Original Agent-SBOM)
- Core schema: agent identity, sponsor, model, capabilities
- Signing requirements

### v2.0 (This RFC — AI-BOM)
- Model provenance with fine-tuning lineage
- Dataset tracking with data cards
- Weights versioning with SLSA provenance
- Compliance framework mapping
- Entra Agent ID integration
- Software dependency SPDX alignment

### v2.1 (Planned)
- Multi-model agent support (ensemble, routing)
- Dynamic capability negotiation protocols
- Real-time AI-BOM updates via webhooks
- Cross-platform federation (inter-org trust)

### v3.0 (Future)
- Autonomous AI-BOM generation from agent introspection
- Live model drift detection linked to BOM
- Regulatory compliance auto-assessment

## Implementation

### Reference Implementation

AgentMesh provides:
- JSON Schema for validation
- Python library for AI-BOM generation
- CLI tool for AI-BOM creation/verification
- Integration with SPDX and CycloneDX export

```bash
# Generate AI-BOM for an agent
agentmesh bom generate --agent my-agent --output bom.json

# Verify an AI-BOM (signature + schema)
agentmesh bom verify bom.json

# Check agent runtime against AI-BOM
agentmesh bom enforce --bom bom.json --agent my-agent

# Export to CycloneDX ML-BOM format
agentmesh bom export --format cyclonedx --output bom.cdx.json

# Generate data card for a dataset
agentmesh bom data-card --dataset customer-faq --output data-card.json

# Verify model weights integrity
agentmesh bom verify-weights --bom bom.json --weights-dir ./model/
```

## Call for Feedback

We invite feedback on:

1. **Schema completeness:** What fields are missing for your AI supply chain needs?
2. **Interoperability:** How to best align with OWASP AI SBOM, CycloneDX ML-BOM, SPDX 3.0?
3. **Dataset tracking:** Are data cards sufficient for your regulatory requirements?
4. **Model provenance:** What additional fine-tuning metadata is needed?
5. **Adoption:** What tooling would make AI-BOM useful for your organization?

Submit feedback:
- GitHub: https://github.com/microsoft/agent-governance-toolkit/discussions
- Microsoft: https://github.com/microsoft/agent-governance-toolkit/issues

---

*This RFC is submitted for consideration by the LF AI & Data Foundation Trusted AI Committee and the OWASP AI SBOM Initiative.*
