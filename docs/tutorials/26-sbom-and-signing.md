<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Tutorial 26 — SBOM Generation and Artifact Signing

Secure your software supply chain with Software Bills of Materials (SBOMs) and
cryptographic artifact signing. This tutorial covers generating SPDX and
CycloneDX SBOMs, signing artifacts with Ed25519, verifying signatures, and
integrating everything into CI/CD pipelines.

> **Package:** `agent-compliance` (Python) · GitHub Actions workflows
> **Formats:** SPDX JSON, CycloneDX JSON
> **Signing:** Ed25519 (SDK), Sigstore (Python packages), ESRP (.NET packages)

---

## What you'll learn

| Section | Topic |
|---------|-------|
| [What is an SBOM?](#what-is-an-sbom) | Why SBOMs matter for agent security |
| [Generating SBOMs](#generating-sboms) | SPDX and CycloneDX generation |
| [Ed25519 Artifact Signing](#ed25519-artifact-signing) | Sign artifacts using the SDK's identity system |
| [Verifying Signatures](#verifying-signatures) | Verify artifact integrity |
| [CI/CD Integration](#cicd-integration) | Automated SBOM and signing pipelines |
| [SBOM Attestation](#sbom-attestation) | Attesting SBOMs to releases |
| [Cross-Reference](#cross-reference) | Related tutorials |

---

## Prerequisites

- **Python 3.10+** for the compliance package
- **Node.js 18+** for TypeScript signing examples
- GitHub Actions for CI/CD integration
- Recommended: read [Tutorial 25 — Security Hardening](25-security-hardening.md)

---

## What is an SBOM?

A **Software Bill of Materials** (SBOM) is a machine-readable inventory of all
components, libraries, and dependencies in a software product. It's the software
equivalent of a food ingredients label.

### Why SBOMs Matter for Agent Systems

Agent systems have unique supply chain risks:

1. **Transitive dependencies** — An agent framework may pull in hundreds of
   packages, each a potential attack vector
2. **Tool definitions** — MCP tool descriptions are executable attack surface
   (see [Tutorial 27](./27-mcp-scan-cli.md))
3. **Model weights** — LLM models themselves are part of the supply chain
4. **Plugin ecosystem** — Third-party plugins introduce untrusted code

An SBOM lets you:
- **Audit** what's actually in your deployed agent
- **Respond** to CVEs by quickly checking if you're affected
- **Comply** with regulatory requirements (Executive Order 14028, EU CRA)
- **Verify** that the deployed artifact matches what was built

### SBOM Formats

| Format | Standard | Best For |
|--------|----------|----------|
| **SPDX** | ISO/IEC 5962:2021 | Licence compliance, open source |
| **CycloneDX** | OWASP standard | Vulnerability tracking, security |

The toolkit generates both formats — use SPDX for licence compliance and
CycloneDX for vulnerability management.

---

## Generating SBOMs

### §2.1 Using the Anchore SBOM Action

The toolkit uses the `anchore/sbom-action` to generate SBOMs from the
repository:

```yaml
# Generate SPDX SBOM
- uses: anchore/sbom-action@v0
  with:
    output-file: sbom.spdx.json
    format: spdx-json
    artifact-name: sbom-spdx

# Generate CycloneDX SBOM
- uses: anchore/sbom-action@v0
  with:
    output-file: sbom.cdx.json
    format: cyclonedx-json
    artifact-name: sbom-cyclonedx
```

### §2.2 Local SBOM Generation

Generate SBOMs locally using Syft (the CLI behind the Anchore action):

```bash
# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s

# Generate SPDX SBOM
syft . -o spdx-json=sbom.spdx.json

# Generate CycloneDX SBOM
syft . -o cyclonedx-json=sbom.cdx.json
```

### §2.3 SBOM Contents

An SPDX SBOM includes:

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "agent-governance-toolkit",
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-python-agent-os-kernel",
      "name": "agent-os-kernel",
      "versionInfo": "2.1.0",
      "supplier": "Organization: Microsoft",
      "downloadLocation": "https://pypi.org/project/agent-os-kernel/",
      "licenseConcluded": "MIT"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-python-agent-os-kernel",
      "relationshipType": "DESCRIBES"
    }
  ]
}
```

A CycloneDX SBOM includes:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "agent-os-kernel",
      "version": "2.1.0",
      "purl": "pkg:pypi/agent-os-kernel@2.1.0",
      "licenses": [{"license": {"id": "MIT"}}]
    }
  ]
}
```

---

## Ed25519 Artifact Signing

Use the toolkit's Ed25519 identity system to sign any artifact — release
binaries, SBOMs, policy files, or audit logs.

### §3.1 Signing with the TypeScript package

```typescript
import { AgentIdentity } from '@microsoft/agentmesh-sdk';
import { readFileSync, writeFileSync } from 'fs';

// 1. Generate (or load) a signing identity
const signer = AgentIdentity.generate('release-signer', ['sign.artifacts'], {
  name: 'Release Signing Identity',
  organization: 'security-team',
});

// 2. Read the artifact to sign
const artifact = readFileSync('dist/agent-os-kernel-2.1.0.tar.gz');

// 3. Sign the artifact
const signature = signer.sign(new Uint8Array(artifact));

// 4. Save the signature
writeFileSync(
  'dist/agent-os-kernel-2.1.0.tar.gz.sig',
  Buffer.from(signature),
);

// 5. Export the public key for verification
const publicIdentity = signer.toJSON();
writeFileSync(
  'dist/signing-identity.json',
  JSON.stringify(publicIdentity, null, 2),
);

console.log('Artifact signed successfully');
console.log('Signature:', Buffer.from(signature).toString('hex').slice(0, 32) + '...');
console.log('Signer DID:', signer.did);
```

### §3.2 Signing with the Rust crate

```rust
use agentmesh::AgentIdentity;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a signing identity
    let signer = AgentIdentity::generate(
        "release-signer",
        vec!["sign.artifacts".into()],
    )?;

    // Read and sign the artifact
    let artifact = fs::read("dist/artifact.tar.gz")?;
    let signature = signer.sign(&artifact)?;

    // Save the signature
    fs::write("dist/artifact.tar.gz.sig", &signature)?;

    // Export public identity for verification
    let pub_json = signer.to_json()?;
    fs::write("dist/signing-identity.json", &pub_json)?;

    println!("Signed by: {}", signer.did);
    Ok(())
}
```

### §3.3 Signing with the Go module

```go
package main

import (
    "log"
    "os"

    agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang"
)

func main() {
    // Generate signing identity
    signer, err := agentmesh.GenerateIdentity("release-signer", []string{"sign.artifacts"})
    if err != nil {
        log.Fatal(err)
    }

    // Read and sign the artifact
    artifact, err := os.ReadFile("dist/artifact.tar.gz")
    if err != nil {
        log.Fatal(err)
    }

    signature, err := signer.Sign(artifact)
    if err != nil {
        log.Fatal(err)
    }

    // Save signature
    os.WriteFile("dist/artifact.tar.gz.sig", signature, 0644)

    // Export public identity
    pubJSON, _ := signer.ToJSON()
    os.WriteFile("dist/signing-identity.json", pubJSON, 0644)

    log.Printf("Signed by: %s\n", signer.DID)
}
```

---

## Verifying Signatures

### §4.1 Verification with the TypeScript package

```typescript
import { AgentIdentity } from '@microsoft/agentmesh-sdk';
import { readFileSync } from 'fs';

// 1. Load the signer's public identity
const signerJSON = JSON.parse(
  readFileSync('dist/signing-identity.json', 'utf-8'),
);
const signer = AgentIdentity.fromJSON(signerJSON);

// 2. Read the artifact and signature
const artifact = readFileSync('dist/agent-os-kernel-2.1.0.tar.gz');
const signature = readFileSync('dist/agent-os-kernel-2.1.0.tar.gz.sig');

// 3. Verify
const valid = signer.verify(
  new Uint8Array(artifact),
  new Uint8Array(signature),
);

if (valid) {
  console.log('✅ Signature valid — artifact is authentic');
  console.log('Signed by:', signer.did);
} else {
  console.error('❌ Signature verification failed — artifact may be tampered');
  process.exit(1);
}
```

### §4.2 Verification with the Go module

```go
// Load signer's public identity
pubJSON, _ := os.ReadFile("dist/signing-identity.json")
signer, _ := agentmesh.FromJSON(pubJSON)

// Read artifact and signature
artifact, _ := os.ReadFile("dist/artifact.tar.gz")
signature, _ := os.ReadFile("dist/artifact.tar.gz.sig")

// Verify
if signer.Verify(artifact, signature) {
    fmt.Println("✅ Signature valid")
} else {
    fmt.Println("❌ Verification failed")
    os.Exit(1)
}
```

---

## CI/CD Integration

### §5.1 Full SBOM + Signing Workflow

```yaml
# .github/workflows/release.yml
name: Release with SBOM and Signing
on:
  release:
    types: [published]

permissions:
  contents: write
  id-token: write
  attestations: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Build the package
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install build && python -m build

      # Generate SBOMs
      - uses: anchore/sbom-action@v0
        with:
          output-file: sbom.spdx.json
          format: spdx-json

      - uses: anchore/sbom-action@v0
        with:
          output-file: sbom.cdx.json
          format: cyclonedx-json

      # Sign Python artifacts with Sigstore
      - uses: sigstore/gh-action-sigstore-python@v3
        with:
          inputs: dist/*.tar.gz dist/*.whl

      # Attest build provenance
      - uses: actions/attest-build-provenance@v2
        with:
          subject-path: dist/*

      # Upload to release
      - run: |
          gh release upload ${{ github.ref_name }} \
            sbom.spdx.json \
            sbom.cdx.json \
            dist/*.tar.gz \
            dist/*.whl \
            --clobber
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### §5.2 .NET Package Signing

For .NET packages, the toolkit supports ESRP-based signing:

```yaml
# Sign NuGet packages (when ESRP is configured)
- name: Sign NuGet package
  run: |
    # ESRP signing (enterprise environments)
    # Authenticode sign the assembly
    # NuGet sign the package
    dotnet nuget verify dist/*.nupkg
```

### §5.3 Verification in CI

Add a verification step to your deployment pipeline:

```yaml
# Verify before deploying
- name: Verify artifact signature
  run: |
    node -e "
      const { AgentIdentity } = require('@microsoft/agentmesh-sdk');
      const fs = require('fs');
      const signer = AgentIdentity.fromJSON(
        JSON.parse(fs.readFileSync('signing-identity.json', 'utf-8'))
      );
      const artifact = fs.readFileSync('dist/artifact.tar.gz');
      const sig = fs.readFileSync('dist/artifact.tar.gz.sig');
      if (!signer.verify(new Uint8Array(artifact), new Uint8Array(sig))) {
        console.error('Signature verification failed');
        process.exit(1);
      }
      console.log('Signature valid:', signer.did);
    "
```

---

## SBOM Attestation

GitHub's attestation system binds SBOMs to specific releases, providing a
verifiable link between the SBOM and the artifact it describes.

### How Attestation Works

```
  ┌─────────────────────────────────────────────────────┐
  │  Release v2.1.0                                     │
  │  ┌──────────────┐  ┌────────────────────────────┐   │
  │  │  artifact.whl │  │  SBOM attestation          │   │
  │  │               │◄─│  • subject: artifact.whl   │   │
  │  │               │  │  • predicate: sbom.spdx    │   │
  │  │               │  │  • signed by: GitHub OIDC  │   │
  │  └──────────────┘  └────────────────────────────┘   │
  └─────────────────────────────────────────────────────┘
```

### Creating Attestations

```yaml
# Attest the SBOM
- uses: actions/attest-sbom@v2
  with:
    subject-path: dist/artifact.whl
    sbom-path: sbom.spdx.json
```

### Verifying Attestations

```bash
# Verify attestation using GitHub CLI
gh attestation verify dist/artifact.whl \
  --owner microsoft \
  --format json
```

---

## Cross-Reference

| Concept | Tutorial |
|---------|----------|
| Security hardening | [Tutorial 25 — Security Hardening](./25-security-hardening.md) |
| Audit and compliance | [Tutorial 04 — Audit & Compliance](./04-audit-and-compliance.md) |
| Compliance verification | [Tutorial 18 — Compliance Verification](./18-compliance-verification.md) |
| Plugin marketplace signing | [Tutorial 10 — Plugin Marketplace](./10-plugin-marketplace.md) |
| Ed25519 identity | [Tutorial 02 — Trust & Identity](./02-trust-and-identity.md) |
| Shift-left governance | [Tutorial 45 — Shift-Left Governance](./45-shift-left-governance.md) |

---

## Source Files

| Component | Location |
|-----------|----------|
| Security scanner | `agent-governance-python/agent-compliance/src/agent_compliance/security/scanner.py` |
| SBOM workflow | `.github/workflows/sbom.yml` |
| Publish workflow | `.github/workflows/publish.yml` |
| Ed25519 identity (TS) | `agent-governance-typescript/src/identity.ts` |
| Ed25519 identity (Rust) | `agent-governance-rust/agentmesh/src/identity.rs` |
| Ed25519 identity (Go) | `agent-governance-golang/identity.go` |

---

## Next Steps

- **Generate an SBOM** for your agent deployment and review the component list
- **Set up Sigstore signing** for Python package releases
- **Add SBOM attestation** to your release workflow
- **Verify signatures** as part of your deployment pipeline
- **Read Tutorial 25** ([Security Hardening](./25-security-hardening.md)) for
  the full security tooling stack
- **Read Tutorial 27** ([MCP Scan CLI](./27-mcp-scan-cli.md)) for scanning
  tool definitions as part of supply chain security
