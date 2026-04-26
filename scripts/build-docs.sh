#!/bin/bash
# Build script for MkDocs documentation site.
# Copies existing docs into site/docs/ so content is maintained in one place.
# Run this before `mkdocs build` or let the GitHub Actions workflow handle it.

set -e

SITE_DOCS="site/docs"

echo "Copying docs to $SITE_DOCS..."

# Create directories
mkdir -p "$SITE_DOCS"/{packages,tutorials,deployment,security,adr,reference}

# Top-level docs
cp QUICKSTART.md "$SITE_DOCS/quickstart.md"
cp docs/ARCHITECTURE.md "$SITE_DOCS/architecture.md"
cp docs/GLOSSARY.md "$SITE_DOCS/glossary.md"

# Tutorials
cp docs/tutorials/*.md "$SITE_DOCS/tutorials/"

# Deployment
cp docs/deployment/*.md "$SITE_DOCS/deployment/"

# Security
cp docs/THREAT_MODEL.md "$SITE_DOCS/security/threat-model.md"
cp docs/OWASP-COMPLIANCE.md "$SITE_DOCS/security/owasp-compliance.md"
cp docs/security-scanning.md "$SITE_DOCS/security/scanning.md"
cp docs/security/tenant-isolation-checklist.md "$SITE_DOCS/security/tenant-isolation.md"

# ADRs
cp docs/adr/*.md "$SITE_DOCS/adr/"

# Reference
cp BENCHMARKS.md "$SITE_DOCS/reference/benchmarks.md"
cp docs/COMPARISON.md "$SITE_DOCS/reference/comparison.md"
[ -f docs/nist-rfi-mapping.md ] && cp docs/nist-rfi-mapping.md "$SITE_DOCS/reference/nist-rfi-mapping.md"
[ -f docs/compliance/nist-rfi-2026-00206.md ] && cp docs/compliance/nist-rfi-2026-00206.md "$SITE_DOCS/reference/nist-rfi-mapping.md"
cp CHANGELOG.md "$SITE_DOCS/reference/changelog.md"
cp CONTRIBUTING.md "$SITE_DOCS/reference/contributing.md"

# Package READMEs
for pkg in agent-os agent-mesh agent-runtime agent-sre agent-compliance agent-marketplace agent-lightning agent-hypervisor agent-os-vscode; do
  if [ -f "$pkg/README.md" ]; then
    cp "$pkg/README.md" "$SITE_DOCS/packages/$pkg.md"
  fi
done

if [ -f "agent-governance-dotnet/README.md" ]; then
  cp "agent-governance-dotnet/README.md" "$SITE_DOCS/packages/dotnet-sdk.md"
fi

echo "Done. $(find $SITE_DOCS -name '*.md' | wc -l | tr -d ' ') pages ready."
