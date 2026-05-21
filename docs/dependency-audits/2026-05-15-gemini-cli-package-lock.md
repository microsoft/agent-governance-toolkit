# Dependency audit — Gemini CLI governance package lockfile

## Which dependencies changed and why

- `agent-governance-gemini-cli/package-lock.json` was added for the new public-preview Gemini CLI governance package.
  - Direct dependency added: `@microsoft/agent-governance-sdk@3.6.0`
  - Direct dependency added: `@modelcontextprotocol/sdk@1.29.0`
  - Key transitive dependencies now locked through those packages include `@noble/ciphers`, `@noble/curves`, `@noble/ed25519`, `@noble/hashes`, `js-yaml`, `ajv`, `content-type`, `cors`, `cross-spawn`, `express`, `hono`, `jose`, `raw-body`, `zod`, and `zod-to-json-schema`
  - Reason: the new package vendors the published AGT JavaScript SDK and the MCP SDK into the managed Gemini CLI extension install and needs a committed lockfile for reproducible CI and release builds.

## Security advisory relevance

- No new advisory-driven upgrade is being introduced here.
- The package pins the published `@microsoft/agent-governance-sdk@3.6.0`, which is already a first-party package in this repository's release set.
- The package also pins `@modelcontextprotocol/sdk@1.29.0` because the Gemini extension bundles a local MCP server for deterministic `/agt:status` and `/agt:check` operations.
- The locked transitive packages are standard cryptography, validation, and HTTP runtime dependencies resolved through those published packages, not ad hoc additions.
- No CVE-specific remediation is claimed by this lockfile change.

## Breaking change risk assessment

- `agent-governance-gemini-cli/package-lock.json`
  - Low to moderate risk.
  - The change introduces a new package and its pinned dependency tree, but it does not replace an existing runtime dependency graph in another shipped package.
  - Runtime impact is bounded to the new Gemini CLI governance package.
- Overall assessment: acceptable for this PR because the new lockfile is required for deterministic package builds and release reproducibility.
