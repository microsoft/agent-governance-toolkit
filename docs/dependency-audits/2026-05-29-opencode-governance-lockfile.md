# Dependency audit — OpenCode CLI governance package lockfile

## Which dependencies changed and why

- `agent-governance-opencode/package-lock.json` was added for the new public-preview OpenCode CLI governance package.
  - Direct dependency added: `@microsoft/agent-governance-sdk@3.7.0`
  - Key transitive dependencies now locked through that package include `@noble/ciphers`, `@noble/curves`, `@noble/ed25519`, `@noble/hashes`, and `js-yaml`
  - Reason: the new package wires the published AGT JavaScript SDK into an in-process OpenCode plugin and needs a committed lockfile for reproducible CI and release builds.

## Security advisory relevance

- No new advisory-driven upgrade is being introduced here.
- The package pins the published `@microsoft/agent-governance-sdk@3.7.0`, which is already a first-party package in this repository's release set.
- The locked transitive packages are standard cryptography and policy/runtime dependencies resolved through that published package, not ad hoc additions.
- No CVE-specific remediation is claimed by this lockfile change.

## Breaking change risk assessment

- `agent-governance-opencode/package-lock.json`
  - Low to moderate risk.
  - The change introduces a new package and its pinned dependency tree, but it does not replace an existing runtime dependency graph in another shipped package.
  - Runtime impact is bounded to the new OpenCode CLI governance package.
- Overall assessment: acceptable for this PR because the new lockfile is required for deterministic package builds and release reproducibility.
