# Dependency audit — Copilot CLI package and TypeScript SDK lockfiles

## Which dependencies changed and why

- `agent-governance-copilot-cli/package-lock.json` was added for the new public-preview Copilot CLI governance package.
  - Direct dependency added: `@microsoft/agent-governance-sdk@3.6.0`
  - Transitive dependencies locked through that SDK: `@noble/ciphers`, `@noble/curves`, `@noble/ed25519`, `@noble/hashes`, `js-yaml`, and `argparse`
  - Reason: the new package vendors the published AGT JavaScript SDK into the managed Copilot CLI extension install and needs a committed lockfile for reproducible CI and release builds.
- `agent-governance-typescript/package-lock.json` changed only to update the package version metadata from `3.5.0` to `3.6.0`.
  - No dependency graph change was introduced in that lockfile diff.
  - Reason: keep the published TypeScript package metadata aligned with the repo version for this release train.

## Security advisory relevance

- No new advisory-driven upgrade is being introduced here.
- The Copilot CLI package pins the published `@microsoft/agent-governance-sdk@3.6.0`, which is already a first-party package in this repository's release set.
- The newly locked transitive packages are standard cryptography and YAML parsing dependencies already resolved through the published SDK tarball, not ad hoc additions.
- No CVE-specific remediation is claimed by this lockfile change.

## Breaking change risk assessment

- `agent-governance-copilot-cli/package-lock.json`
  - Low to moderate risk.
  - The change introduces a new package and its pinned dependency tree, but it does not replace an existing runtime dependency graph in another shipped package.
  - Runtime impact is bounded to the new Copilot CLI governance package.
- `agent-governance-typescript/package-lock.json`
  - Low risk.
  - The diff is version metadata alignment only and does not change resolved dependencies.
- Overall assessment: acceptable for this PR because the new lockfile is required for deterministic package builds and the TypeScript lockfile change does not alter install behavior.
