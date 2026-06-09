# Dependency audit — Mastra zod peer alignment for release dry run

## Which dependencies changed and why

This PR updates `agent-governance-python/agentmesh-integrations/mastra-agentmesh`
so the package can be installed by the release workflow's normal `npm ci
--ignore-scripts` path.

The dry-run release found that `@mastra/core@1.37.1` requires `zod` matching
`^3.25.0 || ^4.0.0`, while the package pinned `zod@3.22.0`. The root dev
dependency now pins `zod@3.25.76`, which satisfies the peer range without moving
to the newer `zod@4` major.

Regenerating `package-lock.json` with npm also records peer metadata packages
needed for the current dependency graph:

- `@standard-community/standard-json@0.3.5`
- `@standard-community/standard-openapi@0.2.9`
- `@types/json-schema@7.0.15`
- `openapi-types@12.1.3`
- `quansync@0.2.11`

All listed package versions were released more than seven days before this audit
date.

## Security advisory relevance

No CVE-specific remediation is claimed. The change is a release-build
compatibility fix for an npm peer dependency mismatch discovered by the package
dry run.

The chosen `zod@3.25.76` version is already present in the previous lockfile as
a transitive dependency under `zod-from-json-schema-v3`, so this PR promotes an
already-audited version to the package's root dev dependency instead of adding a
new zod major.

## Breaking change risk assessment

Runtime risk is low because `zod` remains in the same major version line and the
package declares `zod` as a peer dependency with a lower bound of `>=3.22.0`.
The release workflow only needs the dev dependency to build and pack the package.

The main compatibility risk would be a Mastra build or test failure caused by
behavioral changes between `zod@3.22.0` and `zod@3.25.76`; local validation ran
`npm ci --ignore-scripts` and `npm run build` successfully for the Mastra package.
