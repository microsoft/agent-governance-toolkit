# Release process

This document describes the canonical AGT release process. AGT is proposed for
AAIF hosting in `aaif/project-proposals#19`; until TC approval, Governing Board
approval, governance finalization, and contribution agreement execution are
complete, do not describe AGT as donated.

## Versioning

AGT uses Semantic Versioning for published packages. The repository is a
multi-language monorepo, so a release may publish several ecosystem artifacts
from the same tag even when only a subset changed.

## Release authority

Canonical releases are approved by maintainers with release-workflow ownership.
Release approval is a project authority, not a Microsoft ESRP approval.

## Supported registries

| Ecosystem | Registry | Canonical identity source |
|---|---|---|
| Python | PyPI | `docs/package-migration.md` |
| npm | npmjs.com | `docs/package-migration.md` |
| .NET | NuGet.org | `docs/package-migration.md` |
| Rust | crates.io | `docs/package-migration.md` |
| Go | Go module proxy | `docs/package-migration.md` |
| Containers | GHCR / OCI registry | `docs/package-migration.md` |

## Release workflow

1. Release manager confirms relevant CI is green.
2. Release manager confirms package map, manifests, and release matrix agree.
3. Release manager runs `Publish Packages` with `dry_run: true` and reviews the
   uploaded `release-manifest.json`.
4. Release manager runs `Publish Container Images` with `dry_run: true` when
   container artifacts are in scope.
5. Release manager creates a signed release tag.
6. `.github/workflows/publish.yml` builds, tests, packages, attests, and
   publishes language packages.
7. `.github/workflows/publish-containers.yml` builds, attests, and publishes
   container images.
8. `.github/workflows/sbom.yml` produces release SBOMs and provenance.
9. Release manager verifies artifacts and publishes release notes.

## Supply-chain requirements

Every canonical release must preserve:

- pinned GitHub Actions;
- least-privilege workflow permissions;
- dependency review on PRs;
- CodeQL and Scorecard coverage;
- SBOM generation;
- provenance attestations;
- explicit package and container verification guidance.

## Hotfixes

For critical bugs or security issues:

1. Create a hotfix branch from the affected release tag.
2. Apply the minimal fix with tests.
3. Run relevant package validation.
4. Cut a patch release.
5. Cherry-pick the fix back to `main` if needed.

## Deprecated release paths

Azure DevOps ESRP is not a canonical AGT release path. Do not reintroduce ESRP,
Microsoft tenant IDs, Microsoft Key Vault, or Microsoft signing certificates into
canonical AGT release workflows.
