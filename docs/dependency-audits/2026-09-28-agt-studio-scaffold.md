---
title: AGT Studio initial dependency lockfile
last_reviewed: 2026-09-28
owner: Ricky-G
---

# AGT Studio initial dependency lockfile

## Which dependencies changed and why

This change introduces `agent-governance-studio/web/package-lock.json` for the
new, private Studio frontend. There is no previous Studio lockfile or existing
Studio dependency graph to migrate.

| Direct packages | Pinned versions | Purpose |
|---|---|---|
| `react`, `react-dom` | 18.3.1 | Render the browser entry point using the architecture's React 18 choice. |
| `@tanstack/react-query` | 5.83.0 | Establish the chosen query-provider toolchain without adding network calls. |
| `vite`, `@vitejs/plugin-react`, `typescript` | 7.3.6, 4.7.0, 5.9.2 | Compile and bundle the TypeScript React entry point. |
| `tailwindcss`, `postcss` | 3.4.19, 8.5.28 | Compile the starter CSS without a native install hook. |
| `vitest`, `jsdom`, `@testing-library/react`, `@testing-library/dom` | 4.1.11, 26.1.0, 16.3.0, 10.4.1 | Execute DOM rendering and bootstrap tests. |
| `eslint`, `@eslint/js`, `typescript-eslint`, `globals` | 9.32.0, 9.32.0, 8.39.1, 16.3.0 | Enforce a non-no-op frontend lint gate. |
| `@types/react`, `@types/react-dom`, `@types/node` | 18.3.27, 18.3.7, 22.18.6 | Typecheck the browser and build configuration. |

The committed lockfile records transitive versions, upstream npm tarball URLs,
and SHA-512 integrity hashes for reproducible `npm ci --ignore-scripts`
installation. Since direct npm registry access was unavailable locally, each
registry package tarball was fetched through the configured Microsoft feed;
its bytes matched the initial lockfile hash, and its SHA-512 digest was then
recorded. The upstream registry integrity gate checks every registry-backed
entry independently in CI. The Python Studio package introduces no runtime
dependencies.

## Security advisory relevance

The initial Vite and Vitest selections reported npm advisories, so they were
replaced with patched `vite@7.3.6` and `vitest@4.1.11` before committing the
lockfile. Tailwind 4's native install hook can download a binary without
checking its integrity, so this scaffold instead uses Tailwind 3 with PostCSS.
The direct PostCSS pin is an aged patched release: older 8.5.x versions have
known security advisories. The full `npm audit` reports zero vulnerable
packages for this tree. Install scripts must still pass the repository's
separate registry-backed audit; this document does not replace that check.

## Breaking change risk assessment

This is an additive package that does not change any existing runtime. The
frontend is not published or launched by existing AGT commands. The targeted
Python and frontend tests, both builds, and an isolated Python wheel import
passed locally. The only new executable frontend behavior is rendering the
minimal Studio heading; sidecar and product features are deferred.
