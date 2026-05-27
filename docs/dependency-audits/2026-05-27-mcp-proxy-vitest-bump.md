<!-- cspell:words vite GHSA vg6x rcgg rjx6 jqfw vq24 v9c3 cwx -->
# Dependency audit — mcp-proxy vitest 1.6.1 → 4.1.7

## Which dependencies changed and why

- `agent-governance-python/agent-mesh/packages/mcp-proxy/package-lock.json` updated by
  Dependabot PR #2608 (`chore(deps): bump vite and vitest in
  /agent-governance-python/agent-mesh/packages/mcp-proxy`).
- Direct devDependency change:
  - `vitest`: `1.6.1` → `4.1.7` (major version bump).
- Transitive change:
  - `vite` is removed from the resolved graph. It was previously pulled in only as an
    ancestor of the old `vitest` 1.x; the new `vitest` 4.x line no longer requires it
    in this package's resolved tree.
- Reason: keep the `mcp-proxy` test toolchain on a maintained `vitest` major and clear
  the inherited `vite` 5.x dependency that was the subject of multiple GHSA advisories.
  This is a test-only (`devDependencies`) change; no runtime/published code is affected.

## Security advisory relevance

- Upgrading off `vitest@1.6.1` clears the transitive `vite@5.x` graph that has been the
  source of repeated dev-time advisories (most recently the
  `server.fs.deny` / file-serving family — `GHSA-vg6x-rcgg-rjx6`, `GHSA-x574-m823-4x7w`,
  `GHSA-jqfw-vq24-v9c3`, `GHSA-9cwx-2883-4wfx`, `GHSA-356w-63v5-8wf4`).
- `vitest` 4.x ships with patched `vite` peers, so this bump removes those advisory
  hits from the `mcp-proxy` lockfile.
- No production CVE in `mcp-proxy` is being remediated by this change; the affected
  packages are `devDependencies` used only by the local test runner.

## Breaking change risk assessment

- `agent-governance-python/agent-mesh/packages/mcp-proxy/package-lock.json`
  - Low risk for repository runtime: `vitest` is a `devDependency` used only for
    `mcp-proxy`'s local unit tests; it is not bundled or shipped to any consumer.
  - Moderate risk for the local test suite: `vitest` 1.x → 4.x is a major upgrade and
    can surface API and config differences (e.g. workspace/projects config, default
    pool, snapshot format, deprecation of some `sequential` test options).
  - Mitigation: CI runs `npm test` for this package; any breakage will be visible on
    this PR before merge. If the suite regresses, the fix is either a small config
    update in `vitest.config.*` or pinning to an intermediate `vitest` 2.x/3.x line.
- No other lockfiles, runtime packages, or published SDK surfaces are touched by this PR.

## Overall assessment

Acceptable. The bump removes a known-vulnerable transitive `vite` graph from a
dev-only toolchain, keeps `mcp-proxy` on a supported `vitest` major, and is gated by
the existing CI test run for the affected package.
