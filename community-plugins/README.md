# AGT Community Plugins

Community implementations of the [`EvidenceAnchor`](../docs/proposals/MYCELIUM-EXTERNAL-ANCHOR-PROPOSAL.md) SPI.

AGT ships with WORM and Sigstore Rekor as in-tree reference backends. Community plugins extend
anchoring to additional surfaces without adding runtime dependencies to AGT core.

## Available plugins

| Plugin | Backend | Maintainer |
|--------|---------|------------|
| [`mycelium_trails`](mycelium_trails/) | Mycelium Trails on Arbitrum | [@giskard09](https://github.com/giskard09) |

## Contributing a plugin

1. Create `community-plugins/<your_plugin>/` with at minimum: `__init__.py`, `README.md`, tests.
2. Implement the `EvidenceAnchor` ABC from `MYCELIUM-EXTERNAL-ANCHOR-PROPOSAL.md`.
3. Add your plugin to the table above.
4. Open a PR — one plugin per PR.

Requirements: append-only backend (records cannot be modified or deleted after anchoring),
`verify()` must be independently callable without AGT runtime state.
