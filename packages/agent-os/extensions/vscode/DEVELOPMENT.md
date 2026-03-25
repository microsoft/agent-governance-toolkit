# VS Code Extension Development Guide

## Prerequisites

- **Node.js 18+** -- Required for building and running the extension
- **Python 3.11+** -- Required for the live backend bridge
- **VS Code 1.85+** -- Extension host compatibility

## Quick Start

```bash
cd packages/agent-os/extensions/vscode
npm install
npm run compile
```

Open the extension folder in VS Code and press **F5** to launch the Extension Development Host. The extension activates automatically and registers all views, commands, and providers.

For iterative development, use watch mode:

```bash
npm run watch
```

## Architecture

The extension follows a provider-factory pattern that abstracts data sources behind a unified interface. The factory switches between mock and live backends based on user configuration.

```
Extension.ts (activation)
  |-- ProviderFactory (creates data providers based on mode)
  |     |-- mode: "mock"
  |     |     |-- MockSLOBackend
  |     |     |-- MockTopologyBackend
  |     |     +-- MockPolicyBackend
  |     |
  |     +-- mode: "local"
  |           +-- SubprocessTransport
  |                 +-- python -m agent_os.extensions.vscode_bridge --json
  |                       |-- agent_sre.slo --> SLO Dashboard
  |                       |-- agentmesh.topology --> Agent Topology
  |                       +-- agent_os.policies --> Policy Evaluator
  |
  |-- Views (TreeDataProviders)
  |     |-- sloDashboardView.ts
  |     |-- agentTopologyView.ts
  |     +-- policyTypes.ts
  |
  |-- Webviews (Rich panels)
  |     |-- governanceHub/ (sidebar + panel)
  |     |-- sloDashboard/
  |     +-- agentTopology/
  |
  |-- Language features
  |     |-- governanceDiagnosticProvider.ts
  |     |-- governanceCodeActions.ts
  |     +-- governanceRules.ts
  |
  +-- governanceStatusBar.ts (mode + ring indicator)
```

Key source directories:

| Directory | Purpose |
|-----------|---------|
| `src/views/` | Tree data providers for sidebar panels |
| `src/webviews/` | Rich webview panels (HTML/CSS/JS in TypeScript) |
| `src/services/` | Transport layer, typed clients, caching |
| `src/mockBackend/` | Deterministic test data for development |
| `src/language/` | Diagnostics, code actions, completion |
| `src/test/` | Test suites mirroring source structure |

## Mock vs Live Backend

The `agent-os.backend.mode` setting controls which data provider is used:

- **"mock"** (default) -- Uses `MockSLOBackend`, `MockTopologyBackend`, and `MockPolicyBackend`. Returns deterministic sample data. No Python required.
- **"local"** -- Spawns the Python bridge as a subprocess. Queries the real Agent OS, Agent SRE, and AgentMesh packages installed in the local environment.

Auto-fallback: If `"local"` mode fails to connect (Python not found, packages missing, or bridge errors), the extension falls back to mock data and logs a warning to the Output panel.

## Bridge Protocol

The Python bridge communicates over stdin/stdout using newline-delimited JSON.

**Request format** (extension to bridge):

```json
{"module": "slo", "command": "get_dashboard", "args": {"window": "1h"}}
```

**Response format** (bridge to extension):

```json
{"ok": true, "data": {"availability": 99.95, "latency_p50": 12}, "durationMs": 42}
```

Error responses:

```json
{"ok": false, "error": "PolicyEvaluator not initialized", "durationMs": 5}
```

Protocol details:
- Timeout: 5 seconds per request
- One process spawned per query (no persistent connection)
- Bridge entry point: `python -m agent_os.extensions.vscode_bridge --json`

## Adding a New Data Source

1. **Define raw types** in `src/services/rawApiTypes.ts` -- Add a TypeScript interface matching the bridge JSON response shape.

2. **Add a translator** -- Create a function that maps the raw API type to your view model type, handling missing fields and defaults.

3. **Create a client** in `src/services/` -- Implement a typed client class that uses `SubprocessTransport` to call the bridge with the appropriate module and command.

4. **Create a mock backend** in `src/mockBackend/` -- Return deterministic sample data matching the raw type interface.

5. **Wire into providerFactory** -- Register both the mock backend and the live client, keyed by `agent-os.backend.mode`.

6. **Add tests** -- Use the `FakeTransport` pattern (see existing service tests) to test the client without spawning a real subprocess.

## Testing

Run the full test suite:

```bash
npm test
```

Test files live under `src/test/` and mirror the source directory structure:

```
src/test/
  services/       -- Transport and client tests (FakeTransport pattern)
  mockBackend/    -- Mock data shape validation
  views/          -- TreeDataProvider tests
  webviews/       -- Webview panel logic tests
  language/       -- Diagnostic and code action tests
```

The **FakeTransport** pattern: Service tests inject a `FakeTransport` that returns canned JSON responses, allowing client logic to be tested without subprocess overhead.

## Webview Development

Webview panels render HTML inside VS Code. Key constraints:

- **Content Security Policy (CSP)**: Every webview sets a CSP with a unique nonce. Scripts and styles must include the nonce attribute to load.
- **Theme tokens**: Use `var(--vscode-editor-background)`, `var(--vscode-foreground)`, and other VS Code CSS custom properties for light/dark theme compatibility. Never hardcode colors.
- **Message protocol**: The webview and extension host communicate via `postMessage`. The webview calls `vscode.postMessage({type: "...", data: ...})` and the extension host listens with `panel.webview.onDidReceiveMessage`.

Webview files are organized per panel:

```
src/webviews/governanceHub/
  GovernanceHubPanel.ts       -- Panel lifecycle (create, dispose, update)
  GovernanceHubScript.ts      -- Client-side JavaScript (string template)
  GovernanceHubStyles.ts      -- CSS (string template using theme tokens)
  GovernanceHubViewProvider.ts -- WebviewViewProvider for sidebar
  governanceHubTypes.ts       -- Shared type definitions
```

To iterate on webview UI, use `npm run watch` and reload the Extension Development Host window (`Ctrl+Shift+P` then "Developer: Reload Window"). Webview content refreshes on each panel open.

## Contributing

Run `npm run lint` before committing. Use conventional commit prefixes (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`). See the root `CONTRIBUTING.md` for full guidelines.

## Packaging

To create a distributable `.vsix` file:

```bash
npm run package
```

This runs the TypeScript compiler, bundles assets, and produces a `.vsix` in the extension root directory. Install it manually with:

```bash
code --install-extension agent-os-vscode-*.vsix
```
