# Plan: Governance Visualization Enhancement

## Tribunal Remediation (Entry #67)

This plan has been amended to address VETO findings from Gate Tribunal Entry #67:

| # | Violation | Remediation |
|---|-----------|-------------|
| 1 | Security: Credential validation unspecified | Added `validateCredentials()` with zero-trust (validate-every-upload) |
| 2 | Ghost UI: Export button handler missing | Added export handler to `GovernanceHubScript.ts` spec |
| 3 | Dependency: Chart.js bundled without justification | Justified: interactive reports need zoom/tooltips, 200KB acceptable |
| 4 | Types: `TopologySnapshot` undefined | Replaced with existing types |

---

## Open Questions

- Should the local dev server run on a fixed port (e.g., 9876) or find an available port dynamically?

---

## Phase 1: Governance Hub (Sidebar + Panel)

### Affected Files

- `src/webviews/governanceHub/GovernanceHubTemplate.ts` - HTML template with tabbed layout
- `src/webviews/governanceHub/GovernanceHubScript.ts` - Tab switching, data binding, message handling
- `src/webviews/governanceHub/GovernanceHubPanel.ts` - Panel lifecycle (singleton pattern)
- `src/webviews/governanceHub/GovernanceHubViewProvider.ts` - Sidebar webview provider
- `src/extension.ts` - Register sidebar webview, panel command, settings listener
- `package.json` - Add `agentOS.governanceHub.tabs` configuration

### Changes

**GovernanceHubTemplate.ts**
```typescript
export function renderGovernanceHub(nonce: string, cspSource: string, config: HubConfig): string
```
- Compose header with status indicator and action buttons (refresh, open in browser, export)
- Render tab bar from `config.enabledTabs` array
- Embed SLO content (reuse metric cards, mini gauges from existing styles)
- Embed Topology content (simplified node list for sidebar, full SVG for panel)
- Embed Audit content (scrollable event list with icons)
- Footer with connection status and last-updated timestamp

**GovernanceHubScript.ts**
```typescript
export function governanceHubScript(nonce: string): string
```
- Tab switching via data attributes, persist active tab to localStorage
- Message handler: `sloUpdate`, `topologyUpdate`, `auditUpdate`, `configUpdate`
- Refresh button posts `{ type: 'refresh' }` to extension
- Open in browser button posts `{ type: 'openInBrowser' }`
- **Export button posts `{ type: 'export' }` to extension** *(Remediation #2)*

**GovernanceHubPanel.ts**
- Singleton pattern matching `SLODashboardPanel`
- Accept `SLODataProvider`, `AgentTopologyDataProvider`, `AuditLogger`
- Unified refresh interval (10s) pushes all three data sources
- Handle `openInBrowser` message by invoking `agent-os.openGovernanceInBrowser`
- Handle `export` message by invoking `agent-os.exportReport`

**GovernanceHubViewProvider.ts**
```typescript
export class GovernanceHubViewProvider implements vscode.WebviewViewProvider {
    resolveWebviewView(webviewView: vscode.WebviewView): void
}
```
- Implements sidebar webview (compact mode)
- Shares data providers with panel
- Listens to `onDidChangeVisibility` to pause/resume updates

**package.json configuration**
```json
"agentOS.governanceHub.tabs": {
    "type": "array",
    "default": ["slo", "topology", "audit"],
    "items": { "enum": ["slo", "topology", "audit", "policies"] }
}
```

**extension.ts**
- Register `GovernanceHubViewProvider` for `agent-os.governanceHub` view
- Register `agent-os.showGovernanceHub` command to open panel
- Pass shared data providers to both sidebar and panel

### Unit Tests

- `test/webviews/governanceHub.test.ts`
  - Tab rendering respects `config.enabledTabs` order and presence
  - Tab switching updates `active` class and content visibility
  - Message posting from buttons triggers correct extension commands (refresh, openInBrowser, export)
  - Config change reloads template with new tab set

---

## Phase 2: Local Dev Server (Browser Experience)

### Affected Files

- `src/server/GovernanceServer.ts` - Express server with WebSocket
- `src/server/browserTemplate.ts` - Enhanced HTML with D3.js, Chart.js
- `src/server/serverTypes.ts` - Port config, client connection types
- `src/extension.ts` - Register open-in-browser commands, manage server lifecycle
- `package.json` - Add `express`, `ws` as dependencies

### Changes

**GovernanceServer.ts**
```typescript
export class GovernanceServer {
    constructor(
        private sloProvider: SLODataProvider,
        private topologyProvider: AgentTopologyDataProvider,
        private auditLogger: AuditLogger
    )
    start(port?: number): Promise<number>  // Returns actual port
    stop(): Promise<void>
    getUrl(): string
}
```
- Express serves static HTML from `browserTemplate.ts`
- WebSocket broadcasts data updates to all connected clients
- Graceful shutdown on extension deactivate
- Single server instance shared across all "open in browser" commands

**browserTemplate.ts**
```typescript
export function renderBrowserDashboard(): string
```
- Full HTML document (no CSP restrictions)
- Include D3.js via CDN for force-directed topology graph
- Include Chart.js via CDN for SLO sparklines and gauges
- WebSocket client reconnects on disconnect
- Responsive layout with collapsible sidebar

**extension.ts commands**
- `agent-os.openSLOInBrowser` - Start server if needed, open browser to `/#slo`
- `agent-os.openTopologyInBrowser` - Open browser to `/#topology`
- `agent-os.openGovernanceInBrowser` - Open browser to `/`

### Unit Tests

- `test/server/governanceServer.test.ts`
  - Server starts on available port when default is occupied
  - WebSocket broadcasts SLO updates to multiple clients
  - Server stops cleanly, port is released
  - Reconnecting client receives latest state

---

## Phase 3: Shareable Reports & Observability

### Affected Files

- `src/export/ReportGenerator.ts` - Static HTML snapshot generator
- `src/export/StorageProvider.ts` - Abstract storage interface with credential validation
- `src/export/CredentialError.ts` - Custom error type for credential failures
- `src/export/S3StorageProvider.ts` - AWS S3 implementation
- `src/export/AzureBlobStorageProvider.ts` - Azure Blob implementation
- `src/export/LocalStorageProvider.ts` - Local file export
- `src/observability/MetricsExporter.ts` - OpenTelemetry-compatible export
- `src/extension.ts` - Register export commands
- `package.json` - Add `agentOS.export.storageProvider` setting

### Changes

**ReportGenerator.ts**
```typescript
export class ReportGenerator {
    generate(
        sloSnapshot: SLOSnapshot,
        agents: AgentNode[],
        bridges: BridgeStatus[],
        delegations: DelegationChain[],
        auditEvents: AuditEntry[],
        timeRange: { start: Date; end: Date }
    ): string  // Returns self-contained HTML
}
```
*(Remediation #4: Uses existing types instead of undefined `TopologySnapshot`)*

- Embeds all data as JSON in script tag
- **Includes Chart.js bundled (~200KB)** — justified for interactive report features:
  - Zoom/pan on sparkline charts
  - Hover tooltips on data points
  - Responsive resizing
  - Print-friendly fallback rendering
  *(Remediation #3: Explicit justification for dependency)*
- Timestamp watermark and generation metadata
- Print-friendly CSS media query

**CredentialError.ts**
```typescript
export class CredentialError extends Error {
    constructor(
        message: string,
        public readonly provider: 's3' | 'azure',
        public readonly reason: 'missing' | 'invalid' | 'expired'
    ) {
        super(message);
        this.name = 'CredentialError';
    }
}
```

**StorageProvider interface** *(Remediation #1: Zero-trust credential validation)*
```typescript
export interface StorageProvider {
    /**
     * Validate credentials before upload. Called on every upload (zero-trust).
     * @throws CredentialError if credentials are missing, invalid, or expired
     */
    validateCredentials(): Promise<void>

    /**
     * Upload report to storage. Caller must call validateCredentials() first.
     */
    upload(html: string, filename: string): Promise<{ url: string; expiresAt: Date }>

    /**
     * Configure provider with settings from VS Code configuration.
     */
    configure(settings: Record<string, string>): void
}
```

**S3StorageProvider**
```typescript
export class S3StorageProvider implements StorageProvider {
    async validateCredentials(): Promise<void> {
        const creds = await this.getCredentialsFromSecretStorage();
        if (!creds.accessKeyId || !creds.secretAccessKey) {
            throw new CredentialError(
                'AWS credentials not configured',
                's3',
                'missing'
            );
        }
        // Verify credentials with lightweight S3 API call (e.g., GetCallerIdentity equivalent)
        try {
            await this.s3Client.headBucket({ Bucket: this.bucket });
        } catch (e) {
            if (e.code === 'ExpiredToken') {
                throw new CredentialError('AWS credentials expired', 's3', 'expired');
            }
            throw new CredentialError('AWS credentials invalid', 's3', 'invalid');
        }
    }
}
```

**AzureBlobStorageProvider**
```typescript
export class AzureBlobStorageProvider implements StorageProvider {
    async validateCredentials(): Promise<void> {
        const connString = await this.getConnectionStringFromSecretStorage();
        if (!connString) {
            throw new CredentialError(
                'Azure connection string not configured',
                'azure',
                'missing'
            );
        }
        // Verify credentials with lightweight Azure API call
        try {
            await this.containerClient.exists();
        } catch (e) {
            if (e.code === 'AuthenticationFailed') {
                throw new CredentialError('Azure credentials invalid', 'azure', 'invalid');
            }
            throw new CredentialError('Azure credentials expired', 'azure', 'expired');
        }
    }
}
```

**LocalStorageProvider**
```typescript
export class LocalStorageProvider implements StorageProvider {
    async validateCredentials(): Promise<void> {
        // Local storage has no credentials — always valid
        // Validate write permissions to configured directory
        const testPath = path.join(this.outputDir, '.write-test');
        try {
            await fs.writeFile(testPath, '');
            await fs.unlink(testPath);
        } catch {
            throw new CredentialError(
                `Cannot write to ${this.outputDir}`,
                'local' as any,
                'invalid'
            );
        }
    }
}
```

**extension.ts export command** *(Zero-trust usage pattern)*
```typescript
vscode.commands.registerCommand('agent-os.exportReport', async () => {
    const provider = getConfiguredStorageProvider();

    // Zero-trust: validate on every export
    try {
        await provider.validateCredentials();
    } catch (e) {
        if (e instanceof CredentialError) {
            const action = await vscode.window.showErrorMessage(
                `Storage credentials ${e.reason}: ${e.message}`,
                'Configure'
            );
            if (action === 'Configure') {
                vscode.commands.executeCommand('workbench.action.openSettings',
                    `agentOS.export.${e.provider}`);
            }
            return;
        }
        throw e;
    }

    // Credentials valid — proceed with export
    const report = reportGenerator.generate(sloSnapshot, agents, bridges, delegations, auditEvents, timeRange);
    const result = await provider.upload(report, `governance-report-${Date.now()}.html`);

    vscode.window.showInformationMessage(
        `Report uploaded: ${result.url}`,
        'Open'
    ).then(action => {
        if (action === 'Open') {
            vscode.env.openExternal(vscode.Uri.parse(result.url));
        }
    });
});
```

**MetricsExporter.ts**
```typescript
export class MetricsExporter {
    constructor(private endpoint: string)
    push(metrics: GovernanceMetrics): Promise<void>
}

interface GovernanceMetrics {
    availability: number
    latencyP99: number
    compliancePercent: number
    trustScoreMean: number
    agentCount: number
    violationsToday: number
    timestamp: string
}
```
- POST to configured endpoint in OpenTelemetry line protocol or JSON
- Batch metrics if endpoint supports it
- Retry with exponential backoff

**package.json settings**
```json
"agentOS.export.storageProvider": {
    "enum": ["local", "s3", "azure"],
    "default": "local"
},
"agentOS.observability.endpoint": {
    "type": "string",
    "description": "URL to push governance metrics"
}
```

### Unit Tests

- `test/export/reportGenerator.test.ts`
  - Generated HTML is valid and self-contained
  - Data is correctly embedded and accessible via JS
  - Time range filters audit events correctly
  - Chart.js is bundled and functional

- `test/export/credentialError.test.ts`
  - Error contains provider and reason
  - Error message is descriptive

- `test/export/storageProviders.test.ts`
  - S3 provider validates credentials before upload
  - S3 provider throws CredentialError on missing credentials
  - S3 provider throws CredentialError on invalid credentials
  - S3 provider throws CredentialError on expired credentials
  - S3 provider generates valid pre-signed URL after validation
  - Azure provider validates credentials before upload
  - Azure provider throws CredentialError on missing connection string
  - Azure provider generates valid SAS URL after validation
  - Local provider validates write permissions
  - Local provider throws on unwritable directory

- `test/observability/metricsExporter.test.ts`
  - Metrics are formatted correctly for OpenTelemetry
  - Failed push retries with backoff
  - Batch mode groups multiple snapshots
