# Changelog

All notable changes to the Agent OS VS Code extension will be documented in this file.

## [1.1.0] - 2026-03-25

### Security
- Rate limiting added to GovernanceServer (100 requests/minute per client)
- Session token authentication for WebSocket connections
- Bundled D3.js v7.8.5 and Chart.js v4.4.1 locally (removed CDN dependency on cdn.jsdelivr.net)
- Eliminated innerHTML XSS vectors via shared `escapeHtml` utility across all legacy panels
- Pinned axios (1.13.6) and ws (8.20.0) to exact versions for reproducible builds
- Python path validation: rejects shell metacharacters before subprocess spawn
- axios retained over VS Code built-in fetch: provides timeout, maxContentLength, and maxRedirects guards not available in built-in fetch API

### Removed
- `S3StorageProvider` - Cloud export to AWS S3 (stub, never implemented)
- `AzureBlobStorageProvider` - Cloud export to Azure Blob Storage (stub, never implemented)
- Backend service layer (out of scope for this release)

### Added
- Live governance data: auto-detects and starts agent-failsafe REST server on activation
- Auto-install: prompts to install agent-failsafe[server] from PyPI if not found
- Connection indicator in status bar: Live, Stale, Disconnected
- Input validation on all REST responses with type checking, size caps, string truncation
- Loopback enforcement: governance endpoint restricted to 127.0.0.1/localhost/::1
- Governance Hub: Unified sidebar webview with SLO, topology, and audit tabs
- SLO Dashboard: Rich webview panel with availability, latency, compliance, and trust score metrics
- Agent Topology: Force-directed graph panel showing agent mesh, trust rings, and bridges
- Browser experience: Local dev server serves governance dashboard in external browser
- Governance status bar: Mode indicator, execution ring, connection status
- Policy diagnostics: Real-time governance rule validation with code actions
- Local report export: Self-contained HTML governance report
- Metrics exporter: Push dashboard metrics to observability endpoints
- 3-slot configurable sidebar replacing 8 stacked tree views with React + Tailwind panel system
- Panel picker overlay for drag-and-drop slot configuration
- GovernanceStore: centralized state management with JSON deduplication and visibility gating
- Event-driven refresh: sidebar reacts instantly to data changes via vscode.EventEmitter, 30s heartbeat safety net
- Scanning mode: 4-second auto-rotation through sidebar slots with hover/focus pause and prefers-reduced-motion support
- Attention toggle: Manual/Auto switch — manual locks to user config, auto enables scanning and priority reordering
- Priority engine: ranks panels by health urgency (critical > warning > healthy > unknown), auto-reorders slots in auto mode
- Per-panel latency isolation: slow data sources automatically split to offset refresh cadence with staleness indicator

### Changed
- SLO Dashboard, Agent Topology, and Governance Hub panels migrated from HTML template strings to React + Tailwind
- Panel host classes replaced with shared `panelHost.ts` factory (280 lines of duplication removed)
- GovernanceStore data fetches parallelized via Promise.all (latency: sum of all sources → max)
- ForceGraph DOM rendering optimized (build elements once, update positions per frame)
- Refresh commands (`refreshSLO`, `refreshTopology`) now route through GovernanceStore
- SidebarProvider refactored from monolithic 213-line data owner to 133-line thin webview bridge
- Sidebar polling replaced with event-driven architecture — LiveSREClient and AuditLogger emit change events

### Removed
- Legacy tree view commands: `showSLODashboard`, `showAgentTopology` (replaced by `showSLOWebview`, `showTopologyGraph`)
- Legacy HTML template panels: SLODashboardPanel, TopologyGraphPanel, GovernanceHubPanel (replaced by React detail panels)
- Legacy hub formatters: hubSLOFormatter, hubTopologyFormatter, hubAuditFormatter, hubAuditHelpers

### Fixed
- Path traversal vulnerability in LocalStorageProvider (export directory escape)
- KernelDebuggerProvider 1-second timer never disposed (memory/CPU leak)
- GovernanceStore detail subscriptions leaked empty Sets on dispose
- Panel host title HTML injection vulnerability (now stripped)

## [1.0.1] - 2026-01-29

### Fixed
- Workflow Designer: Delete button now works correctly on nodes
- Workflow Designer: Code generation handles empty workflows gracefully
- Workflow Designer: TypeScript and Go exports have proper type annotations

## [1.0.0] - 2026-01-28

### Added - GA Release 🎉
- **Policy Management Studio**: Visual policy editor with templates
  - 5 built-in templates (Strict Security, SOC 2, GDPR, Development, Rate Limiting)
  - Real-time validation
  - Import/Export in YAML format
  
- **Workflow Designer**: Drag-and-drop agent workflow builder
  - 4 node types (Action, Condition, Loop, Parallel)
  - 8 action types (file_read, http_request, llm_call, etc.)
  - Code export to Python, TypeScript, Go
  - Policy attachment at node level
  
- **Metrics Dashboard**: Real-time monitoring
  - Policy check statistics
  - Activity feed with timestamps
  - Export to CSV/JSON
  
- **IntelliSense & Snippets**
  - 14 code snippets for Python, TypeScript, YAML
  - Context-aware completions for AgentOS APIs
  - Hover documentation
  
- **Security Diagnostics**
  - Real-time vulnerability detection
  - 13 security rules (os.system, eval, exec, etc.)
  - Quick fixes available
  
- **Enterprise Features**
  - SSO integration (Azure AD, Okta, Google, GitHub)
  - Role-based access control (5 roles)
  - CI/CD integration (GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, CircleCI)
  - Compliance frameworks (SOC 2, GDPR, HIPAA, PCI DSS)

- **Onboarding Experience**
  - Interactive getting started guide
  - Progress tracking
  - First agent tutorial

### Changed
- Upgraded extension architecture for GA stability
- Improved WebView performance

## [0.1.0] - 2026-01-27

### Added
- Initial release
- Real-time code safety analysis
- Policy engine with 5 policy categories:
  - Destructive SQL (DROP, DELETE, TRUNCATE)
  - File deletes (rm -rf, unlink, rmtree)
  - Secret exposure (API keys, passwords, tokens)
  - Privilege escalation (sudo, chmod 777)
  - Unsafe network calls (HTTP instead of HTTPS)
- CMVK multi-model code review (mock implementation for demo)
- Audit log sidebar with recent activity
- Policies view showing active policies
- Statistics view with daily/weekly counts
- Status bar with real-time protection indicator
- Team policy sharing via `.vscode/agent-os.json`
- Export audit log to JSON
- Custom rule support

### Known Limitations
- CMVK uses mock responses (real API integration planned)
- Inline completion interception is read-only (doesn't block)
- Limited to text change detection for now
