# Changelog

## 0.1.0 (2026-04-11)

### Added
- Initial release of agent-discovery package
- `DiscoveredAgent` model with evidence tracking and confidence scoring
- `AgentInventory` with deduplication and merge-key correlation
- Scanner plugin architecture with `BaseScanner` ABC
- `ProcessScanner` — detect AI agent processes on local host
- `GitHubScanner` — find agent configurations in GitHub repositories
- `ConfigScanner` — scan filesystem for agent config artifacts
- `Reconciler` with `RegistryProvider` interface for shadow agent detection
- `RiskScorer` for unregistered/ungoverned agent risk assessment
- Click CLI: `agent-discovery scan`, `inventory`, `reconcile`
- Comprehensive test suite
