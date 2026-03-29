# Changelog

All notable changes to the Agent OS VS Code extension will be documented in this file.

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
- CMVK uses mock responses (real API coming in v0.2.0)
- Inline completion interception is read-only (doesn't block)
- Limited to text change detection for now
