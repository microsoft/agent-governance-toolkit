# Changelog

All notable changes to the Agent OS Cursor extension will be documented in this file.

## [0.1.0] - 2026-01-27

### Added
- Initial release for Cursor IDE
- **Cursor-Specific Features:**
  - "Ask Cursor for Alternative" - Get safe code suggestions from Cursor AI
  - Cursor Composer interception and validation
  - "Cursor + Agent OS" status bar branding
- **Enterprise Features:**
  - SOC 2 compliance mode with enhanced audit trails
  - Approval workflows for high-risk operations
  - Webhook streaming to enterprise SIEM systems
  - Enterprise info panel
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
- Team policy sharing via `.cursor/agent-os.json` or `.vscode/agent-os.json`
- Export audit log to JSON
- Custom rule support

### Marketing
- "The AI IDE with a Safety Kernel"
- "Cursor won't delete your production code"
- Enterprise appeal: SOC 2 compliant out-of-box

### Known Limitations
- CMVK uses mock responses (real API coming in v0.2.0)
- Inline completion interception is read-only (doesn't block)
- Limited to text change detection for now
- Cursor Chat integration requires manual copy/paste
