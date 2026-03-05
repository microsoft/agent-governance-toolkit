# Changelog

All notable changes to the AgentOS MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-30

### Added - Initial Release 🎉

#### MCP Tools (10 total)
- **`create_agent`** - Create agents from natural language descriptions
  - Automatic policy recommendations based on task
  - Support for Python, TypeScript, JavaScript, Go
  - Cron schedule support for recurring agents
  
- **`attach_policy`** - Attach safety policies to agents
  - Policy conflict detection
  - Template-based and custom policies
  - Validation before attachment
  
- **`test_agent`** - Dry-run testing before deployment
  - Scenario-based testing
  - Policy violation detection
  - Resource usage estimation
  
- **`deploy_agent`** - Deploy agents to local or cloud
  - Local execution support
  - Cloud deployment (requires API key)
  - Approval workflow integration
  
- **`get_agent_status`** - Get agent status and metrics
  - Execution metrics (success rate, failures)
  - Active policy list
  - Pending approval status
  - Recent activity logs
  
- **`list_templates`** - Browse template library
  - Filter by category, search, framework
  - Agent and policy templates
  - Example prompts for each template
  
- **`request_approval`** - Human-in-the-loop approvals
  - Risk-based approval requirements
  - Multi-party approval for critical actions
  - Expiration handling
  
- **`audit_log`** - Query audit trail
  - Time range filtering
  - Action type filtering
  - Summary statistics
  - Export capability
  
- **`create_policy`** - Create custom policies
  - Natural language to policy rules
  - Extend existing templates
  - Category and framework tagging
  
- **`check_compliance`** - Compliance framework validation
  - SOC 2 Type II controls
  - GDPR requirements
  - HIPAA privacy rules
  - PCI DSS security standards
  - CCPA, NIST, ISO 27001, FedRAMP

#### Built-in Policies (6)
- **PII Protection** - Blocks access to PII fields, auto-redacts emails
- **Rate Limiting** - API and database query rate limits
- **Cost Control** - Daily budget enforcement, expensive operation approval
- **Data Deletion Safety** - Blocks mass deletes, requires backup
- **Secrets Protection** - Blocks hardcoded secrets, redacts from logs
- **Human Review Required** - Approval for external communications, financial transactions

#### Policy Templates (6)
- **GDPR Compliance** - Data minimization, consent, right to erasure
- **SOC 2 Security** - Access logging, change management, encryption
- **HIPAA Healthcare** - PHI protection, minimum necessary, audit controls
- **PCI DSS Payments** - Card data protection, CVV blocking, encryption
- **Read-Only Access** - Database read-only enforcement
- **Production Safety** - Deployment approval, rollback requirements

#### Agent Templates (10)
- Data Processor
- Email Assistant
- Database Analyst
- File Organizer
- Backup Agent
- Web Scraper
- Slack Bot
- API Monitor
- Report Generator
- Content Moderator

#### MCP Prompts (6)
- **create_safe_agent** - Guided agent creation with policies
- **compliance_setup** - Configure agents for compliance frameworks
- **troubleshoot_agent** - Diagnose and fix agent issues
- **batch_policy_update** - Apply policies across multiple agents
- **security_review** - Comprehensive security assessment
- **onboarding** - Introduction for new users

#### Core Services
- **AgentManager** - Agent lifecycle management
- **PolicyEngine** - Real-time policy evaluation
- **ApprovalWorkflow** - Human-in-the-loop approvals
- **AuditLogger** - Immutable audit trail (JSONL format)
- **TemplateLibrary** - Agent and policy templates

#### Infrastructure
- TypeScript/Node.js implementation
- MCP SDK integration (`@modelcontextprotocol/sdk`)
- Stdio transport for Claude Desktop
- Local file-based storage
- Winston logging

### Security
- All actions validated against policies before execution
- Sensitive data automatically redacted from logs
- Secrets never stored in plain text
- Complete audit trail for compliance
- Risk-based approval workflows

### Performance Targets
- MCP server startup: <2 seconds
- Tool response time: <500ms (p95)
- Memory footprint: <100MB
- Policy evaluation: <50ms

---

## [Unreleased]

### Planned
- HTTP transport mode for development
- Cloud backend integration
- Real-time agent execution monitoring
- WebSocket-based notifications
- Multi-tenant organization support
- Custom compliance framework builder

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2026-01-30 | Initial release with 10 tools, 6 policies, 10 agent templates |

---

**Links:**
- [GitHub Repository](https://github.com/microsoft/agent-governance-toolkit)
- [npm Package](https://www.npmjs.com/package/@agentos/mcp-server)
- [MCP Specification](https://modelcontextprotocol.io)
