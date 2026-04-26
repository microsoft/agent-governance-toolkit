// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * AgentOS MCP Server - Main Entry Point
 */

export { AgentOSMCPServer, ServerConfig } from './server.js';
export * from './types/index.js';

// Re-export services for programmatic use
export { AgentManager } from './services/agent-manager.js';
export { PolicyEngine } from './services/policy-engine.js';
export { ApprovalWorkflow } from './services/approval-workflow.js';
export { AuditLogger } from './services/audit-logger.js';
export { TemplateLibrary } from './services/template-library.js';
