// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * AgentOS MCP Server - Core Server Implementation
 * 
 * Exposes AgentOS capabilities through Model Context Protocol:
 * - 10 Tools for agent lifecycle management
 * - Resources for VFS and audit logs
 * - Prompts for guided agent creation
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { createLogger, format, transports, Logger } from 'winston';

import { AgentManager } from './services/agent-manager.js';
import { PolicyEngine } from './services/policy-engine.js';
import { ApprovalWorkflow } from './services/approval-workflow.js';
import { AuditLogger } from './services/audit-logger.js';
import { TemplateLibrary } from './services/template-library.js';

import { createAgentTool } from './tools/create-agent.js';
import { attachPolicyTool } from './tools/attach-policy.js';
import { testAgentTool } from './tools/test-agent.js';
import { deployAgentTool } from './tools/deploy-agent.js';
import { getAgentStatusTool } from './tools/get-agent-status.js';
import { listTemplatesTool } from './tools/list-templates.js';
import { requestApprovalTool } from './tools/request-approval.js';
import { auditLogTool } from './tools/audit-log.js';
import { createPolicyTool } from './tools/create-policy.js';
import { checkComplianceTool } from './tools/check-compliance.js';

import { PROMPTS } from './prompts/index.js';

export interface ServerConfig {
  policyMode: 'strict' | 'permissive';
  apiKey?: string;
  dataDir: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

export interface ServiceContext {
  agentManager: AgentManager;
  policyEngine: PolicyEngine;
  approvalWorkflow: ApprovalWorkflow;
  auditLogger: AuditLogger;
  templateLibrary: TemplateLibrary;
  logger: Logger;
  config: ServerConfig;
}

export class AgentOSMCPServer {
  private server: Server;
  private logger: Logger;
  private context: ServiceContext;
  
  static readonly SERVER_NAME = 'agentos';
  static readonly SERVER_VERSION = '1.0.0';
  
  constructor(config: ServerConfig) {
    // Initialize logger
    this.logger = createLogger({
      level: config.logLevel,
      format: format.combine(
        format.timestamp(),
        format.json()
      ),
      transports: [
        new transports.Console({
          format: format.combine(
            format.colorize(),
            format.simple()
          ),
          stderrLevels: ['error', 'warn', 'info', 'debug']
        })
      ]
    });
    
    // Initialize services
    const agentManager = new AgentManager(config.dataDir);
    const policyEngine = new PolicyEngine(config.policyMode);
    const approvalWorkflow = new ApprovalWorkflow(config.dataDir);
    const auditLogger = new AuditLogger(config.dataDir);
    const templateLibrary = new TemplateLibrary();
    
    this.context = {
      agentManager,
      policyEngine,
      approvalWorkflow,
      auditLogger,
      templateLibrary,
      logger: this.logger,
      config,
    };
    
    // Initialize MCP server
    this.server = new Server(
      {
        name: AgentOSMCPServer.SERVER_NAME,
        version: AgentOSMCPServer.SERVER_VERSION,
      },
      {
        capabilities: {
          tools: {},
          resources: {},
          prompts: {},
        },
      }
    );
    
    this.setupHandlers();
  }
  
  private setupHandlers(): void {
    // ==========================================================================
    // Tools Handler
    // ==========================================================================
    
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          createAgentTool.definition,
          attachPolicyTool.definition,
          testAgentTool.definition,
          deployAgentTool.definition,
          getAgentStatusTool.definition,
          listTemplatesTool.definition,
          requestApprovalTool.definition,
          auditLogTool.definition,
          createPolicyTool.definition,
          checkComplianceTool.definition,
        ],
      };
    });
    
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      
      this.logger.info(`Tool called: ${name}`, { args });
      
      try {
        let result: unknown;
        
        switch (name) {
          case 'create_agent':
            result = await createAgentTool.execute(args, this.context);
            break;
          case 'attach_policy':
            result = await attachPolicyTool.execute(args, this.context);
            break;
          case 'test_agent':
            result = await testAgentTool.execute(args, this.context);
            break;
          case 'deploy_agent':
            result = await deployAgentTool.execute(args, this.context);
            break;
          case 'get_agent_status':
            result = await getAgentStatusTool.execute(args, this.context);
            break;
          case 'list_templates':
            result = await listTemplatesTool.execute(args, this.context);
            break;
          case 'request_approval':
            result = await requestApprovalTool.execute(args, this.context);
            break;
          case 'audit_log':
            result = await auditLogTool.execute(args, this.context);
            break;
          case 'create_policy':
            result = await createPolicyTool.execute(args, this.context);
            break;
          case 'check_compliance':
            result = await checkComplianceTool.execute(args, this.context);
            break;
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
        
        // Log to audit trail
        await this.context.auditLogger.log({
          action: `tool:${name}`,
          agentId: (args as Record<string, unknown>)?.agentId as string || 'system',
          outcome: 'SUCCESS',
          metadata: { args, result },
        });
        
        return {
          content: [
            {
              type: 'text',
              text: typeof result === 'string' ? result : JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (error) {
        this.logger.error(`Tool ${name} failed`, { error });
        
        // Log failure to audit trail
        await this.context.auditLogger.log({
          action: `tool:${name}`,
          agentId: (args as Record<string, unknown>)?.agentId as string || 'system',
          outcome: 'FAILURE',
          errorMessage: error instanceof Error ? error.message : String(error),
          metadata: { args },
        });
        
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    });
    
    // ==========================================================================
    // Resources Handler
    // ==========================================================================
    
    this.server.setRequestHandler(ListResourcesRequestSchema, async () => {
      const agents = await this.context.agentManager.listAgents();
      
      return {
        resources: [
          {
            uri: 'agentos://agents',
            name: 'Agents Registry',
            description: 'List of all registered agents',
            mimeType: 'application/json',
          },
          {
            uri: 'agentos://policies',
            name: 'Policy Library',
            description: 'Available policy templates',
            mimeType: 'application/json',
          },
          {
            uri: 'agentos://audit',
            name: 'Audit Log',
            description: 'System-wide audit trail',
            mimeType: 'application/json',
          },
          ...agents.map((agent) => ({
            uri: `agentos://agents/${agent.id}`,
            name: agent.name,
            description: agent.description,
            mimeType: 'application/json',
          })),
        ],
      };
    });
    
    this.server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const { uri } = request.params;
      
      this.logger.info(`Resource read: ${uri}`);
      
      try {
        let content: unknown;
        
        if (uri === 'agentos://agents') {
          content = await this.context.agentManager.listAgents();
        } else if (uri === 'agentos://policies') {
          content = this.context.templateLibrary.listPolicyTemplates();
        } else if (uri === 'agentos://audit') {
          content = await this.context.auditLogger.getRecentLogs(100);
        } else if (uri.startsWith('agentos://agents/')) {
          const agentId = uri.replace('agentos://agents/', '');
          content = await this.context.agentManager.getAgent(agentId);
        } else {
          throw new Error(`Unknown resource: ${uri}`);
        }
        
        return {
          contents: [
            {
              uri,
              mimeType: 'application/json',
              text: JSON.stringify(content, null, 2),
            },
          ],
        };
      } catch (error) {
        this.logger.error(`Resource ${uri} read failed`, { error });
        throw error;
      }
    });
    
    // ==========================================================================
    // Prompts Handler
    // ==========================================================================
    
    this.server.setRequestHandler(ListPromptsRequestSchema, async () => {
      return {
        prompts: Object.values(PROMPTS).map((p) => ({
          name: p.name,
          description: p.description,
          arguments: p.arguments,
        })),
      };
    });
    
    this.server.setRequestHandler(GetPromptRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      
      const prompt = PROMPTS[name];
      if (!prompt) {
        throw new Error(`Unknown prompt: ${name}`);
      }
      
      // Fill in template with arguments
      let text = prompt.template;
      for (const arg of prompt.arguments || []) {
        const value = args?.[arg.name] || '';
        text = text.replace(new RegExp(`\\{${arg.name}\\}`, 'g'), String(value));
      }
      
      return {
        description: prompt.description,
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text,
            },
          },
        ],
      };
    });
  }
  
  /**
   * Run server in stdio mode for Claude Desktop.
   */
  async runStdio(): Promise<void> {
    this.logger.info('Starting AgentOS MCP Server in stdio mode');
    
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    
    this.logger.info('AgentOS MCP Server connected via stdio');
  }
  
  /**
   * Run server in HTTP mode for development/testing.
   */
  async runHttp(port: number): Promise<void> {
    this.logger.info(`Starting AgentOS MCP Server in HTTP mode on port ${port}`);
    
    // Note: HTTP transport would be implemented here
    // For now, just log that it's not implemented
    this.logger.warn('HTTP mode not yet implemented. Use stdio mode for Claude Desktop.');
    
    // Keep process alive
    await new Promise(() => {});
  }
}
