// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent Manager Service
 * 
 * Handles agent lifecycle: creation, storage, retrieval, and status management.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import {
  AgentConfig,
  AgentSpec,
  AgentStatus,
  CreateAgentInput,
} from '../types/index.js';

export class AgentManager {
  private dataDir: string;
  private agentsDir: string;
  
  constructor(dataDir: string) {
    this.dataDir = dataDir;
    this.agentsDir = path.join(dataDir, 'agents');
  }
  
  /**
   * Ensure data directory exists.
   */
  private async ensureDir(): Promise<void> {
    await fs.mkdir(this.agentsDir, { recursive: true });
  }
  
  /**
   * Create a new agent from natural language description.
   */
  async createAgent(input: CreateAgentInput): Promise<AgentSpec> {
    await this.ensureDir();
    
    const now = new Date().toISOString();
    const id = uuidv4();
    
    // Parse the description to extract agent details
    const { name, task } = this.parseDescription(input.description);
    
    const config: AgentConfig = {
      id,
      name,
      description: input.description,
      task,
      language: input.language || 'python',
      schedule: input.schedule,
      policies: input.policies || [],
      approvalRequired: input.approvalRequired || false,
      createdAt: now,
      updatedAt: now,
      status: 'draft',
      metadata: {},
    };
    
    // Generate workflow based on task
    const workflow = this.generateWorkflow(task, config.language);
    
    const spec: AgentSpec = {
      config,
      workflow,
      integrations: [],
    };
    
    // Save agent
    await this.saveAgent(spec);
    
    return spec;
  }
  
  /**
   * Parse natural language description into structured data.
   */
  private parseDescription(description: string): { name: string; task: string } {
    // Extract a short name from description
    const words = description.split(' ').slice(0, 4);
    const name = words.join('-').toLowerCase().replace(/[^a-z0-9-]/g, '');
    
    return {
      name: name || 'agent-' + Date.now(),
      task: description,
    };
  }
  
  /**
   * Generate a basic workflow from task description.
   */
  private generateWorkflow(task: string, language: string): AgentSpec['workflow'] {
    // This would be enhanced with AI-based workflow generation
    const steps = [];
    
    // Detect common patterns and generate steps
    if (task.toLowerCase().includes('email')) {
      steps.push({
        name: 'connect_email',
        action: 'email.connect',
        params: { protocol: 'imap' },
      });
    }
    
    if (task.toLowerCase().includes('database') || task.toLowerCase().includes('query')) {
      steps.push({
        name: 'connect_database',
        action: 'database.connect',
        params: { type: 'postgresql' },
      });
    }
    
    if (task.toLowerCase().includes('slack')) {
      steps.push({
        name: 'connect_slack',
        action: 'slack.connect',
        params: {},
      });
    }
    
    // Add main processing step
    steps.push({
      name: 'process_data',
      action: 'execute',
      params: { task },
    });
    
    // Add output step
    steps.push({
      name: 'output_results',
      action: 'output',
      params: { format: 'json' },
    });
    
    return { steps };
  }
  
  /**
   * Save agent to disk.
   */
  private async saveAgent(spec: AgentSpec): Promise<void> {
    const filePath = path.join(this.agentsDir, `${spec.config.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(spec, null, 2));
  }
  
  /**
   * Get agent by ID.
   */
  async getAgent(id: string): Promise<AgentSpec | null> {
    try {
      const filePath = path.join(this.agentsDir, `${id}.json`);
      const content = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(content) as AgentSpec;
    } catch {
      return null;
    }
  }
  
  /**
   * List all agents.
   */
  async listAgents(): Promise<AgentConfig[]> {
    await this.ensureDir();
    
    try {
      const files = await fs.readdir(this.agentsDir);
      const agents: AgentConfig[] = [];
      
      for (const file of files) {
        if (file.endsWith('.json')) {
          const content = await fs.readFile(path.join(this.agentsDir, file), 'utf-8');
          const spec = JSON.parse(content) as AgentSpec;
          agents.push(spec.config);
        }
      }
      
      return agents;
    } catch {
      return [];
    }
  }
  
  /**
   * Update agent status.
   */
  async updateStatus(id: string, status: AgentStatus): Promise<void> {
    const spec = await this.getAgent(id);
    if (!spec) {
      throw new Error(`Agent not found: ${id}`);
    }
    
    spec.config.status = status;
    spec.config.updatedAt = new Date().toISOString();
    
    await this.saveAgent(spec);
  }
  
  /**
   * Update agent configuration.
   */
  async updateAgent(id: string, updates: Partial<AgentConfig>): Promise<AgentSpec> {
    const spec = await this.getAgent(id);
    if (!spec) {
      throw new Error(`Agent not found: ${id}`);
    }
    
    spec.config = {
      ...spec.config,
      ...updates,
      id, // Preserve ID
      updatedAt: new Date().toISOString(),
    };
    
    await this.saveAgent(spec);
    
    return spec;
  }
  
  /**
   * Delete agent.
   */
  async deleteAgent(id: string): Promise<void> {
    const filePath = path.join(this.agentsDir, `${id}.json`);
    await fs.unlink(filePath);
  }
  
  /**
   * Attach policies to agent.
   */
  async attachPolicies(id: string, policyIds: string[]): Promise<AgentSpec> {
    const spec = await this.getAgent(id);
    if (!spec) {
      throw new Error(`Agent not found: ${id}`);
    }
    
    // Merge policies (avoid duplicates)
    const existingPolicies = new Set(spec.config.policies);
    for (const policyId of policyIds) {
      existingPolicies.add(policyId);
    }
    
    spec.config.policies = Array.from(existingPolicies);
    spec.config.updatedAt = new Date().toISOString();
    
    await this.saveAgent(spec);
    
    return spec;
  }
}
