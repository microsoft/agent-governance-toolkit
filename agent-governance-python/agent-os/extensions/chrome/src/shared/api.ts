// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * AgentOS API Client
 */
import { getSettings } from './storage';
import type { Agent, Policy, AuditLogEntry } from './types';

class AgentOSApiClient {
  private async getBaseUrl(): Promise<string> {
    const settings = await getSettings();
    return settings.apiEndpoint || 'https://api.agent-os.dev/v1';
  }

  private async getHeaders(): Promise<HeadersInit> {
    const settings = await getSettings();
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${settings.apiKey}`,
    };
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const baseUrl = await this.getBaseUrl();
    const headers = await this.getHeaders();

    const response = await fetch(`${baseUrl}${endpoint}`, {
      ...options,
      headers: {
        ...headers,
        ...options.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  // Agent operations
  async listAgents(): Promise<Agent[]> {
    try {
      return await this.request<Agent[]>('/agents');
    } catch (error) {
      console.warn('Failed to fetch agents from API:', error);
      return [];
    }
  }

  async createAgent(agent: Omit<Agent, 'id'>): Promise<Agent> {
    return this.request<Agent>('/agents', {
      method: 'POST',
      body: JSON.stringify(agent),
    });
  }

  async updateAgent(id: string, updates: Partial<Agent>): Promise<Agent> {
    return this.request<Agent>(`/agents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  }

  async deleteAgent(id: string): Promise<void> {
    await this.request(`/agents/${id}`, { method: 'DELETE' });
  }

  async startAgent(id: string): Promise<void> {
    await this.request(`/agents/${id}/start`, { method: 'POST' });
  }

  async stopAgent(id: string): Promise<void> {
    await this.request(`/agents/${id}/stop`, { method: 'POST' });
  }

  async pauseAgent(id: string): Promise<void> {
    await this.request(`/agents/${id}/pause`, { method: 'POST' });
  }

  // Policy operations
  async listPolicies(): Promise<Policy[]> {
    try {
      return await this.request<Policy[]>('/policies');
    } catch (error) {
      console.warn('Failed to fetch policies from API:', error);
      return this.getDefaultPolicies();
    }
  }

  // Audit log
  async getAuditLog(agentId?: string, limit = 100): Promise<AuditLogEntry[]> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (agentId) params.set('agentId', agentId);
    
    try {
      return await this.request<AuditLogEntry[]>(`/audit?${params}`);
    } catch (error) {
      console.warn('Failed to fetch audit log from API:', error);
      return [];
    }
  }

  // CMVK review
  async reviewCode(code: string, language: string): Promise<CMVKResult> {
    try {
      return await this.request<CMVKResult>('/cmvk/review', {
        method: 'POST',
        body: JSON.stringify({ code, language }),
      });
    } catch (error) {
      console.warn('CMVK review failed:', error);
      return {
        consensus: 0,
        modelResults: [],
        overallSafe: true,
        issues: ['Offline mode - unable to perform CMVK review'],
        suggestions: [],
      };
    }
  }

  // Default policies when API is unavailable
  private getDefaultPolicies(): Policy[] {
    return [
      {
        id: 'destructive-sql',
        name: 'Block Destructive SQL',
        description: 'Prevents DROP, DELETE without WHERE, TRUNCATE statements',
        enabled: true,
        severity: 'critical',
      },
      {
        id: 'secret-exposure',
        name: 'Block Secret Exposure',
        description: 'Detects hardcoded API keys, passwords, and secrets',
        enabled: true,
        severity: 'error',
      },
      {
        id: 'dangerous-file-ops',
        name: 'Block Dangerous File Operations',
        description: 'Prevents rm -rf, format, and destructive file commands',
        enabled: true,
        severity: 'critical',
      },
      {
        id: 'rate-limiting',
        name: 'Rate Limiting',
        description: 'Limits API calls to prevent abuse',
        enabled: true,
        severity: 'warning',
      },
    ];
  }
}

// CMVK result type
interface CMVKResult {
  consensus: number;
  modelResults: Array<{
    model: string;
    safe: boolean;
    confidence: number;
    issues: string[];
  }>;
  overallSafe: boolean;
  issues: string[];
  suggestions: string[];
}

// Singleton instance
export const apiClient = new AgentOSApiClient();
