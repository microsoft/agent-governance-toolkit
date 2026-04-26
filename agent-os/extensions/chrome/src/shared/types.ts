// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * AgentOS Shared Types and Utilities
 */

// Agent model
export interface Agent {
  id: string;
  name: string;
  description: string;
  status: AgentStatus;
  platform: string;
  lastRun?: string;
  runCount: number;
  policies: string[];
}

export type AgentStatus = 'running' | 'paused' | 'stopped' | 'error';

// Platform integration
export interface PlatformIntegration {
  id: string;
  name: string;
  icon: string;
  enabled: boolean;
  matchPatterns: string[];
}

// Policy
export interface Policy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: 'info' | 'warning' | 'error' | 'critical';
}

// Audit log entry
export interface AuditLogEntry {
  id: string;
  agentId: string;
  agentName: string;
  action: string;
  result: 'success' | 'blocked' | 'warning';
  timestamp: string;
  details: string;
}

// Settings
export interface AgentOSSettings {
  apiKey: string;
  apiEndpoint: string;
  enabled: boolean;
  notifications: boolean;
  autoRun: boolean;
  platforms: {
    github: boolean;
    jira: boolean;
    aws: boolean;
    gitlab: boolean;
    linear: boolean;
  };
}

// Default settings
export const DEFAULT_SETTINGS: AgentOSSettings = {
  apiKey: '',
  apiEndpoint: 'https://api.agent-os.dev/v1',
  enabled: true,
  notifications: true,
  autoRun: false,
  platforms: {
    github: true,
    jira: true,
    aws: false,
    gitlab: false,
    linear: false,
  },
};

// Platform definitions
export const PLATFORMS: PlatformIntegration[] = [
  {
    id: 'github',
    name: 'GitHub',
    icon: '🐙',
    enabled: true,
    matchPatterns: ['*://github.com/*'],
  },
  {
    id: 'jira',
    name: 'Jira',
    icon: '📋',
    enabled: true,
    matchPatterns: ['*://*.atlassian.net/*', '*://jira.*/*'],
  },
  {
    id: 'aws',
    name: 'AWS Console',
    icon: '☁️',
    enabled: false,
    matchPatterns: ['*://*.console.aws.amazon.com/*'],
  },
  {
    id: 'gitlab',
    name: 'GitLab',
    icon: '🦊',
    enabled: false,
    matchPatterns: ['*://gitlab.com/*', '*://gitlab.*/*'],
  },
  {
    id: 'linear',
    name: 'Linear',
    icon: '📐',
    enabled: false,
    matchPatterns: ['*://linear.app/*'],
  },
];

// Sample agents for demo
export const SAMPLE_AGENTS: Agent[] = [
  {
    id: '1',
    name: 'PR Reviewer',
    description: 'Automatically reviews pull requests for code quality',
    status: 'running',
    platform: 'github',
    lastRun: new Date().toISOString(),
    runCount: 42,
    policies: ['code-quality', 'security-scan'],
  },
  {
    id: '2',
    name: 'Issue Labeler',
    description: 'Auto-labels issues based on content',
    status: 'paused',
    platform: 'github',
    lastRun: new Date(Date.now() - 3600000).toISOString(),
    runCount: 128,
    policies: ['rate-limiting'],
  },
  {
    id: '3',
    name: 'Sprint Planner',
    description: 'Helps plan sprints and estimate stories',
    status: 'stopped',
    platform: 'jira',
    runCount: 15,
    policies: [],
  },
];
