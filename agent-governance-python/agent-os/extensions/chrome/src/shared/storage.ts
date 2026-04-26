// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * AgentOS Chrome Storage Utilities
 */
import { AgentOSSettings, DEFAULT_SETTINGS, Agent, AuditLogEntry } from './types';

const STORAGE_KEYS = {
  SETTINGS: 'agentos_settings',
  AGENTS: 'agentos_agents',
  AUDIT_LOG: 'agentos_audit_log',
} as const;

/**
 * Get settings from Chrome storage
 */
export async function getSettings(): Promise<AgentOSSettings> {
  return new Promise((resolve) => {
    chrome.storage.sync.get(STORAGE_KEYS.SETTINGS, (result) => {
      const settings = result[STORAGE_KEYS.SETTINGS];
      resolve(settings ? { ...DEFAULT_SETTINGS, ...settings } : DEFAULT_SETTINGS);
    });
  });
}

/**
 * Save settings to Chrome storage
 */
export async function saveSettings(settings: Partial<AgentOSSettings>): Promise<void> {
  const current = await getSettings();
  const updated = { ...current, ...settings };
  
  return new Promise((resolve) => {
    chrome.storage.sync.set({ [STORAGE_KEYS.SETTINGS]: updated }, resolve);
  });
}

/**
 * Get agents from local storage
 */
export async function getAgents(): Promise<Agent[]> {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.AGENTS, (result) => {
      resolve(result[STORAGE_KEYS.AGENTS] || []);
    });
  });
}

/**
 * Save agents to local storage
 */
export async function saveAgents(agents: Agent[]): Promise<void> {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [STORAGE_KEYS.AGENTS]: agents }, resolve);
  });
}

/**
 * Add or update an agent
 */
export async function upsertAgent(agent: Agent): Promise<void> {
  const agents = await getAgents();
  const index = agents.findIndex((a) => a.id === agent.id);
  
  if (index >= 0) {
    agents[index] = agent;
  } else {
    agents.push(agent);
  }
  
  await saveAgents(agents);
}

/**
 * Delete an agent
 */
export async function deleteAgent(agentId: string): Promise<void> {
  const agents = await getAgents();
  const filtered = agents.filter((a) => a.id !== agentId);
  await saveAgents(filtered);
}

/**
 * Get audit log entries
 */
export async function getAuditLog(limit = 100): Promise<AuditLogEntry[]> {
  return new Promise((resolve) => {
    chrome.storage.local.get(STORAGE_KEYS.AUDIT_LOG, (result) => {
      const log = result[STORAGE_KEYS.AUDIT_LOG] || [];
      resolve(log.slice(0, limit));
    });
  });
}

/**
 * Add audit log entry
 */
export async function addAuditLogEntry(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): Promise<void> {
  const log = await getAuditLog(999);
  
  const newEntry: AuditLogEntry = {
    ...entry,
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
  };
  
  // Keep only last 1000 entries
  const updated = [newEntry, ...log].slice(0, 1000);
  
  return new Promise((resolve) => {
    chrome.storage.local.set({ [STORAGE_KEYS.AUDIT_LOG]: updated }, resolve);
  });
}

/**
 * Clear all AgentOS data
 */
export async function clearAllData(): Promise<void> {
  return new Promise((resolve) => {
    chrome.storage.local.clear(() => {
      chrome.storage.sync.clear(resolve);
    });
  });
}
