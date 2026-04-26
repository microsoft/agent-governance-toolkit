// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * AgentOS Background Service Worker
 * Handles communication, notifications, and agent management
 */

import { getSettings, getAgents, addAuditLogEntry } from '../shared/storage';
import type { Agent, AgentOSSettings } from '../shared/types';

// Keep track of connections
const connections = new Map<number, chrome.runtime.Port>();

// Initialize on install
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('AgentOS extension installed');
    // Open onboarding page
    chrome.tabs.create({ url: chrome.runtime.getURL('options.html#welcome') });
  } else if (details.reason === 'update') {
    console.log(`AgentOS updated to version ${chrome.runtime.getManifest().version}`);
  }
});

// Handle connections from popup and content scripts
chrome.runtime.onConnect.addListener((port) => {
  console.log(`Connection established: ${port.name}`);
  
  if (port.name === 'popup') {
    const tabId = port.sender?.tab?.id;
    if (tabId) {
      connections.set(tabId, port);
    }
    
    port.onDisconnect.addListener(() => {
      if (tabId) connections.delete(tabId);
    });
    
    port.onMessage.addListener(handlePopupMessage);
  }
  
  if (port.name === 'content-script') {
    const tabId = port.sender?.tab?.id;
    if (tabId) {
      connections.set(tabId, port);
    }
    
    port.onMessage.addListener((message) => handleContentScriptMessage(message, port));
  }
});

// Handle messages from popup
async function handlePopupMessage(message: any) {
  switch (message.type) {
    case 'GET_AGENTS':
      return getAgents();
    
    case 'GET_SETTINGS':
      return getSettings();
    
    case 'START_AGENT':
      return startAgent(message.agentId);
    
    case 'STOP_AGENT':
      return stopAgent(message.agentId);
    
    default:
      console.warn('Unknown popup message type:', message.type);
  }
}

// Handle messages from content scripts
async function handleContentScriptMessage(message: any, port: chrome.runtime.Port) {
  const tabId = port.sender?.tab?.id;
  const url = port.sender?.tab?.url || '';
  
  switch (message.type) {
    case 'PLATFORM_DETECTED':
      console.log(`Platform detected: ${message.platform} on tab ${tabId}`);
      await handlePlatformDetected(message.platform, url, tabId);
      break;
    
    case 'ACTION_REQUESTED':
      await handleActionRequest(message, port);
      break;
    
    case 'PAGE_DATA':
      await handlePageData(message.data, message.platform);
      break;
    
    default:
      console.warn('Unknown content script message type:', message.type);
  }
}

// Handle platform detection
async function handlePlatformDetected(platform: string, url: string, tabId?: number) {
  const settings = await getSettings();
  const agents = await getAgents();
  
  // Find agents for this platform
  const platformAgents = agents.filter(
    (a) => a.platform === platform && a.status === 'running'
  );
  
  if (platformAgents.length > 0 && settings.enabled) {
    // Notify content script about available agents
    if (tabId) {
      chrome.tabs.sendMessage(tabId, {
        type: 'AGENTS_AVAILABLE',
        agents: platformAgents,
      });
    }
  }
}

// Handle action requests from content scripts
async function handleActionRequest(message: any, port: chrome.runtime.Port) {
  const { agentId, action, data } = message;
  const agents = await getAgents();
  const agent = agents.find((a) => a.id === agentId);
  
  if (!agent) {
    port.postMessage({ type: 'ACTION_RESULT', success: false, error: 'Agent not found' });
    return;
  }
  
  // Log the action
  await addAuditLogEntry({
    agentId: agent.id,
    agentName: agent.name,
    action: action,
    result: 'success',
    details: JSON.stringify(data),
  });
  
  // Execute the action (in a real implementation, this would call the AgentOS API)
  port.postMessage({
    type: 'ACTION_RESULT',
    success: true,
    agentId,
    action,
  });
}

// Handle page data from content scripts
async function handlePageData(data: any, platform: string) {
  console.log(`Received page data from ${platform}:`, data);
  // Process the data based on platform
  // This could trigger agents or store data for later use
}

// Start an agent
async function startAgent(agentId: string): Promise<boolean> {
  const agents = await getAgents();
  const agent = agents.find((a) => a.id === agentId);
  
  if (agent) {
    await addAuditLogEntry({
      agentId,
      agentName: agent.name,
      action: 'start',
      result: 'success',
      details: 'Agent started',
    });
    
    // Show notification
    const settings = await getSettings();
    if (settings.notifications) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: 'AgentOS',
        message: `Agent "${agent.name}" is now running`,
      });
    }
    
    return true;
  }
  
  return false;
}

// Stop an agent
async function stopAgent(agentId: string): Promise<boolean> {
  const agents = await getAgents();
  const agent = agents.find((a) => a.id === agentId);
  
  if (agent) {
    await addAuditLogEntry({
      agentId,
      agentName: agent.name,
      action: 'stop',
      result: 'success',
      details: 'Agent stopped',
    });
    
    return true;
  }
  
  return false;
}

// Handle tab updates to detect platform changes
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    const settings = await getSettings();
    
    if (!settings.enabled) return;
    
    // Check if this is a supported platform
    const platform = detectPlatform(tab.url);
    if (platform && settings.platforms[platform as keyof typeof settings.platforms]) {
      // Inject content script if needed (handled by manifest, but we can send init message)
      chrome.tabs.sendMessage(tabId, { type: 'INIT', platform });
    }
  }
});

// Detect platform from URL
function detectPlatform(url: string): string | null {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname;
    if (host === 'github.com' || host.endsWith('.github.com')) return 'github';
    if (host === 'atlassian.net' || host.endsWith('.atlassian.net') || host.startsWith('jira.')) return 'jira';
    if (host === 'console.aws.amazon.com') return 'aws';
    if (host === 'gitlab.com' || host.endsWith('.gitlab.com')) return 'gitlab';
    if (host === 'linear.app' || host.endsWith('.linear.app')) return 'linear';
  } catch {
    // Invalid URL
  }
  return null;
}

// Handle extension icon click
chrome.action.onClicked.addListener((tab) => {
  // This is handled by popup, but we can add badge updates here
});

// Update badge based on agent status
async function updateBadge() {
  const agents = await getAgents();
  const runningCount = agents.filter((a) => a.status === 'running').length;
  
  if (runningCount > 0) {
    chrome.action.setBadgeText({ text: String(runningCount) });
    chrome.action.setBadgeBackgroundColor({ color: '#22c55e' });
  } else {
    chrome.action.setBadgeText({ text: '' });
  }
}

// Update badge periodically
setInterval(updateBadge, 30000);
updateBadge();

console.log('AgentOS background service worker started');
