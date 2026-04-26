// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * AgentOS Jira Content Script
 * Integrates with Jira issues, boards, and sprints
 */

import { getSettings } from '../shared/storage';

const AGENTOS_CLASS = 'agentos-injected';

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

async function init() {
  const settings = await getSettings();
  
  if (!settings.enabled || !settings.platforms.jira) {
    return;
  }

  const pageType = detectPageType();
  console.log('AgentOS: Jira page type detected:', pageType);

  switch (pageType) {
    case 'issue':
      injectIssueIntegration();
      break;
    case 'board':
      injectBoardIntegration();
      break;
    case 'backlog':
      injectBacklogIntegration();
      break;
  }

  // Notify background script
  chrome.runtime.sendMessage({
    type: 'PLATFORM_DETECTED',
    platform: 'jira',
    pageType,
    url: window.location.href,
  });

  // Inject FAB on all Jira pages
  injectFAB();
}

function detectPageType(): string {
  const path = window.location.pathname;
  const url = window.location.href;
  
  if (path.includes('/browse/') || url.includes('selectedIssue=')) return 'issue';
  if (path.includes('/board')) return 'board';
  if (path.includes('/backlog')) return 'backlog';
  if (path.includes('/sprint')) return 'sprint';
  
  return 'other';
}

function injectIssueIntegration() {
  // Wait for issue detail panel
  waitForElement('[data-testid="issue.views.issue-details.issue-layout"]').then((issuePanel) => {
    if (issuePanel.querySelector(`.${AGENTOS_CLASS}`)) return;

    // Create AgentOS section
    const agentOSSection = document.createElement('div');
    agentOSSection.className = `${AGENTOS_CLASS}`;
    agentOSSection.style.cssText = `
      margin: 16px;
      padding: 16px;
      border: 1px solid #dfe1e6;
      border-radius: 8px;
      background: linear-gradient(to bottom, #f4f5f7, #ffffff);
    `;
    const sectionHeader = document.createElement('div');
    sectionHeader.style.cssText = 'display: flex; align-items: center; gap: 8px; margin-bottom: 12px;';
    const sectionIcon = document.createElement('span');
    sectionIcon.style.fontSize = '20px';
    sectionIcon.textContent = '🛡️';
    sectionHeader.appendChild(sectionIcon);
    const sectionTitle = document.createElement('h4');
    sectionTitle.style.cssText = 'font-size: 14px; font-weight: 600; margin: 0;';
    sectionTitle.textContent = 'AgentOS Automation';
    sectionHeader.appendChild(sectionTitle);
    agentOSSection.appendChild(sectionHeader);

    const buttonGroup = document.createElement('div');
    buttonGroup.style.cssText = 'display: flex; flex-direction: column; gap: 8px;';
    for (const { action, label } of [
      { action: 'breakdown', label: '📝 Break into subtasks' },
      { action: 'estimate', label: '⏱️ Estimate story points' },
      { action: 'find-prs', label: '🔗 Find related PRs' },
      { action: 'test-plan', label: '🧪 Generate test plan' },
    ]) {
      const btn = document.createElement('button');
      btn.className = 'agentos-jira-btn';
      btn.dataset.action = action;
      btn.textContent = label;
      buttonGroup.appendChild(btn);
    }
    agentOSSection.appendChild(buttonGroup);

    const style = document.createElement('style');
    style.textContent = `
      .agentos-jira-btn {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 10px 14px;
        background: white;
        border: 1px solid #dfe1e6;
        border-radius: 4px;
        cursor: pointer;
        font-size: 13px;
        color: #172b4d;
        transition: all 0.2s;
        text-align: left;
      }
      .agentos-jira-btn:hover {
        background: #f4f5f7;
        border-color: #6366f1;
      }
    `;
    document.head.appendChild(style);

    // Find a good place to insert
    const detailsSection = issuePanel.querySelector('[data-testid="issue.views.issue-details.issue-layout.container-right"]');
    if (detailsSection) {
      detailsSection.insertBefore(agentOSSection, detailsSection.firstChild);
    } else {
      issuePanel.appendChild(agentOSSection);
    }

    // Handle button clicks
    agentOSSection.querySelectorAll('.agentos-jira-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const action = (btn as HTMLElement).dataset.action;
        runJiraAgent(action || '');
      });
    });
  });
}

function injectBoardIntegration() {
  waitForElement('[data-testid="software-board.board"]').then((board) => {
    if (document.querySelector(`.agentos-board-banner`)) return;

    const banner = document.createElement('div');
    banner.className = 'agentos-board-banner';
    banner.style.cssText = `
      position: fixed;
      top: 56px;
      right: 20px;
      background: white;
      border: 1px solid #dfe1e6;
      border-radius: 8px;
      padding: 12px 16px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.1);
      z-index: 1000;
      display: flex;
      align-items: center;
      gap: 12px;
    `;
    const bannerIcon = document.createElement('span');
    bannerIcon.style.fontSize = '20px';
    bannerIcon.textContent = '🛡️';
    banner.appendChild(bannerIcon);

    const bannerInfo = document.createElement('div');
    const bannerTitle = document.createElement('div');
    bannerTitle.style.cssText = 'font-size: 13px; font-weight: 500;';
    bannerTitle.textContent = 'AgentOS Active';
    bannerInfo.appendChild(bannerTitle);
    const bannerSubtitle = document.createElement('div');
    bannerSubtitle.style.cssText = 'font-size: 11px; color: #5e6c84;';
    bannerSubtitle.textContent = 'Monitoring board activity';
    bannerInfo.appendChild(bannerSubtitle);
    banner.appendChild(bannerInfo);

    const optimizeBtn = document.createElement('button');
    optimizeBtn.className = 'agentos-banner-btn';
    optimizeBtn.style.cssText = 'background: #6366f1; color: white; border: none; border-radius: 4px; padding: 6px 12px; cursor: pointer; font-size: 12px;';
    optimizeBtn.textContent = 'Optimize Sprint';
    banner.appendChild(optimizeBtn);

    document.body.appendChild(banner);

    banner.querySelector('.agentos-banner-btn')?.addEventListener('click', () => {
      runJiraAgent('optimize-sprint');
    });

    // Auto-hide after 5 seconds
    setTimeout(() => {
      banner.style.opacity = '0.7';
    }, 5000);
  });
}

function injectBacklogIntegration() {
  waitForElement('[data-testid="software-backlog.backlog-content"]').then((backlog) => {
    if (document.querySelector(`.agentos-backlog-tools`)) return;

    const toolbar = document.createElement('div');
    toolbar.className = 'agentos-backlog-tools';
    toolbar.style.cssText = `
      padding: 8px 16px;
      background: #f4f5f7;
      border-bottom: 1px solid #dfe1e6;
      display: flex;
      align-items: center;
      gap: 12px;
    `;
    const toolbarLabel = document.createElement('span');
    toolbarLabel.style.fontSize = '14px';
    toolbarLabel.textContent = '🛡️ AgentOS:';
    toolbar.appendChild(toolbarLabel);
    for (const { action, label } of [
      { action: 'auto-prioritize', label: 'Auto-prioritize' },
      { action: 'estimate-all', label: 'Estimate all' },
      { action: 'find-duplicates', label: 'Find duplicates' },
    ]) {
      const btn = document.createElement('button');
      btn.className = 'agentos-tool-btn';
      btn.dataset.action = action;
      btn.textContent = label;
      toolbar.appendChild(btn);
    }

    const style = document.createElement('style');
    style.textContent = `
      .agentos-tool-btn {
        background: white;
        border: 1px solid #dfe1e6;
        border-radius: 4px;
        padding: 6px 12px;
        cursor: pointer;
        font-size: 12px;
        transition: all 0.2s;
      }
      .agentos-tool-btn:hover {
        background: #6366f1;
        color: white;
        border-color: #6366f1;
      }
    `;
    document.head.appendChild(style);

    backlog.insertBefore(toolbar, backlog.firstChild);

    toolbar.querySelectorAll('.agentos-tool-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const action = (btn as HTMLElement).dataset.action;
        runJiraAgent(action || '');
      });
    });
  });
}

function injectFAB() {
  if (document.querySelector('.agentos-fab')) return;

  const fab = document.createElement('div');
  fab.className = 'agentos-fab';
  const fabButton = document.createElement('button');
  fabButton.className = 'agentos-fab-button';
  fabButton.title = 'AgentOS';
  fabButton.textContent = '🤖';
  fab.appendChild(fabButton);

  const fabMenu = document.createElement('div');
  fabMenu.className = 'agentos-fab-menu';
  fabMenu.style.display = 'none';
  for (const { action, label } of [
    { action: 'create', label: '➕ Create Agent' },
    { action: 'sprint-report', label: '📊 Sprint Report' },
    { action: 'velocity', label: '📈 Velocity Analysis' },
  ]) {
    const item = document.createElement('div');
    item.className = 'agentos-fab-menu-item';
    item.dataset.action = action;
    item.textContent = label;
    fabMenu.appendChild(item);
  }
  fab.appendChild(fabMenu);

  const style = document.createElement('style');
  style.textContent = `
    .agentos-fab {
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 9999;
    }
    .agentos-fab-button {
      width: 56px;
      height: 56px;
      border-radius: 50%;
      background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      border: none;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.4);
      cursor: pointer;
      font-size: 24px;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .agentos-fab-button:hover {
      transform: scale(1.1);
      box-shadow: 0 6px 20px rgba(99, 102, 241, 0.5);
    }
    .agentos-fab-menu {
      position: absolute;
      bottom: 64px;
      right: 0;
      background: white;
      border-radius: 8px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.15);
      overflow: hidden;
      min-width: 180px;
    }
    .agentos-fab-menu-item {
      padding: 12px 16px;
      cursor: pointer;
      font-size: 14px;
      transition: background 0.2s;
    }
    .agentos-fab-menu-item:hover {
      background: #f4f5f7;
    }
  `;

  document.head.appendChild(style);
  document.body.appendChild(fab);

  // Toggle menu
  const button = fab.querySelector('.agentos-fab-button') as HTMLElement;
  const menu = fab.querySelector('.agentos-fab-menu') as HTMLElement;

  button.addEventListener('click', () => {
    menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
  });

  // Handle menu actions
  menu.addEventListener('click', (e) => {
    const target = e.target as HTMLElement;
    const action = target.dataset.action;
    
    if (action) {
      runJiraAgent(action);
    }
    
    menu.style.display = 'none';
  });

  // Close menu when clicking outside
  document.addEventListener('click', (e) => {
    if (!fab.contains(e.target as Node)) {
      menu.style.display = 'none';
    }
  });
}

function runJiraAgent(action: string) {
  console.log('AgentOS: Running Jira agent:', action);
  
  // Show loading toast
  showToast(`Running ${action}...`, 'info');
  
  chrome.runtime.sendMessage({
    type: 'ACTION_REQUESTED',
    agentId: `jira-${action}`,
    action,
    data: {
      url: window.location.href,
      issueKey: extractIssueKey(),
    },
  });

  // Simulate completion (in real implementation, this would be a callback)
  setTimeout(() => {
    showToast(`${action} completed!`, 'success');
  }, 2000);
}

function extractIssueKey(): string | null {
  const match = window.location.href.match(/([A-Z]+-\d+)/);
  return match ? match[1] : null;
}

function showToast(message: string, type: 'info' | 'success' | 'error') {
  const toast = document.createElement('div');
  toast.style.cssText = `
    position: fixed;
    bottom: 100px;
    right: 24px;
    background: ${type === 'success' ? '#22c55e' : type === 'error' ? '#ef4444' : '#6366f1'};
    color: white;
    padding: 12px 20px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    z-index: 10000;
    font-size: 14px;
    animation: slideIn 0.3s ease;
  `;
  toast.textContent = message;

  const style = document.createElement('style');
  style.textContent = `
    @keyframes slideIn {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
  `;
  document.head.appendChild(style);
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function waitForElement(selector: string, timeout = 10000): Promise<Element> {
  return new Promise((resolve, reject) => {
    const element = document.querySelector(selector);
    if (element) {
      resolve(element);
      return;
    }

    const observer = new MutationObserver((mutations, obs) => {
      const element = document.querySelector(selector);
      if (element) {
        obs.disconnect();
        resolve(element);
      }
    });

    observer.observe(document.body, { childList: true, subtree: true });

    setTimeout(() => {
      observer.disconnect();
      reject(new Error(`Element ${selector} not found`));
    }, timeout);
  });
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'INIT') {
    init();
  }
});

console.log('AgentOS Jira content script loaded');
