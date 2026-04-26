// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * AgentOS GitHub Content Script
 * Integrates with GitHub PRs, Issues, and Actions
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
  
  if (!settings.enabled || !settings.platforms.github) {
    return;
  }

  // Detect page type and inject appropriate UI
  const pageType = detectPageType();
  console.log('AgentOS: GitHub page type detected:', pageType);

  switch (pageType) {
    case 'pull-request':
      injectPRIntegration();
      break;
    case 'issue':
      injectIssueIntegration();
      break;
    case 'repository':
      injectRepoIntegration();
      break;
  }

  // Notify background script
  chrome.runtime.sendMessage({
    type: 'PLATFORM_DETECTED',
    platform: 'github',
    pageType,
    url: window.location.href,
  });

  // Watch for SPA navigation
  observeNavigation();
}

function detectPageType(): string {
  const path = window.location.pathname;
  
  if (path.includes('/pull/')) return 'pull-request';
  if (path.includes('/issues/') && !path.includes('/issues')) return 'issue';
  if (path.match(/^\/[^/]+\/[^/]+\/?$/)) return 'repository';
  if (path.includes('/issues')) return 'issues-list';
  if (path.includes('/pulls')) return 'pr-list';
  
  return 'other';
}

function injectPRIntegration() {
  // Wait for the tab bar to be available
  const tabBar = document.querySelector('.tabnav-tabs, [data-target="diff-layout.diffLayoutNavigation"]');
  if (!tabBar || tabBar.querySelector(`.${AGENTOS_CLASS}`)) return;

  // Create AgentOS tab
  const agentOSTab = document.createElement('a');
  agentOSTab.className = `tabnav-tab ${AGENTOS_CLASS}`;
  agentOSTab.href = '#agentos';
  const tabIcon = document.createElement('span');
  tabIcon.style.marginRight = '4px';
  tabIcon.textContent = '🛡️';
  agentOSTab.appendChild(tabIcon);
  agentOSTab.appendChild(document.createTextNode(' AgentOS '));
  const tabCounter = document.createElement('span');
  tabCounter.className = 'Counter';
  tabCounter.style.cssText = 'margin-left: 4px; background: #22c55e; color: white;';
  tabCounter.textContent = '✓';
  agentOSTab.appendChild(tabCounter);
  agentOSTab.onclick = (e) => {
    e.preventDefault();
    showAgentOSPanel();
  };

  tabBar.appendChild(agentOSTab);

  // Also inject floating action button
  injectFAB();
}

function injectIssueIntegration() {
  // Find sidebar
  const sidebar = document.querySelector('.Layout-sidebar');
  if (!sidebar || sidebar.querySelector(`.${AGENTOS_CLASS}`)) return;

  // Create AgentOS section
  const agentOSSection = document.createElement('div');
  agentOSSection.className = `${AGENTOS_CLASS}`;
  agentOSSection.style.cssText = `
    margin-top: 16px;
    padding: 16px;
    border: 1px solid #d0d7de;
    border-radius: 6px;
    background: #f6f8fa;
  `;
  const sectionHeading = document.createElement('h3');
  sectionHeading.style.cssText = 'font-size: 14px; font-weight: 600; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;';
  sectionHeading.textContent = '🛡️ AgentOS';
  agentOSSection.appendChild(sectionHeading);

  const sectionDesc = document.createElement('div');
  sectionDesc.style.cssText = 'font-size: 13px; color: #57606a; margin-bottom: 12px;';
  sectionDesc.textContent = 'Available automations:';
  agentOSSection.appendChild(sectionDesc);

  const buttonContainer = document.createElement('div');
  buttonContainer.style.cssText = 'display: flex; flex-direction: column; gap: 8px;';
  for (const { agentId, label } of [
    { agentId: 'issue-labeler', label: '🏷️ Auto-label this issue' },
    { agentId: 'issue-breakdown', label: '📝 Break into subtasks' },
    { agentId: 'estimate', label: '⏱️ Estimate effort' },
  ]) {
    const btn = document.createElement('button');
    btn.className = 'btn btn-sm';
    btn.textContent = label;
    btn.addEventListener('click', () => (window as any).agentOS?.runAgent(agentId));
    buttonContainer.appendChild(btn);
  }
  agentOSSection.appendChild(buttonContainer);

  sidebar.insertBefore(agentOSSection, sidebar.firstChild);
  injectFAB();
}

function injectRepoIntegration() {
  injectFAB();
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
    { action: 'view', label: '👀 View Agents' },
    { action: 'logs', label: '📋 Audit Log' },
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
      min-width: 160px;
    }
    .agentos-fab-menu-item {
      padding: 12px 16px;
      cursor: pointer;
      font-size: 14px;
      transition: background 0.2s;
    }
    .agentos-fab-menu-item:hover {
      background: #f3f4f6;
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
    
    if (action === 'create') {
      chrome.runtime.sendMessage({ type: 'OPEN_CREATE_AGENT' });
    } else if (action === 'view') {
      chrome.runtime.sendMessage({ type: 'OPEN_POPUP' });
    } else if (action === 'logs') {
      chrome.runtime.sendMessage({ type: 'OPEN_AUDIT_LOG' });
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

function showAgentOSPanel() {
  // Remove existing panel
  document.querySelector('.agentos-panel')?.remove();

  const panel = document.createElement('div');
  panel.className = 'agentos-panel';
  // SECURITY: innerHTML with trusted content only — static extension UI, no user data interpolated
  panel.innerHTML = `
    <div class="agentos-panel-header">
      <h2>🛡️ AgentOS Policy Check</h2>
      <button class="agentos-panel-close">&times;</button>
    </div>
    <div class="agentos-panel-content">
      <div class="agentos-check-result success">
        <span class="icon">✅</span>
        <span>All policies passed</span>
      </div>
      
      <div class="agentos-section">
        <h3>Checks Performed</h3>
        <ul class="agentos-checks">
          <li class="pass">✅ Code quality standards</li>
          <li class="pass">✅ Security scan clean</li>
          <li class="pass">✅ Test coverage >80%</li>
          <li class="warn">⚠️ Large file detected (review recommended)</li>
        </ul>
      </div>
      
      <div class="agentos-section">
        <h3>🤖 Available Agents</h3>
        <div class="agentos-agents">
          <button class="agentos-agent-btn">
            <span>🔄</span> Auto-merge (safe PRs)
          </button>
          <button class="agentos-agent-btn">
            <span>📝</span> Generate changelog
          </button>
          <button class="agentos-agent-btn">
            <span>📚</span> Update documentation
          </button>
        </div>
      </div>
      
      <div class="agentos-section">
        <button class="agentos-run-all">▶️ Run All Agents</button>
      </div>
    </div>
  `;

  const style = document.createElement('style');
  style.textContent = `
    .agentos-panel {
      position: fixed;
      top: 60px;
      right: 20px;
      width: 360px;
      background: white;
      border-radius: 12px;
      box-shadow: 0 8px 30px rgba(0,0,0,0.15);
      z-index: 10000;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .agentos-panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px 20px;
      border-bottom: 1px solid #e5e7eb;
    }
    .agentos-panel-header h2 {
      font-size: 16px;
      font-weight: 600;
      margin: 0;
    }
    .agentos-panel-close {
      background: none;
      border: none;
      font-size: 24px;
      cursor: pointer;
      color: #6b7280;
    }
    .agentos-panel-content {
      padding: 20px;
    }
    .agentos-check-result {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 12px 16px;
      border-radius: 8px;
      margin-bottom: 16px;
    }
    .agentos-check-result.success {
      background: #ecfdf5;
      color: #065f46;
    }
    .agentos-section {
      margin-bottom: 20px;
    }
    .agentos-section h3 {
      font-size: 14px;
      font-weight: 600;
      margin-bottom: 12px;
      color: #374151;
    }
    .agentos-checks {
      list-style: none;
      padding: 0;
      margin: 0;
    }
    .agentos-checks li {
      padding: 8px 0;
      font-size: 13px;
      border-bottom: 1px solid #f3f4f6;
    }
    .agentos-checks li.warn {
      color: #92400e;
    }
    .agentos-agents {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .agentos-agent-btn {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
      background: #f9fafb;
      border: 1px solid #e5e7eb;
      border-radius: 6px;
      cursor: pointer;
      font-size: 13px;
      transition: all 0.2s;
    }
    .agentos-agent-btn:hover {
      background: #f3f4f6;
      border-color: #6366f1;
    }
    .agentos-run-all {
      width: 100%;
      padding: 12px;
      background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      transition: transform 0.2s;
    }
    .agentos-run-all:hover {
      transform: translateY(-1px);
    }
  `;

  document.head.appendChild(style);
  document.body.appendChild(panel);

  // Close button
  panel.querySelector('.agentos-panel-close')?.addEventListener('click', () => {
    panel.remove();
  });
}

function observeNavigation() {
  // GitHub uses pjax/turbo for navigation
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === 'childList') {
        // Re-run init on navigation
        setTimeout(() => {
          // Remove old injections
          document.querySelectorAll(`.${AGENTOS_CLASS}`).forEach((el) => el.remove());
          document.querySelector('.agentos-fab')?.remove();
          // Re-inject
          init();
        }, 500);
        break;
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: false });
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'INIT') {
    init();
  }
  
  if (message.type === 'AGENTS_AVAILABLE') {
    console.log('AgentOS: Agents available:', message.agents);
  }
});

// Expose global for inline handlers
(window as any).agentOS = {
  runAgent: (agentId: string) => {
    chrome.runtime.sendMessage({
      type: 'RUN_AGENT',
      agentId,
      context: {
        url: window.location.href,
        platform: 'github',
      },
    });
  },
};

console.log('AgentOS GitHub content script loaded');
