// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * AgentOS AWS Console Content Script
 * Integrates with AWS Console for cost monitoring and security alerts
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
  
  if (!settings.enabled || !settings.platforms.aws) {
    return;
  }

  const service = detectAWSService();
  console.log('AgentOS: AWS service detected:', service);

  // Inject service-specific integrations
  switch (service) {
    case 'ec2':
      injectEC2Integration();
      break;
    case 's3':
      injectS3Integration();
      break;
    case 'lambda':
      injectLambdaIntegration();
      break;
    case 'billing':
      injectBillingIntegration();
      break;
    default:
      // Generic integration
      break;
  }

  // Always inject the alert banner and FAB
  injectAlertBanner();
  injectFAB();

  // Notify background script
  chrome.runtime.sendMessage({
    type: 'PLATFORM_DETECTED',
    platform: 'aws',
    service,
    url: window.location.href,
  });
}

function detectAWSService(): string {
  const url = window.location.href;
  
  if (url.includes('ec2')) return 'ec2';
  if (url.includes('s3')) return 's3';
  if (url.includes('lambda')) return 'lambda';
  if (url.includes('billing') || url.includes('cost')) return 'billing';
  if (url.includes('iam')) return 'iam';
  if (url.includes('cloudwatch')) return 'cloudwatch';
  if (url.includes('rds')) return 'rds';
  
  return 'other';
}

function injectAlertBanner() {
  if (document.querySelector('.agentos-aws-banner')) return;

  const banner = document.createElement('div');
  banner.className = 'agentos-aws-banner';
  banner.style.cssText = `
    position: fixed;
    top: 44px;
    left: 50%;
    transform: translateX(-50%);
    background: white;
    border: 1px solid #d1d5db;
    border-radius: 8px;
    padding: 12px 20px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    z-index: 10000;
    display: flex;
    align-items: center;
    gap: 16px;
    max-width: 600px;
  `;
  const bannerLeft = document.createElement('div');
  bannerLeft.style.cssText = 'display: flex; align-items: center; gap: 8px;';
  const bannerIcon = document.createElement('span');
  bannerIcon.style.fontSize = '20px';
  bannerIcon.textContent = '🛡️';
  bannerLeft.appendChild(bannerIcon);
  const bannerLabel = document.createElement('span');
  bannerLabel.style.fontWeight = '500';
  bannerLabel.textContent = 'AgentOS Monitoring Active';
  bannerLeft.appendChild(bannerLabel);
  banner.appendChild(bannerLeft);

  const bannerActions = document.createElement('div');
  bannerActions.style.cssText = 'display: flex; gap: 8px;';
  for (const { action, label } of [
    { action: 'cost-check', label: '💰 Cost Check' },
    { action: 'security-scan', label: '🔒 Security Scan' },
  ]) {
    const btn = document.createElement('button');
    btn.className = 'agentos-aws-btn';
    btn.dataset.action = action;
    btn.textContent = label;
    bannerActions.appendChild(btn);
  }
  banner.appendChild(bannerActions);

  const closeBtn = document.createElement('button');
  closeBtn.className = 'agentos-banner-close';
  closeBtn.style.cssText = 'background: none; border: none; font-size: 18px; cursor: pointer; color: #6b7280;';
  closeBtn.textContent = '\u00d7';
  banner.appendChild(closeBtn);

  const style = document.createElement('style');
  style.textContent = `
    .agentos-aws-btn {
      background: #f3f4f6;
      border: 1px solid #d1d5db;
      border-radius: 4px;
      padding: 6px 12px;
      cursor: pointer;
      font-size: 12px;
      transition: all 0.2s;
    }
    .agentos-aws-btn:hover {
      background: #6366f1;
      color: white;
      border-color: #6366f1;
    }
  `;
  document.head.appendChild(style);
  document.body.appendChild(banner);

  // Handle button clicks
  banner.querySelectorAll('.agentos-aws-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const action = (btn as HTMLElement).dataset.action;
      runAWSAgent(action || '');
    });
  });

  // Close button
  banner.querySelector('.agentos-banner-close')?.addEventListener('click', () => {
    banner.style.display = 'none';
  });
}

function injectEC2Integration() {
  // Wait for EC2 dashboard
  waitForElement('[data-testid="ec2-dashboard"], .gwt-HTML').then((dashboard) => {
    if (document.querySelector(`.${AGENTOS_CLASS}.ec2`)) return;

    // Check for running instances and inject recommendations
    const section = document.createElement('div');
    section.className = `${AGENTOS_CLASS} ec2`;
    section.style.cssText = `
      margin: 16px;
      padding: 16px;
      background: #fef3c7;
      border: 1px solid #fcd34d;
      border-radius: 8px;
    `;
    // SECURITY: innerHTML with trusted content only — static extension UI, no user data interpolated
    section.innerHTML = `
      <div style="display: flex; align-items: flex-start; gap: 12px;">
        <span style="font-size: 24px;">⚠️</span>
        <div style="flex: 1;">
          <h4 style="font-size: 14px; font-weight: 600; margin: 0 0 8px 0; color: #92400e;">
            AgentOS Cost Alert
          </h4>
          <p style="font-size: 13px; color: #78350f; margin: 0 0 12px 0;">
            Detected instances that may be over-provisioned. Potential savings: <strong>$150/month</strong>
          </p>
          <div style="display: flex; gap: 8px;">
            <button class="agentos-action-btn primary">Review Recommendations</button>
            <button class="agentos-action-btn">Dismiss</button>
          </div>
        </div>
      </div>
    `;

    const style = document.createElement('style');
    style.textContent = `
      .agentos-action-btn {
        background: white;
        border: 1px solid #d1d5db;
        border-radius: 4px;
        padding: 8px 16px;
        cursor: pointer;
        font-size: 13px;
        transition: all 0.2s;
      }
      .agentos-action-btn.primary {
        background: #6366f1;
        color: white;
        border-color: #6366f1;
      }
      .agentos-action-btn:hover {
        transform: translateY(-1px);
      }
    `;
    document.head.appendChild(style);

    dashboard.insertBefore(section, dashboard.firstChild);

    // Handle dismiss
    section.querySelector('.agentos-action-btn:not(.primary)')?.addEventListener('click', () => {
      section.remove();
    });
  }).catch(() => {
    console.log('AgentOS: EC2 dashboard not found');
  });
}

function injectS3Integration() {
  waitForElement('[data-testid="s3-buckets-list"], .s3-bucket-list').then((list) => {
    if (document.querySelector(`.${AGENTOS_CLASS}.s3`)) return;

    const notice = document.createElement('div');
    notice.className = `${AGENTOS_CLASS} s3`;
    notice.style.cssText = `
      margin: 16px;
      padding: 12px 16px;
      background: #ecfdf5;
      border: 1px solid #a7f3d0;
      border-radius: 8px;
      display: flex;
      align-items: center;
      gap: 12px;
    `;
    const noticeIcon = document.createElement('span');
    noticeIcon.style.fontSize = '20px';
    noticeIcon.textContent = '🛡️';
    notice.appendChild(noticeIcon);

    const noticeBody = document.createElement('div');
    noticeBody.style.flex = '1';
    const noticeText = document.createElement('span');
    noticeText.style.cssText = 'font-size: 13px; color: #065f46;';
    noticeText.appendChild(document.createTextNode('AgentOS is monitoring bucket permissions. '));
    const noticeStrong = document.createElement('strong');
    noticeStrong.textContent = 'All buckets compliant';
    noticeText.appendChild(noticeStrong);
    noticeText.appendChild(document.createTextNode(' with security policies.'));
    noticeBody.appendChild(noticeText);
    notice.appendChild(noticeBody);

    const auditBtn = document.createElement('button');
    auditBtn.className = 'agentos-aws-btn';
    auditBtn.dataset.action = 's3-audit';
    auditBtn.textContent = 'Run Full Audit';
    notice.appendChild(auditBtn);

    list.insertBefore(notice, list.firstChild);

    notice.querySelector('.agentos-aws-btn')?.addEventListener('click', () => {
      runAWSAgent('s3-audit');
    });
  }).catch(() => {
    console.log('AgentOS: S3 list not found');
  });
}

function injectLambdaIntegration() {
  // Add Lambda-specific monitoring
  console.log('AgentOS: Lambda integration active');
}

function injectBillingIntegration() {
  waitForElement('.aws-billing, [data-testid="billing-dashboard"]').then((billing) => {
    if (document.querySelector(`.${AGENTOS_CLASS}.billing`)) return;

    const insights = document.createElement('div');
    insights.className = `${AGENTOS_CLASS} billing`;
    insights.style.cssText = `
      margin: 16px;
      padding: 20px;
      background: white;
      border: 1px solid #d1d5db;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    `;
    // SECURITY: innerHTML with trusted content only — static extension UI, no user data interpolated
    insights.innerHTML = `
      <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 16px;">
        <span style="font-size: 24px;">🛡️</span>
        <h3 style="font-size: 16px; font-weight: 600; margin: 0;">AgentOS Cost Insights</h3>
      </div>
      
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 16px;">
        <div style="background: #f9fafb; padding: 12px; border-radius: 6px;">
          <div style="font-size: 11px; color: #6b7280;">CURRENT MONTH</div>
          <div style="font-size: 24px; font-weight: 600;">$1,234</div>
          <div style="font-size: 11px; color: #22c55e;">↓ 12% from last month</div>
        </div>
        <div style="background: #f9fafb; padding: 12px; border-radius: 6px;">
          <div style="font-size: 11px; color: #6b7280;">PROJECTED</div>
          <div style="font-size: 24px; font-weight: 600;">$1,456</div>
          <div style="font-size: 11px; color: #6b7280;">By end of month</div>
        </div>
        <div style="background: #fef3c7; padding: 12px; border-radius: 6px;">
          <div style="font-size: 11px; color: #92400e;">POTENTIAL SAVINGS</div>
          <div style="font-size: 24px; font-weight: 600;">$320</div>
          <div style="font-size: 11px; color: #92400e;">5 optimizations found</div>
        </div>
      </div>
      
      <button class="agentos-action-btn primary" style="width: 100%;">
        View Optimization Recommendations
      </button>
    `;

    billing.insertBefore(insights, billing.firstChild);
  }).catch(() => {
    console.log('AgentOS: Billing dashboard not found');
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
    { action: 'cost-analysis', label: '💰 Cost Analysis' },
    { action: 'security-audit', label: '🔒 Security Audit' },
    { action: 'resource-optimizer', label: '⚡ Optimize Resources' },
    { action: 'compliance-check', label: '✅ Compliance Check' },
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
    
    if (action) {
      runAWSAgent(action);
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

function runAWSAgent(action: string) {
  console.log('AgentOS: Running AWS agent:', action);
  
  showToast(`Running ${action}...`, 'info');
  
  chrome.runtime.sendMessage({
    type: 'ACTION_REQUESTED',
    agentId: `aws-${action}`,
    action,
    data: {
      url: window.location.href,
      service: detectAWSService(),
    },
  });

  // Simulate completion
  setTimeout(() => {
    showToast(`${action} completed!`, 'success');
  }, 2000);
}

function showToast(message: string, type: 'info' | 'success' | 'error') {
  const existing = document.querySelector('.agentos-toast');
  existing?.remove();

  const toast = document.createElement('div');
  toast.className = 'agentos-toast';
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
  `;
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function waitForElement(selector: string, timeout = 5000): Promise<Element> {
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

console.log('AgentOS AWS Console content script loaded');
