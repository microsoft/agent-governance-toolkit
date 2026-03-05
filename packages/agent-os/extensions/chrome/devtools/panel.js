// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent OS DevTools - Panel Logic
 * 
 * Handles the DevTools panel UI and communication with the inspected page.
 */

class AgentOSPanel {
  constructor() {
    this.messages = [];
    this.agents = new Map();
    this.stats = {
      messagesSent: 0,
      messagesReceived: 0,
      activeAgents: 0,
      verifications: 0,
      failedVerifications: 0,
      violations: 0
    };
    this.isPaused = false;
    
    this.init();
  }
  
  init() {
    this.setupTabs();
    this.setupToolbar();
    this.setupNetworkCanvas();
    this.connectToPage();
    
    // Refresh stats periodically
    setInterval(() => this.updateStats(), 1000);
  }
  
  setupTabs() {
    const tabs = document.querySelectorAll('.tab');
    const panels = document.querySelectorAll('.panel');
    
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const targetId = tab.dataset.tab;
        
        tabs.forEach(t => t.classList.remove('active'));
        panels.forEach(p => p.classList.remove('active'));
        
        tab.classList.add('active');
        document.getElementById(targetId).classList.add('active');
      });
    });
  }
  
  setupToolbar() {
    // Message filter
    document.getElementById('messageFilter').addEventListener('input', (e) => {
      this.filterMessages(e.target.value);
    });
    
    // Clear messages
    document.getElementById('clearMessages').addEventListener('click', () => {
      this.messages = [];
      this.renderMessages();
    });
    
    // Pause/Resume
    document.getElementById('pauseMessages').addEventListener('click', (e) => {
      this.isPaused = !this.isPaused;
      e.target.textContent = this.isPaused ? 'Resume' : 'Pause';
    });
    
    // Refresh trust
    document.getElementById('refreshTrust').addEventListener('click', () => {
      this.refreshTrustTable();
    });
    
    // Trust filter
    document.getElementById('trustFilter').addEventListener('input', (e) => {
      this.filterTrust(e.target.value);
    });
  }
  
  setupNetworkCanvas() {
    const canvas = document.getElementById('networkCanvas');
    this.ctx = canvas.getContext('2d');
    
    // Set canvas size
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    
    // Network visualization state
    this.networkNodes = [];
    this.networkEdges = [];
    
    // Initial render
    this.renderNetwork();
    
    // Handle resize
    window.addEventListener('resize', () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
      this.renderNetwork();
    });
  }
  
  connectToPage() {
    // Create connection to background script
    const port = chrome.runtime.connect({ name: 'devtools-panel' });
    
    // Send tab ID to background
    port.postMessage({
      type: 'init',
      tabId: chrome.devtools.inspectedWindow.tabId
    });
    
    // Listen for messages from the page
    port.onMessage.addListener((message) => {
      this.handlePageMessage(message);
    });
    
    // Update connection status
    this.setConnectionStatus(true);
    
    port.onDisconnect.addListener(() => {
      this.setConnectionStatus(false);
    });
    
    // Also inject our listener into the page
    this.injectPageListener();
  }
  
  injectPageListener() {
    chrome.devtools.inspectedWindow.eval(`
      (function() {
        // Hook into Agent OS if present
        if (window.__AGENT_OS__) {
          const originalEmit = window.__AGENT_OS__.emit;
          window.__AGENT_OS__.emit = function(event, data) {
            // Send to DevTools
            window.postMessage({
              source: 'agent-os-page',
              event: event,
              data: data
            }, '*');
            // Call original
            return originalEmit.apply(this, arguments);
          };
          console.log('[Agent OS DevTools] Monitoring enabled');
        } else {
          console.log('[Agent OS DevTools] No Agent OS instance found');
        }
      })();
    `);
  }
  
  setConnectionStatus(connected) {
    const dot = document.getElementById('connectionStatus');
    const text = document.getElementById('connectionText');
    
    if (connected) {
      dot.classList.remove('disconnected');
      text.textContent = 'Connected';
    } else {
      dot.classList.add('disconnected');
      text.textContent = 'Disconnected';
    }
  }
  
  handlePageMessage(message) {
    switch (message.type) {
      case 'amb-message':
        this.addMessage(message.data);
        break;
      case 'iatp-verification':
        this.addVerification(message.data);
        break;
      case 'agent-registered':
        this.addAgent(message.data);
        break;
      case 'agent-removed':
        this.removeAgent(message.data.agentId);
        break;
      case 'policy-violation':
        this.addViolation(message.data);
        break;
    }
  }
  
  // Message handling
  addMessage(data) {
    if (this.isPaused) return;
    
    const message = {
      id: Date.now(),
      timestamp: new Date(),
      type: data.type || 'message',
      sender: data.sender,
      recipient: data.recipient,
      content: data.content,
      signature: data.signature
    };
    
    this.messages.unshift(message);
    this.stats.messagesReceived++;
    
    // Limit stored messages
    if (this.messages.length > 1000) {
      this.messages.pop();
    }
    
    this.renderMessages();
  }
  
  renderMessages() {
    const container = document.getElementById('messageList');
    
    if (this.messages.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="icon">📭</div>
          <p>No messages captured yet</p>
          <p>Agent OS messages will appear here</p>
        </div>
      `;
      return;
    }
    
    container.innerHTML = this.messages.map(msg => `
      <div class="message-item" data-id="${msg.id}">
        <div class="message-header">
          <span class="message-type">${msg.type}</span>
          <span class="message-time">${this.formatTime(msg.timestamp)}</span>
        </div>
        <div class="message-body">${JSON.stringify(msg.content, null, 2)}</div>
        <div class="message-meta">
          <span>From: ${msg.sender || 'unknown'}</span>
          <span>To: ${msg.recipient || 'broadcast'}</span>
          ${msg.signature ? `<span>✓ Signed</span>` : ''}
        </div>
      </div>
    `).join('');
  }
  
  filterMessages(query) {
    const items = document.querySelectorAll('.message-item');
    const lowerQuery = query.toLowerCase();
    
    items.forEach(item => {
      const text = item.textContent.toLowerCase();
      item.style.display = text.includes(lowerQuery) ? 'block' : 'none';
    });
  }
  
  // Trust handling
  addAgent(data) {
    this.agents.set(data.agentId, {
      id: data.agentId,
      name: data.name,
      trustLevel: data.trustLevel || 'MEDIUM',
      publicKey: data.publicKey,
      lastVerified: new Date()
    });
    
    this.stats.activeAgents = this.agents.size;
    this.renderTrustTable();
    this.updateNetworkNode(data);
  }
  
  removeAgent(agentId) {
    this.agents.delete(agentId);
    this.stats.activeAgents = this.agents.size;
    this.renderTrustTable();
    this.renderNetwork();
  }
  
  addVerification(data) {
    if (data.success) {
      this.stats.verifications++;
    } else {
      this.stats.failedVerifications++;
    }
    
    // Update agent's last verified time
    const agent = this.agents.get(data.agentId);
    if (agent) {
      agent.lastVerified = new Date();
    }
  }
  
  refreshTrustTable() {
    // Request fresh trust data from page
    chrome.devtools.inspectedWindow.eval(`
      window.__AGENT_OS__?.trustRegistry?.listAgents() || {}
    `, (result) => {
      if (result) {
        Object.entries(result).forEach(([id, data]) => {
          this.agents.set(id, {
            id: id,
            name: data.name || id,
            trustLevel: data.trustLevel || 'UNKNOWN',
            publicKey: data.publicKey?.substring(0, 16) + '...',
            lastVerified: data.lastVerified ? new Date(data.lastVerified) : null
          });
        });
        this.renderTrustTable();
      }
    });
  }
  
  renderTrustTable() {
    const tbody = document.getElementById('trustTableBody');
    
    if (this.agents.size === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No agents registered</td></tr>';
      return;
    }
    
    tbody.innerHTML = Array.from(this.agents.values()).map(agent => `
      <tr>
        <td>${agent.id}</td>
        <td>${agent.name}</td>
        <td>
          <span class="trust-level ${agent.trustLevel.toLowerCase()}">
            ${agent.trustLevel}
          </span>
        </td>
        <td><code>${agent.publicKey || 'N/A'}</code></td>
        <td>${agent.lastVerified ? this.formatTime(agent.lastVerified) : 'Never'}</td>
      </tr>
    `).join('');
  }
  
  filterTrust(query) {
    const rows = document.querySelectorAll('#trustTableBody tr');
    const lowerQuery = query.toLowerCase();
    
    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      row.style.display = text.includes(lowerQuery) ? 'table-row' : 'none';
    });
  }
  
  // Network visualization
  updateNetworkNode(agent) {
    const existing = this.networkNodes.find(n => n.id === agent.agentId);
    
    if (existing) {
      existing.name = agent.name;
      existing.trustLevel = agent.trustLevel;
    } else {
      this.networkNodes.push({
        id: agent.agentId,
        name: agent.name || agent.agentId,
        trustLevel: agent.trustLevel || 'MEDIUM',
        x: Math.random() * 300 + 50,
        y: Math.random() * 200 + 50
      });
    }
    
    this.renderNetwork();
  }
  
  renderNetwork() {
    const canvas = document.getElementById('networkCanvas');
    const ctx = this.ctx;
    
    // Clear canvas
    ctx.fillStyle = '#252526';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    if (this.networkNodes.length === 0) {
      ctx.fillStyle = '#858585';
      ctx.font = '14px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No agents to display', canvas.width / 2, canvas.height / 2);
      return;
    }
    
    // Draw edges
    ctx.strokeStyle = '#404040';
    ctx.lineWidth = 1;
    
    this.networkEdges.forEach(edge => {
      const from = this.networkNodes.find(n => n.id === edge.from);
      const to = this.networkNodes.find(n => n.id === edge.to);
      
      if (from && to) {
        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.stroke();
      }
    });
    
    // Draw nodes
    this.networkNodes.forEach(node => {
      // Node circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, 20, 0, Math.PI * 2);
      
      // Color based on trust level
      switch (node.trustLevel) {
        case 'HIGH':
          ctx.fillStyle = '#4ec9b0';
          break;
        case 'MEDIUM':
          ctx.fillStyle = '#dcdcaa';
          break;
        case 'LOW':
          ctx.fillStyle = '#f14c4c';
          break;
        default:
          ctx.fillStyle = '#569cd6';
      }
      
      ctx.fill();
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 2;
      ctx.stroke();
      
      // Node label
      ctx.fillStyle = '#cccccc';
      ctx.font = '11px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(node.name, node.x, node.y + 35);
    });
  }
  
  // Violation handling
  addViolation(data) {
    this.stats.violations++;
    
    // Add as a special message
    this.addMessage({
      type: 'VIOLATION',
      sender: data.agentId,
      content: {
        policy: data.policy,
        action: data.action,
        reason: data.reason
      }
    });
  }
  
  // Stats
  updateStats() {
    document.getElementById('statMessagesSent').textContent = this.stats.messagesSent;
    document.getElementById('statMessagesReceived').textContent = this.stats.messagesReceived;
    document.getElementById('statActiveAgents').textContent = this.stats.activeAgents;
    document.getElementById('statVerifications').textContent = this.stats.verifications;
    document.getElementById('statFailedVerifications').textContent = this.stats.failedVerifications;
    document.getElementById('statViolations').textContent = this.stats.violations;
  }
  
  // Utilities
  formatTime(date) {
    return date.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      fractionalSecondDigits: 3
    });
  }
}

// Initialize panel
const panel = new AgentOSPanel();
