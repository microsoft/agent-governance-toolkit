// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent OS Chrome Extension - Content Script
 * 
 * Injected into pages to detect and communicate with Agent OS instances.
 * Acts as a bridge between the page context and the extension.
 */

// Connect to background script
let port = null;

function connectToBackground() {
  port = chrome.runtime.connect({ name: 'content-script' });
  
  port.onMessage.addListener((message) => {
    // Forward messages from DevTools to page
    if (message.type === 'devtools-connected') {
      window.postMessage({ source: 'agent-os-extension', type: 'devtools-connected' }, '*');
    }
  });
  
  port.onDisconnect.addListener(() => {
    // Reconnect after a delay
    setTimeout(connectToBackground, 1000);
  });
}

connectToBackground();

// Listen for messages from the page
window.addEventListener('message', (event) => {
  // Only accept messages from our page
  if (event.source !== window) return;
  
  // Handle messages from Agent OS
  if (event.data.source === 'agent-os-page') {
    // Forward to background (and then to DevTools)
    if (port) {
      port.postMessage({
        type: event.data.event,
        data: event.data.data
      });
    }
  }
});

// Handle extension messages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'check-agent-os') {
    // Check if Agent OS is present on the page
    const checkScript = `
      (function() {
        if (window.__AGENT_OS__) {
          return {
            detected: true,
            version: window.__AGENT_OS__.version || 'unknown'
          };
        }
        return { detected: false };
      })()
    `;
    
    // Inject and execute
    const script = document.createElement('script');
    script.textContent = `
      window.postMessage({
        source: 'agent-os-check',
        result: ${checkScript}
      }, '*');
    `;
    document.documentElement.appendChild(script);
    script.remove();
    
    // Listen for result
    const handler = (event) => {
      if (event.data.source === 'agent-os-check') {
        window.removeEventListener('message', handler);
        sendResponse(event.data.result);
      }
    };
    window.addEventListener('message', handler);
    
    return true; // Keep channel open
  }
});

// Inject the page-level script that hooks into Agent OS
function injectPageScript() {
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('injected.js');
  script.onload = function() {
    this.remove();
  };
  (document.head || document.documentElement).appendChild(script);
}

// Inject when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', injectPageScript);
} else {
  injectPageScript();
}

console.log('[Agent OS] Content script loaded');
