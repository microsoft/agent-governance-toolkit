// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent OS Chrome Extension - Background Service Worker
 * 
 * Handles communication between DevTools panel and content scripts.
 */

// Map of tab IDs to their DevTools connections
const devtoolsConnections = new Map();

// Map of tab IDs to their content script ports
const contentScriptPorts = new Map();

// Handle connections from DevTools panels
chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'devtools-panel') {
    let tabId = null;
    
    port.onMessage.addListener((message) => {
      if (message.type === 'init') {
        tabId = message.tabId;
        devtoolsConnections.set(tabId, port);
        console.log(`DevTools connected for tab ${tabId}`);
        
        // If we have a content script connection, relay messages
        const contentPort = contentScriptPorts.get(tabId);
        if (contentPort) {
          contentPort.postMessage({ type: 'devtools-connected' });
        }
      } else {
        // Forward messages to content script
        const contentPort = contentScriptPorts.get(tabId);
        if (contentPort) {
          contentPort.postMessage(message);
        }
      }
    });
    
    port.onDisconnect.addListener(() => {
      if (tabId !== null) {
        devtoolsConnections.delete(tabId);
        console.log(`DevTools disconnected for tab ${tabId}`);
      }
    });
  }
  
  if (port.name === 'content-script') {
    const tabId = port.sender?.tab?.id;
    if (tabId) {
      contentScriptPorts.set(tabId, port);
      console.log(`Content script connected for tab ${tabId}`);
      
      port.onMessage.addListener((message) => {
        // Forward to DevTools panel
        const devtoolsPort = devtoolsConnections.get(tabId);
        if (devtoolsPort) {
          devtoolsPort.postMessage(message);
        }
      });
      
      port.onDisconnect.addListener(() => {
        contentScriptPorts.delete(tabId);
        console.log(`Content script disconnected for tab ${tabId}`);
      });
    }
  }
});

// Handle messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'get-status') {
    // Return status of Agent OS detection
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      if (tabId) {
        chrome.tabs.sendMessage(tabId, { type: 'check-agent-os' }, (response) => {
          sendResponse({
            detected: response?.detected || false,
            version: response?.version || null
          });
        });
      } else {
        sendResponse({ detected: false });
      }
    });
    return true; // Keep channel open for async response
  }
});

// Listen for tab updates to re-inject content script if needed
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && devtoolsConnections.has(tabId)) {
    // Tab was reloaded, notify DevTools
    const port = devtoolsConnections.get(tabId);
    if (port) {
      port.postMessage({ type: 'tab-reloaded' });
    }
  }
});

// Clean up when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  devtoolsConnections.delete(tabId);
  contentScriptPorts.delete(tabId);
});

console.log('Agent OS background service worker started');
