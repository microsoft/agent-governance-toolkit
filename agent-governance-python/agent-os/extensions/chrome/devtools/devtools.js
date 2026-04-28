// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent OS DevTools - Panel Registration
 * 
 * Creates the Agent OS panel in Chrome DevTools for monitoring
 * inter-agent communication and trust protocols.
 */

// Create the Agent OS panel in DevTools
chrome.devtools.panels.create(
  "Agent OS",           // Panel title
  "icons/icon32.png",   // Icon path
  "devtools/panel.html", // Panel HTML
  (panel) => {
    console.log("Agent OS DevTools panel created");
    
    // Panel shown callback
    panel.onShown.addListener((window) => {
      console.log("Agent OS panel shown");
    });
    
    // Panel hidden callback  
    panel.onHidden.addListener(() => {
      console.log("Agent OS panel hidden");
    });
  }
);

// Create sidebar pane for element inspection
chrome.devtools.panels.elements.createSidebarPane(
  "Agent Trust",
  (sidebar) => {
    // Show trust info for selected element's associated agent
    chrome.devtools.panels.elements.onSelectionChanged.addListener(() => {
      sidebar.setExpression(`
        (function() {
          const el = $0;
          const agentId = el?.dataset?.agentId;
          if (agentId && window.__AGENT_OS__) {
            return window.__AGENT_OS__.getTrustInfo(agentId);
          }
          return { message: "No agent associated with this element" };
        })()
      `);
    });
  }
);
