// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent OS Chrome Extension - Injected Page Script
 * 
 * Runs in the page context to hook into Agent OS instances.
 * Communicates with the content script via window.postMessage.
 */

(function() {
  'use strict';
  
  // Wait for Agent OS to be available
  function waitForAgentOS(callback, maxAttempts = 50) {
    let attempts = 0;
    
    const check = () => {
      attempts++;
      
      if (window.__AGENT_OS__) {
        callback(window.__AGENT_OS__);
      } else if (attempts < maxAttempts) {
        setTimeout(check, 100);
      } else {
        console.log('[Agent OS DevTools] No Agent OS instance found after', maxAttempts * 100, 'ms');
      }
    };
    
    check();
  }
  
  // Hook into Agent OS
  function hookAgentOS(agentOS) {
    console.log('[Agent OS DevTools] Agent OS detected, hooking...');
    
    // Hook message bus if available
    if (agentOS.messageBus) {
      hookMessageBus(agentOS.messageBus);
    }
    
    // Hook trust registry if available
    if (agentOS.trustRegistry) {
      hookTrustRegistry(agentOS.trustRegistry);
    }
    
    // Hook kernel if available
    if (agentOS.kernel) {
      hookKernel(agentOS.kernel);
    }
    
    // Add emit function if not present
    if (!agentOS.emit) {
      agentOS.emit = emitToDevTools;
    } else {
      // Wrap existing emit
      const originalEmit = agentOS.emit.bind(agentOS);
      agentOS.emit = function(event, data) {
        emitToDevTools(event, data);
        return originalEmit(event, data);
      };
    }
    
    console.log('[Agent OS DevTools] Hooks installed');
    emitToDevTools('connected', { version: agentOS.version });
  }
  
  // Hook into message bus
  function hookMessageBus(messageBus) {
    // Hook publish method
    if (messageBus.publish) {
      const originalPublish = messageBus.publish.bind(messageBus);
      messageBus.publish = function(topic, message) {
        emitToDevTools('amb-message', {
          direction: 'outbound',
          topic: topic,
          type: 'publish',
          sender: message.sender,
          recipient: message.recipient || 'broadcast',
          content: message.content,
          signature: message.signature,
          timestamp: Date.now()
        });
        return originalPublish(topic, message);
      };
    }
    
    // Hook subscribe method to intercept incoming messages
    if (messageBus.subscribe) {
      const originalSubscribe = messageBus.subscribe.bind(messageBus);
      messageBus.subscribe = function(topic, handler) {
        const wrappedHandler = (message) => {
          emitToDevTools('amb-message', {
            direction: 'inbound',
            topic: topic,
            type: 'receive',
            sender: message.sender,
            recipient: message.recipient,
            content: message.content,
            signature: message.signature,
            timestamp: Date.now()
          });
          return handler(message);
        };
        return originalSubscribe(topic, wrappedHandler);
      };
    }
  }
  
  // Hook into trust registry
  function hookTrustRegistry(registry) {
    // Hook register method
    if (registry.register) {
      const originalRegister = registry.register.bind(registry);
      registry.register = function(agent, trustLevel) {
        emitToDevTools('agent-registered', {
          agentId: agent.agent_id || agent.id,
          name: agent.name,
          trustLevel: trustLevel?.name || trustLevel || 'MEDIUM',
          publicKey: agent.public_key?.substring(0, 32),
          capabilities: agent.capabilities,
          timestamp: Date.now()
        });
        return originalRegister(agent, trustLevel);
      };
    }
    
    // Hook verify method
    if (registry.verify) {
      const originalVerify = registry.verify.bind(registry);
      registry.verify = function(message) {
        const result = originalVerify(message);
        emitToDevTools('iatp-verification', {
          agentId: message.sender_id,
          success: result.is_valid,
          reason: result.rejection_reason,
          timestamp: Date.now()
        });
        return result;
      };
    }
    
    // Hook revoke method
    if (registry.revoke) {
      const originalRevoke = registry.revoke.bind(registry);
      registry.revoke = function(agentId, reason) {
        emitToDevTools('agent-removed', {
          agentId: agentId,
          reason: reason,
          timestamp: Date.now()
        });
        return originalRevoke(agentId, reason);
      };
    }
  }
  
  // Hook into kernel
  function hookKernel(kernel) {
    // Hook policy violations
    if (kernel.on) {
      kernel.on('violation', (violation) => {
        emitToDevTools('policy-violation', {
          agentId: violation.agentId,
          policy: violation.policy,
          action: violation.action,
          reason: violation.reason,
          signal: violation.signal,
          timestamp: Date.now()
        });
      });
    }
    
    // Hook signal dispatch
    if (kernel.signalDispatcher && kernel.signalDispatcher.signal) {
      const originalSignal = kernel.signalDispatcher.signal.bind(kernel.signalDispatcher);
      kernel.signalDispatcher.signal = function(agentId, signal) {
        emitToDevTools('signal-sent', {
          agentId: agentId,
          signal: signal.name || signal,
          timestamp: Date.now()
        });
        return originalSignal(agentId, signal);
      };
    }
  }
  
  // Send event to DevTools via content script
  function emitToDevTools(event, data) {
    window.postMessage({
      source: 'agent-os-page',
      event: event,
      data: data
    }, '*');
  }
  
  // Expose API for DevTools console
  window.__AGENT_OS_DEVTOOLS__ = {
    getMessages: function() {
      return '[Call from DevTools panel]';
    },
    getAgents: function() {
      if (window.__AGENT_OS__?.trustRegistry) {
        return window.__AGENT_OS__.trustRegistry.listAgents();
      }
      return {};
    },
    exportLogs: function() {
      // Trigger export in DevTools panel
      emitToDevTools('export-request', {});
    },
    clear: function() {
      emitToDevTools('clear-request', {});
    }
  };
  
  // Listen for DevTools connection
  window.addEventListener('message', (event) => {
    if (event.data.source === 'agent-os-extension' && event.data.type === 'devtools-connected') {
      console.log('[Agent OS DevTools] DevTools panel connected');
      // Resend current state
      if (window.__AGENT_OS__?.trustRegistry) {
        const agents = window.__AGENT_OS__.trustRegistry.listAgents();
        Object.entries(agents).forEach(([id, agent]) => {
          emitToDevTools('agent-registered', {
            agentId: id,
            name: agent.name,
            trustLevel: agent.trustLevel,
            publicKey: agent.publicKey?.substring(0, 32)
          });
        });
      }
    }
  });
  
  // Start watching for Agent OS
  waitForAgentOS(hookAgentOS);
  
})();
