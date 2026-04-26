// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import React, { useState, useEffect } from 'react';
import { AgentList } from './components/AgentList';
import { Header } from './components/Header';
import { StatusBanner } from './components/StatusBanner';
import { CurrentPage } from './components/CurrentPage';
import { SuggestedAgent } from './components/SuggestedAgent';
import { Footer } from './components/Footer';
import { getSettings, getAgents, saveAgents } from '../shared/storage';
import type { Agent, AgentOSSettings } from '../shared/types';
import { SAMPLE_AGENTS } from '../shared/types';

export function App() {
  const [settings, setSettings] = useState<AgentOSSettings | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [currentUrl, setCurrentUrl] = useState<string>('');
  const [currentPlatform, setCurrentPlatform] = useState<string | null>(null);

  useEffect(() => {
    // Load settings and agents
    Promise.all([getSettings(), getAgents()]).then(([loadedSettings, loadedAgents]) => {
      setSettings(loadedSettings);
      // Use sample agents if none exist
      setAgents(loadedAgents.length > 0 ? loadedAgents : SAMPLE_AGENTS);
    });

    // Get current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url || '';
      setCurrentUrl(url);
      setCurrentPlatform(detectPlatform(url));
    });
  }, []);

  const detectPlatform = (url: string): string | null => {
    try {
      const hostname = new URL(url).hostname;
      if (hostname === 'github.com' || hostname.endsWith('.github.com')) return 'github';
      if (hostname.endsWith('.atlassian.net') || hostname.startsWith('jira.')) return 'jira';
      if (hostname === 'console.aws.amazon.com') return 'aws';
      if (hostname === 'gitlab.com' || hostname.endsWith('.gitlab.com')) return 'gitlab';
      if (hostname === 'linear.app' || hostname.endsWith('.linear.app')) return 'linear';
    } catch {
      // Invalid URL
    }
    return null;
  };

  const handleToggleAgent = async (agentId: string) => {
    const updatedAgents = agents.map((agent) => {
      if (agent.id === agentId) {
        const newStatus = agent.status === 'running' ? 'paused' : 'running';
        return { ...agent, status: newStatus as Agent['status'] };
      }
      return agent;
    });
    setAgents(updatedAgents);
    await saveAgents(updatedAgents);
  };

  const handleStopAgent = async (agentId: string) => {
    const updatedAgents = agents.map((agent) => {
      if (agent.id === agentId) {
        return { ...agent, status: 'stopped' as Agent['status'] };
      }
      return agent;
    });
    setAgents(updatedAgents);
    await saveAgents(updatedAgents);
  };

  const handleCreateAgent = () => {
    // Open agent creation page or trigger wizard
    chrome.tabs.create({ url: chrome.runtime.getURL('options.html#create') });
  };

  const handleOpenDashboard = () => {
    chrome.tabs.create({ url: 'https://app.agent-os.dev/dashboard' });
  };

  const handleOpenSettings = () => {
    chrome.runtime.openOptionsPage();
  };

  if (!settings) {
    return (
      <div className="popup-container">
        <div style={{ padding: 20, textAlign: 'center' }}>Loading...</div>
      </div>
    );
  }

  const activeAgents = agents.filter((a) => a.status === 'running' || a.status === 'paused');
  const platformAgents = currentPlatform
    ? agents.filter((a) => a.platform === currentPlatform)
    : [];

  return (
    <div className="popup-container">
      <Header onSettingsClick={handleOpenSettings} />
      
      <StatusBanner enabled={settings.enabled} />
      
      <CurrentPage url={currentUrl} platform={currentPlatform} />
      
      {currentPlatform && platformAgents.length === 0 && (
        <SuggestedAgent
          platform={currentPlatform}
          onCreateClick={handleCreateAgent}
        />
      )}
      
      <AgentList
        agents={activeAgents}
        onToggle={handleToggleAgent}
        onStop={handleStopAgent}
      />
      
      <Footer
        onDashboardClick={handleOpenDashboard}
        onCreateClick={handleCreateAgent}
      />
    </div>
  );
}
