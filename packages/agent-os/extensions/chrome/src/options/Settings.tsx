// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import React, { useState, useEffect } from 'react';
import { getSettings, saveSettings, clearAllData } from '../shared/storage';
import type { AgentOSSettings } from '../shared/types';
import { PLATFORMS } from '../shared/types';

export function Settings() {
  const [settings, setSettings] = useState<AgentOSSettings | null>(null);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
  const [isWelcome, setIsWelcome] = useState(false);

  useEffect(() => {
    // Check if this is the welcome page
    if (window.location.hash === '#welcome') {
      setIsWelcome(true);
    }

    getSettings().then(setSettings);
  }, []);

  const showToast = (message: string, type: 'success' | 'error') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3000);
  };

  const handleSave = async () => {
    if (!settings) return;
    
    try {
      await saveSettings(settings);
      showToast('Settings saved successfully!', 'success');
    } catch (error) {
      showToast('Failed to save settings', 'error');
    }
  };

  const handleReset = async () => {
    if (confirm('Are you sure you want to reset all settings and data?')) {
      await clearAllData();
      window.location.reload();
    }
  };

  const handleToggle = (key: keyof AgentOSSettings) => {
    if (!settings) return;
    setSettings({ ...settings, [key]: !settings[key] });
  };

  const handlePlatformToggle = (platformId: string) => {
    if (!settings) return;
    setSettings({
      ...settings,
      platforms: {
        ...settings.platforms,
        [platformId]: !settings.platforms[platformId as keyof typeof settings.platforms],
      },
    });
  };

  const handleInputChange = (key: keyof AgentOSSettings, value: string) => {
    if (!settings) return;
    setSettings({ ...settings, [key]: value });
  };

  if (!settings) {
    return <div className="settings-container">Loading...</div>;
  }

  if (isWelcome) {
    return (
      <div className="settings-container">
        <div className="settings-section">
          <div className="welcome-section">
            <div className="welcome-icon">🛡️</div>
            <h1 className="welcome-title">Welcome to AgentOS!</h1>
            <p className="welcome-description">
              Build and run safe AI agents across your favorite platforms.
              Let's get you set up.
            </p>
            <button
              className="btn btn-primary"
              onClick={() => setIsWelcome(false)}
            >
              Get Started
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="settings-container">
      <header className="settings-header">
        <h1>
          <span>🛡️</span>
          AgentOS Settings
        </h1>
        <p>Configure your AI agent safety platform</p>
      </header>

      {/* General Settings */}
      <section className="settings-section">
        <div className="section-header">
          <span className="icon">⚙️</span>
          <h2>General</h2>
        </div>
        <div className="section-content">
          <div className="setting-row">
            <div className="setting-info">
              <div className="setting-label">Enable AgentOS</div>
              <div className="setting-description">
                Turn on agent monitoring and safety features
              </div>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={settings.enabled}
                onChange={() => handleToggle('enabled')}
              />
              <span className="toggle-slider"></span>
            </label>
          </div>

          <div className="setting-row">
            <div className="setting-info">
              <div className="setting-label">Notifications</div>
              <div className="setting-description">
                Show browser notifications for agent actions
              </div>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={settings.notifications}
                onChange={() => handleToggle('notifications')}
              />
              <span className="toggle-slider"></span>
            </label>
          </div>

          <div className="setting-row">
            <div className="setting-info">
              <div className="setting-label">Auto-run Agents</div>
              <div className="setting-description">
                Automatically run agents when visiting supported platforms
              </div>
            </div>
            <label className="toggle">
              <input
                type="checkbox"
                checked={settings.autoRun}
                onChange={() => handleToggle('autoRun')}
              />
              <span className="toggle-slider"></span>
            </label>
          </div>
        </div>
      </section>

      {/* API Settings */}
      <section className="settings-section">
        <div className="section-header">
          <span className="icon">🔑</span>
          <h2>API Configuration</h2>
        </div>
        <div className="section-content">
          <div className="input-group">
            <label>API Key</label>
            <input
              type="password"
              className="input-field"
              value={settings.apiKey}
              onChange={(e) => handleInputChange('apiKey', e.target.value)}
              placeholder="Enter your AgentOS API key"
            />
          </div>
          <div className="input-group">
            <label>API Endpoint</label>
            <input
              type="text"
              className="input-field"
              value={settings.apiEndpoint}
              onChange={(e) => handleInputChange('apiEndpoint', e.target.value)}
              placeholder="https://api.agent-os.dev/v1"
            />
          </div>
        </div>
      </section>

      {/* Platform Integrations */}
      <section className="settings-section">
        <div className="section-header">
          <span className="icon">🔗</span>
          <h2>Platform Integrations</h2>
        </div>
        <div className="section-content">
          <div className="platform-list">
            {PLATFORMS.map((platform) => (
              <div key={platform.id} className="platform-item">
                <span className="platform-icon">{platform.icon}</span>
                <div className="platform-info">
                  <div className="platform-name">{platform.name}</div>
                  <div className="platform-status">
                    {settings.platforms[platform.id as keyof typeof settings.platforms]
                      ? 'Enabled'
                      : 'Disabled'}
                  </div>
                </div>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={settings.platforms[platform.id as keyof typeof settings.platforms] || false}
                    onChange={() => handlePlatformToggle(platform.id)}
                  />
                  <span className="toggle-slider"></span>
                </label>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Actions */}
      <section className="settings-section">
        <div className="section-header">
          <span className="icon">⚡</span>
          <h2>Actions</h2>
        </div>
        <div className="section-content">
          <div className="btn-group">
            <button className="btn btn-primary" onClick={handleSave}>
              Save Settings
            </button>
            <button className="btn btn-secondary" onClick={() => window.location.reload()}>
              Cancel
            </button>
            <button className="btn btn-danger" onClick={handleReset}>
              Reset All Data
            </button>
          </div>
        </div>
      </section>

      {/* Toast */}
      {toast && (
        <div className={`toast ${toast.type}`}>
          {toast.message}
        </div>
      )}
    </div>
  );
}
