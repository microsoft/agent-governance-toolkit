// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import React from 'react';

interface HeaderProps {
  onSettingsClick: () => void;
}

export function Header({ onSettingsClick }: HeaderProps) {
  return (
    <header className="header">
      <div className="header-title">
        <span className="logo">🛡️</span>
        <h1>AgentOS</h1>
      </div>
      <div className="header-actions">
        <button className="icon-btn" onClick={onSettingsClick} title="Settings">
          ⚙️
        </button>
      </div>
    </header>
  );
}
