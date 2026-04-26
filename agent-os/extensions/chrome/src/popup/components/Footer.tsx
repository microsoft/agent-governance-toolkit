// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import React from 'react';

interface FooterProps {
  onDashboardClick: () => void;
  onCreateClick: () => void;
}

export function Footer({ onDashboardClick, onCreateClick }: FooterProps) {
  return (
    <footer className="footer">
      <button className="footer-btn" onClick={onDashboardClick}>
        📊 Dashboard
      </button>
      <button className="footer-btn primary" onClick={onCreateClick}>
        ➕ Create Agent
      </button>
    </footer>
  );
}
