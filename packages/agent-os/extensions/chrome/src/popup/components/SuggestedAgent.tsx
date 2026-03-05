// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import React from 'react';

interface SuggestedAgentProps {
  platform: string;
  onCreateClick: () => void;
}

const SUGGESTIONS: Record<string, { name: string; description: string }> = {
  github: {
    name: 'PR Review Agent',
    description: 'Auto-review pull requests for code quality and security',
  },
  jira: {
    name: 'Sprint Planner Agent',
    description: 'Help estimate and organize sprint tasks',
  },
  aws: {
    name: 'Cost Monitor Agent',
    description: 'Alert on unexpected AWS cost increases',
  },
  gitlab: {
    name: 'Merge Request Agent',
    description: 'Review and auto-merge safe merge requests',
  },
  linear: {
    name: 'Issue Triage Agent',
    description: 'Auto-label and prioritize issues',
  },
};

export function SuggestedAgent({ platform, onCreateClick }: SuggestedAgentProps) {
  const suggestion = SUGGESTIONS[platform];
  if (!suggestion) return null;

  return (
    <div className="suggested-section">
      <div className="suggested-title">
        <span>💡</span>
        <span>Suggested for this page</span>
      </div>
      <div className="suggested-card">
        <div className="suggested-info">
          <h4>{suggestion.name}</h4>
          <p>{suggestion.description}</p>
        </div>
        <button className="action-btn primary" onClick={onCreateClick}>
          Create
        </button>
      </div>
    </div>
  );
}
