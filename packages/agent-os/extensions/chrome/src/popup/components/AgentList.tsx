// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import React from 'react';
import type { Agent } from '../../shared/types';

interface AgentListProps {
  agents: Agent[];
  onToggle: (agentId: string) => void;
  onStop: (agentId: string) => void;
}

const STATUS_ICONS: Record<Agent['status'], string> = {
  running: '🟢',
  paused: '🟡',
  stopped: '⚪',
  error: '🔴',
};

export function AgentList({ agents, onToggle, onStop }: AgentListProps) {
  if (agents.length === 0) {
    return (
      <div className="agents-section">
        <div className="empty-state">
          <div className="empty-state-icon">🤖</div>
          <p className="empty-state-text">No active agents</p>
          <p style={{ fontSize: 12 }}>Create an agent to get started</p>
        </div>
      </div>
    );
  }

  return (
    <div className="agents-section">
      <div className="section-header">
        <span className="section-title">Active Agents</span>
        <span className="agent-count">{agents.length}</span>
      </div>
      
      <div className="agents-list">
        {agents.map((agent) => (
          <AgentCard
            key={agent.id}
            agent={agent}
            onToggle={() => onToggle(agent.id)}
            onStop={() => onStop(agent.id)}
          />
        ))}
      </div>
    </div>
  );
}

interface AgentCardProps {
  agent: Agent;
  onToggle: () => void;
  onStop: () => void;
}

function AgentCard({ agent, onToggle, onStop }: AgentCardProps) {
  const formatLastRun = (isoDate?: string): string => {
    if (!isoDate) return 'Never';
    const date = new Date(isoDate);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
    return `${Math.floor(diffMins / 1440)}d ago`;
  };

  return (
    <div className="agent-card">
      <div className="agent-header">
        <div className="agent-name">
          <span className="agent-status">{STATUS_ICONS[agent.status]}</span>
          <span>{agent.name}</span>
        </div>
        <div className="agent-actions">
          <button
            className="action-btn"
            onClick={(e) => {
              e.stopPropagation();
              onToggle();
            }}
          >
            {agent.status === 'running' ? 'Pause' : 'Resume'}
          </button>
          <button
            className="action-btn"
            onClick={(e) => {
              e.stopPropagation();
              onStop();
            }}
          >
            Stop
          </button>
        </div>
      </div>
      
      <div className="agent-description">{agent.description}</div>
      
      <div className="agent-meta">
        <span>Last run: {formatLastRun(agent.lastRun)}</span>
        <span>•</span>
        <span>{agent.runCount} runs</span>
      </div>
    </div>
  );
}
