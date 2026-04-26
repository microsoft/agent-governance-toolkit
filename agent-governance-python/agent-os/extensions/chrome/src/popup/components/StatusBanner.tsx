// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import React from 'react';

interface StatusBannerProps {
  enabled: boolean;
}

export function StatusBanner({ enabled }: StatusBannerProps) {
  return (
    <div className={`status-banner ${enabled ? 'enabled' : 'disabled'}`}>
      <span className={`status-dot ${enabled ? 'green' : 'red'}`}></span>
      <span>
        {enabled ? 'AgentOS is active and protecting your workflows' : 'AgentOS is disabled'}
      </span>
    </div>
  );
}
