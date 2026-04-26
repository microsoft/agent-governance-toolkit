// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import React from 'react';

interface CurrentPageProps {
  url: string;
  platform: string | null;
}

const PLATFORM_NAMES: Record<string, string> = {
  github: 'GitHub',
  jira: 'Jira',
  aws: 'AWS',
  gitlab: 'GitLab',
  linear: 'Linear',
};

const PLATFORM_ICONS: Record<string, string> = {
  github: '🐙',
  jira: '📋',
  aws: '☁️',
  gitlab: '🦊',
  linear: '📐',
};

export function CurrentPage({ url, platform }: CurrentPageProps) {
  const hostname = url ? new URL(url).hostname : 'Unknown';

  return (
    <div className="current-page">
      <div className="current-page-title">Current Page</div>
      <div className="current-page-url">
        {platform && <span>{PLATFORM_ICONS[platform]}</span>}
        <span>{hostname}</span>
        {platform && (
          <span className="platform-badge">{PLATFORM_NAMES[platform]}</span>
        )}
      </div>
    </div>
  );
}
