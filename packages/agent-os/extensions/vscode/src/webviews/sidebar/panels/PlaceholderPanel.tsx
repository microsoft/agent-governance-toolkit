// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Placeholder Panel
 *
 * Generic stub rendered for panels that are not yet implemented.
 * Displays the panel name centered with a codicon.
 */

import React from 'react';
import type { PanelId } from '../types';
import { PANEL_LABELS, PANEL_ICONS } from '../types';

export function PlaceholderPanel(
    { panelId }: { panelId: PanelId }
): React.ReactElement {
    const label = PANEL_LABELS[panelId];
    const icon = PANEL_ICONS[panelId];

    return (
        <div className="flex flex-col items-center justify-center h-full gap-ml-xs p-ml-sm">
            <i className={`codicon codicon-${icon} text-ml-text-muted text-lg`} />
            <span className="text-sm text-ml-text-muted">{label}</span>
        </div>
    );
}
