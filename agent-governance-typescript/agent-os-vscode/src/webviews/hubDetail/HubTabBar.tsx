// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Hub Tab Bar
 *
 * Horizontal tab navigation for the Governance Hub detail panel.
 * Active tab renders with bold text and a bottom border accent.
 */

import React from 'react';

export interface TabDef {
    id: string;
    label: string;
}

interface HubTabBarProps {
    tabs: TabDef[];
    activeId: string;
    onSelect: (id: string) => void;
}

/** Style object for the active tab indicator border. */
const activeBorderStyle: React.CSSProperties = {
    borderBottomColor: 'var(--vscode-focusBorder)',
};

/** Renders a single tab button. */
function TabButton(
    { tab, isActive, onSelect }: { tab: TabDef; isActive: boolean; onSelect: (id: string) => void },
): React.JSX.Element {
    const baseClasses = 'px-3 py-2 text-sm border-b-2 transition-opacity cursor-pointer';
    const activeClasses = 'font-bold opacity-100';
    const inactiveClasses = 'font-normal opacity-60 border-transparent';

    return (
        <button
            type="button"
            role="tab"
            aria-selected={isActive}
            className={`${baseClasses} ${isActive ? activeClasses : inactiveClasses}`}
            style={isActive ? activeBorderStyle : undefined}
            onClick={() => onSelect(tab.id)}
        >
            {tab.label}
        </button>
    );
}

/**
 * Horizontal tab bar for switching between Hub sub-panels.
 */
export function HubTabBar({ tabs, activeId, onSelect }: HubTabBarProps): React.JSX.Element {
    return (
        <nav
            className="flex gap-2 border-b border-ml-border shrink-0"
            role="tablist"
            aria-label="Governance Hub tabs"
        >
            {tabs.map((tab) => (
                <TabButton
                    key={tab.id}
                    tab={tab}
                    isActive={tab.id === activeId}
                    onSelect={onSelect}
                />
            ))}
        </nav>
    );
}
