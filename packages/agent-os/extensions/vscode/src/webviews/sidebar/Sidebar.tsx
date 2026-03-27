// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Sidebar Root Component
 *
 * Renders the 3-slot governance sidebar. Subscribes to extension host
 * state updates and manages the panel picker overlay.
 */
import React, { useState, useEffect, useCallback } from 'react';
import { getVSCodeAPI, onMessage, ExtensionMessage } from '../shared/vscode';
import {
    SidebarState,
    SlotConfig,
    PanelId,
    DEFAULT_SLOTS,
} from './types';
import { Slot } from './Slot';
import { PanelPicker } from './PanelPicker';

const INITIAL_STATE: SidebarState = {
    slots: DEFAULT_SLOTS,
    slo: null, audit: null, topology: null,
    policy: null, stats: null, kernel: null, memory: null, hub: null,
    stalePanels: [],
};

/** Inline 14x14 gear SVG for the settings button. */
function GearIcon(): React.ReactElement {
    return (
        <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
            <path d="M9.1 4.4L8.6 2H7.4L6.9 4.4L6.2 4.7L4.2 3.4L3.4
                4.2L4.7 6.2L4.4 6.9L2 7.4V8.6L4.4 9.1L4.7 9.8L3.4
                11.8L4.2 12.6L6.2 11.3L6.9 11.6L7.4 14H8.6L9.1
                11.6L9.8 11.3L11.8 12.6L12.6 11.8L11.3 9.8L11.6
                9.1L14 8.6V7.4L11.6 6.9L11.3 6.2L12.6 4.2L11.8
                3.4L9.8 4.7L9.1 4.4ZM8 10C6.9 10 6 9.1 6 8C6 6.9
                6.9 6 8 6C9.1 6 10 6.9 10 8C10 9.1 9.1 10 8 10Z" />
        </svg>
    );
}

function handleStateMessage(msg: ExtensionMessage): SidebarState | null {
    if (msg.type !== 'stateUpdate') {
        return null;
    }
    return msg.state as SidebarState;
}

/** Root sidebar component with 3 configurable panel slots. */
export function Sidebar(): React.ReactElement {
    const [state, setState] = useState<SidebarState>(INITIAL_STATE);
    const [pickerOpen, setPickerOpen] = useState(false);

    useEffect(() => {
        const cleanup = onMessage((msg) => {
            const next = handleStateMessage(msg);
            if (next) {
                setState(next);
            }
        });
        getVSCodeAPI().postMessage({ type: 'ready' });
        return cleanup;
    }, []);

    const handlePromote = useCallback((panelId: PanelId) => {
        getVSCodeAPI().postMessage({ type: 'promotePanelToWebview', panelId });
    }, []);

    const handleApply = useCallback((slots: SlotConfig) => {
        getVSCodeAPI().postMessage({ type: 'setSlots', slots });
        setPickerOpen(false);
    }, []);

    const handleCancel = useCallback(() => {
        setPickerOpen(false);
    }, []);

    return (
        <div className="h-screen flex flex-col bg-ml-bg text-ml-text overflow-hidden">
            <SidebarHeader onOpenPicker={() => setPickerOpen(true)} />
            <SlotStack state={state} onPromote={handlePromote} />
            {pickerOpen && (
                <PanelPicker
                    current={state.slots}
                    onApply={handleApply}
                    onCancel={handleCancel}
                />
            )}
        </div>
    );
}

/** Header bar with title and gear button. */
function SidebarHeader(
    props: { onOpenPicker: () => void },
): React.ReactElement {
    return (
        <div className="flex items-center justify-between px-ml-sm py-ml-xs border-b border-ml-border">
            <span className="text-xs font-semibold uppercase tracking-wider text-ml-text-muted">
                Governance
            </span>
            <button
                className="p-1 rounded hover:bg-ml-surface-hover text-ml-text-muted hover:text-ml-text"
                onClick={props.onOpenPicker}
                aria-label="Configure panel slots"
                title="Configure panel slots"
            >
                <GearIcon />
            </button>
        </div>
    );
}

/** Renders the 3 slots separated by 1px borders. */
function SlotStack(
    props: { state: SidebarState; onPromote: (id: PanelId) => void },
): React.ReactElement {
    const { state, onPromote } = props;
    const { slots } = state;

    const stalePanels = state.stalePanels ?? [];
    return (
        <div className="flex-1 flex flex-col min-h-0">
            <Slot position="A" panelId={slots.slotA} state={state} stale={stalePanels.includes(slots.slotA)} onPromote={onPromote} />
            <div className="border-t border-ml-border" />
            <Slot position="B" panelId={slots.slotB} state={state} stale={stalePanels.includes(slots.slotB)} onPromote={onPromote} />
            <div className="border-t border-ml-border" />
            <Slot position="C" panelId={slots.slotC} state={state} stale={stalePanels.includes(slots.slotC)} onPromote={onPromote} />
        </div>
    );
}

export default Sidebar;
