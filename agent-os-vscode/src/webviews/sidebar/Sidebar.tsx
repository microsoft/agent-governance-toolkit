// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Sidebar Root Component
 *
 * Renders the 3-slot governance sidebar. Subscribes to extension host
 * state updates, manages the panel picker overlay, and runs scan rotation.
 */
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { getVSCodeAPI, onMessage, ExtensionMessage } from '../shared/vscode';
import {
    SidebarState,
    SlotConfig,
    PanelId,
    SlotKey,
    AttentionMode,
    DEFAULT_SLOTS,
} from './types';
import { Slot } from './Slot';
import { PanelPicker } from './PanelPicker';
import { nextSlot, shouldScan, SCAN_INTERVAL_MS, IDLE_RESUME_MS } from './scanController';

const INITIAL_STATE: SidebarState = {
    slots: DEFAULT_SLOTS, userSlots: DEFAULT_SLOTS, attentionMode: 'auto',
    slo: null, audit: null, topology: null,
    policy: null, stats: null, kernel: null, memory: null, hub: null,
    stalePanels: [],
};

function handleStateMessage(msg: ExtensionMessage): SidebarState | null {
    if (msg.type !== 'stateUpdate') { return null; }
    return msg.state as SidebarState;
}

/** Hook: manages scan rotation, pause/resume, and reduced motion detection. */
function useScanRotation(mode: AttentionMode) {
    const [activeSlot, setActiveSlot] = useState<SlotKey>('slotA');
    const [reducedMotion, setReducedMotion] = useState(false);
    const scanPaused = useRef(false);
    const resumeTimer = useRef<ReturnType<typeof setTimeout>>();

    useEffect(() => {
        const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
        setReducedMotion(mq.matches);
        const handler = (e: MediaQueryListEvent) => setReducedMotion(e.matches);
        mq.addEventListener('change', handler);
        return () => mq.removeEventListener('change', handler);
    }, []);

    useEffect(() => {
        if (!shouldScan(mode, reducedMotion)) { return; }
        const id = setInterval(() => {
            if (!scanPaused.current) { setActiveSlot(s => nextSlot(s)); }
        }, SCAN_INTERVAL_MS);
        return () => clearInterval(id);
    }, [mode, reducedMotion]);

    useEffect(() => {
        return () => { if (resumeTimer.current) { clearTimeout(resumeTimer.current); } };
    }, []);

    const pause = useCallback(() => {
        scanPaused.current = true;
        if (resumeTimer.current) { clearTimeout(resumeTimer.current); }
    }, []);
    const resume = useCallback(() => {
        resumeTimer.current = setTimeout(() => { scanPaused.current = false; }, IDLE_RESUME_MS);
    }, []);

    return { activeSlot, scanning: shouldScan(mode, reducedMotion), pause, resume };
}

/** Root sidebar component with 3 configurable panel slots. */
export function Sidebar(): React.ReactElement {
    const [state, setState] = useState<SidebarState>(INITIAL_STATE);
    const [pickerOpen, setPickerOpen] = useState(false);
    const scan = useScanRotation(state.attentionMode);

    useEffect(() => {
        const cleanup = onMessage((msg) => {
            const next = handleStateMessage(msg);
            if (next) { setState(next); }
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
    const handleToggleMode = useCallback(() => {
        const next: AttentionMode = state.attentionMode === 'auto' ? 'manual' : 'auto';
        getVSCodeAPI().postMessage({ type: 'setAttentionMode', mode: next });
    }, [state.attentionMode]);

    return (
        <div className="h-screen flex flex-col bg-ml-bg text-ml-text overflow-hidden">
            <SidebarHeader
                attentionMode={state.attentionMode}
                onToggleMode={handleToggleMode}
                onOpenPicker={() => setPickerOpen(true)}
                onOpenBrowser={() => getVSCodeAPI().postMessage({ type: 'openInBrowser' })}
            />
            <SlotStack
                state={state}
                activeSlot={scan.activeSlot}
                scanning={scan.scanning}
                onPromote={handlePromote}
                onPointerEnter={scan.pause}
                onPointerLeave={scan.resume}
            />
            {pickerOpen && (
                <PanelPicker
                    current={state.slots}
                    onApply={handleApply}
                    onCancel={() => setPickerOpen(false)}
                />
            )}
        </div>
    );
}

/** Header bar with title, browser button, attention toggle, and gear button. */
function SidebarHeader(props: {
    attentionMode: AttentionMode;
    onToggleMode: () => void;
    onOpenPicker: () => void;
    onOpenBrowser: () => void;
}): React.ReactElement {
    const isAuto = props.attentionMode === 'auto';
    return (
        <div className="flex items-center justify-between px-ml-sm py-ml-xs border-b border-ml-border">
            <span className="text-xs font-semibold uppercase tracking-wider text-ml-text-muted">
                Governance
            </span>
            <div className="flex items-center gap-1">
                <button
                    className="p-1 rounded hover:bg-ml-surface-hover text-ml-text-muted hover:text-ml-text"
                    onClick={props.onOpenBrowser}
                    aria-label="Open in browser"
                    title="Open in browser"
                >
                    <LinkExternalIcon />
                </button>
                <button
                    className="px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider hover:bg-ml-surface-hover text-ml-text-muted hover:text-ml-text"
                    onClick={props.onToggleMode}
                    aria-label={`Switch to ${isAuto ? 'manual' : 'auto'} mode`}
                    title={isAuto ? 'Auto: scanning + priority' : 'Manual: locked to your config'}
                >
                    {isAuto ? 'Auto' : 'Manual'}
                </button>
                <button
                    className="p-1 rounded hover:bg-ml-surface-hover text-ml-text-muted hover:text-ml-text"
                    onClick={props.onOpenPicker}
                    aria-label="Configure panel slots"
                    title="Configure panel slots"
                >
                    <GearIcon />
                </button>
            </div>
        </div>
    );
}

/** Inline 14x14 gear SVG. */
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

/** Inline 14x14 link-external SVG. */
function LinkExternalIcon(): React.ReactElement {
    return (
        <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
            <path d="M1.5 1H6V2.5H2.5V13.5H13.5V10H15V14.5H1V1.5L1.5 1Z" />
            <path d="M15 1.5V8H13.5V3.56L7.53 9.53L6.47 8.47L12.44 2.5H8V1H14.5L15 1.5Z" />
        </svg>
    );
}

/** Renders the 3 slots with scan highlight and hover handlers. */
function SlotStack(props: {
    state: SidebarState;
    activeSlot: SlotKey;
    scanning: boolean;
    onPromote: (id: PanelId) => void;
    onPointerEnter: () => void;
    onPointerLeave: () => void;
}): React.ReactElement {
    const { state, activeSlot, scanning, onPromote, onPointerEnter, onPointerLeave } = props;
    const { slots } = state;
    const stalePanels = state.stalePanels ?? [];

    const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
        const target = e.target as HTMLElement;
        const slots = target.closest('.flex-1')?.querySelectorAll('[role="region"]');
        if (!slots) { return; }
        const slotArray = Array.from(slots);
        const currentIndex = slotArray.indexOf(target);
        if (currentIndex < 0) { return; }

        if (e.key === 'ArrowDown' && currentIndex < slotArray.length - 1) {
            e.preventDefault();
            (slotArray[currentIndex + 1] as HTMLElement).focus();
        } else if (e.key === 'ArrowUp' && currentIndex > 0) {
            e.preventDefault();
            (slotArray[currentIndex - 1] as HTMLElement).focus();
        }
    }, []);

    return (
        <div
            className="flex-1 flex flex-col min-h-0"
            onPointerEnter={onPointerEnter}
            onPointerLeave={onPointerLeave}
            onFocus={onPointerEnter}
            onBlur={onPointerLeave}
            onKeyDown={handleKeyDown}
        >
            <Slot position="A" panelId={slots.slotA} state={state} stale={stalePanels.includes(slots.slotA)} active={scanning && activeSlot === 'slotA'} onPromote={onPromote} />
            <div className="border-t border-ml-border" />
            <Slot position="B" panelId={slots.slotB} state={state} stale={stalePanels.includes(slots.slotB)} active={scanning && activeSlot === 'slotB'} onPromote={onPromote} />
            <div className="border-t border-ml-border" />
            <Slot position="C" panelId={slots.slotC} state={state} stale={stalePanels.includes(slots.slotC)} active={scanning && activeSlot === 'slotC'} onPromote={onPromote} />
        </div>
    );
}

export default Sidebar;
