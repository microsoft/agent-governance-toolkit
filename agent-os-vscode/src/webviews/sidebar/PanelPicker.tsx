// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * PanelPicker Overlay
 *
 * Full-screen overlay for assigning panels to the 3 sidebar slots.
 * Uses draft state so changes are only committed on Apply.
 */
import React, { useState, useEffect, useRef } from 'react';
import {
    PanelId,
    SlotConfig,
    PANEL_LABELS,
} from './types';
import {
    SlotKey,
    SLOT_KEYS,
    findSlotForPanel,
    slotBadgeLetter,
    hasChanges,
} from './pickerUtils';

interface PanelPickerProps {
    current: SlotConfig;
    onApply: (slots: SlotConfig) => void;
    onCancel: () => void;
}

const ALL_PANELS: PanelId[] = [
    'governance-hub',
    'slo-dashboard',
    'audit-log',
    'agent-topology',
    'active-policies',
    'safety-stats',
    'kernel-debugger',
    'memory-browser',
];

const SLOT_LABELS: Record<SlotKey, string> = {
    slotA: 'Slot A',
    slotB: 'Slot B',
    slotC: 'Slot C',
};

/** Header with title, Cancel, and Apply buttons. */
function PickerHeader(props: {
    canApply: boolean;
    onApply: () => void;
    onCancel: () => void;
}): React.ReactElement {
    return (
        <div className="flex items-center justify-between px-ml-sm py-ml-sm border-b border-ml-border">
            <span className="text-sm font-semibold text-ml-text">
                Configure Panels
            </span>
            <div className="flex gap-2">
                <button
                    className="px-3 py-1 text-xs text-ml-text-muted hover:text-ml-text rounded-ml"
                    onClick={props.onCancel}
                >
                    Cancel
                </button>
                <button
                    className="px-3 py-1 text-xs text-white bg-ml-accent rounded-ml disabled:opacity-40"
                    disabled={!props.canApply}
                    onClick={props.onApply}
                >
                    Apply
                </button>
            </div>
        </div>
    );
}

/** A single slot zone showing the assigned panel name. */
function SlotZone(props: {
    slotKey: SlotKey;
    panelId: PanelId;
    isSelected: boolean;
    onSelect: () => void;
}): React.ReactElement {
    const borderClass = props.isSelected ? 'border-ml-accent' : 'border-ml-border';
    return (
        <button
            className={`flex-1 bg-ml-surface border ${borderClass} rounded-ml p-ml-sm text-left`}
            onClick={props.onSelect}
            aria-label={`${SLOT_LABELS[props.slotKey]}: ${PANEL_LABELS[props.panelId]}`}
        >
            <div className="text-[10px] uppercase tracking-wider text-ml-text-muted mb-1">
                {SLOT_LABELS[props.slotKey]}
            </div>
            <div className="text-xs text-ml-text truncate">
                {PANEL_LABELS[props.panelId]}
            </div>
        </button>
    );
}

/** Row of 3 slot zones. */
function SlotRow(props: {
    draft: SlotConfig;
    activeSlot: SlotKey | null;
    onSelectSlot: (key: SlotKey) => void;
}): React.ReactElement {
    return (
        <div className="flex gap-2 px-ml-sm py-ml-sm">
            {SLOT_KEYS.map((key) => (
                <SlotZone
                    key={key}
                    slotKey={key}
                    panelId={props.draft[key]}
                    isSelected={props.activeSlot === key}
                    onSelect={() => props.onSelectSlot(key)}
                />
            ))}
        </div>
    );
}

/** A single panel card in the picker grid. */
function PanelCard(props: {
    panelId: PanelId;
    assignedSlot: SlotKey | null;
    onClick: () => void;
}): React.ReactElement {
    return (
        <button
            className="bg-ml-surface hover:bg-ml-surface-hover border border-ml-border rounded-ml p-ml-sm cursor-pointer text-left relative"
            onClick={props.onClick}
            aria-label={`Assign ${PANEL_LABELS[props.panelId]}`}
        >
            <span className="text-xs text-ml-text">
                {PANEL_LABELS[props.panelId]}
            </span>
            {props.assignedSlot && (
                <span className="absolute top-1 right-1 w-4 h-4 flex items-center justify-center rounded-full bg-ml-accent text-white text-[9px] font-bold">
                    {slotBadgeLetter(props.assignedSlot)}
                </span>
            )}
        </button>
    );
}

/** 2x4 grid of all panel cards. */
function PanelGrid(props: {
    draft: SlotConfig;
    onSelectPanel: (panelId: PanelId) => void;
}): React.ReactElement {
    return (
        <div className="grid grid-cols-2 gap-2 px-ml-sm pb-ml-sm">
            {ALL_PANELS.map((id) => (
                <PanelCard
                    key={id}
                    panelId={id}
                    assignedSlot={findSlotForPanel(props.draft, id)}
                    onClick={() => props.onSelectPanel(id)}
                />
            ))}
        </div>
    );
}

/** Full-screen panel picker overlay. */
export function PanelPicker(props: PanelPickerProps): React.ReactElement {
    const { current, onApply, onCancel } = props;
    const [draft, setDraft] = useState<SlotConfig>({ ...current });
    const [activeSlot, setActiveSlot] = useState<SlotKey | null>(null);
    const dialogRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        dialogRef.current?.focus();
    }, []);

    const handleKeyDown = (e: React.KeyboardEvent): void => {
        if (e.key === 'Escape') { onCancel(); }
    };

    const handleSelectPanel = (panelId: PanelId): void => {
        if (!activeSlot) {
            return;
        }
        const existingSlot = findSlotForPanel(draft, panelId);
        const next = { ...draft };
        if (existingSlot && existingSlot !== activeSlot) {
            next[existingSlot] = draft[activeSlot];
        }
        next[activeSlot] = panelId;
        setDraft(next);
    };

    return (
        <div
            ref={dialogRef}
            role="dialog"
            aria-modal="true"
            aria-label="Configure panel layout"
            tabIndex={-1}
            onKeyDown={handleKeyDown}
            className="fixed inset-0 z-50 bg-ml-bg flex flex-col outline-none">
            <PickerHeader
                canApply={hasChanges(current, draft)}
                onApply={() => onApply(draft)}
                onCancel={onCancel}
            />
            <SlotRow
                draft={draft}
                activeSlot={activeSlot}
                onSelectSlot={setActiveSlot}
            />
            <div className="flex-1 overflow-auto">
                <PanelGrid draft={draft} onSelectPanel={handleSelectPanel} />
            </div>
        </div>
    );
}

export default PanelPicker;
