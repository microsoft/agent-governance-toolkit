// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Store
 *
 * Extension-scoped state owner for the 3-slot governance sidebar.
 * Wraps the existing polling model with deduplication, visibility
 * gating, and per-panel latency isolation.
 */

import type * as vscode from 'vscode';
import type { SidebarState, SlotConfig, PanelId } from './types';
import { DEFAULT_SLOTS } from './types';
import { GovernanceEventBus, Disposable } from './governanceEventBus';
import {
    DataProviders,
    fetchSLO, fetchTopology, fetchAudit, fetchPolicy,
    fetchStats, fetchKernel, fetchMemory, deriveHub,
} from './dataAggregator';
import {
    type PanelTiming, createTiming, recordDuration,
    shouldIsolate, shouldRejoin, markIsolated, markRejoined,
    recordFastTick, resetFastTick,
} from './panelLatencyTracker';

const SLOT_CONFIG_KEY = 'agentOS.slotConfig';
const DEFAULT_THRESHOLD_MS = 2000;

/** Data source keys that map to individual fetch functions. */
type DataSourceKey = 'slo' | 'topology' | 'audit' | 'policy' | 'stats' | 'kernel' | 'memory';

const ALL_SOURCES: DataSourceKey[] = ['slo', 'topology', 'audit', 'policy', 'stats', 'kernel', 'memory'];

/** Map from data source key to the PanelId that consumes it. */
const SOURCE_TO_PANEL: Record<DataSourceKey, PanelId> = {
    slo: 'slo-dashboard', topology: 'agent-topology', audit: 'audit-log',
    policy: 'active-policies', stats: 'safety-stats',
    kernel: 'kernel-debugger', memory: 'memory-browser',
};

/**
 * Central state store for the governance sidebar.
 * Owns polling, deduplication, visibility gating, and latency isolation.
 */
export class GovernanceStore {
    private _state: SidebarState;
    private _lastJson = '';
    private _visible = false;
    private _fetching = false;
    private _interval: ReturnType<typeof setInterval> | undefined;
    private readonly _timings = new Map<DataSourceKey, PanelTiming>();
    private readonly _isolatedTimers = new Map<DataSourceKey, ReturnType<typeof setInterval>>();
    private readonly _thresholdMs: number;

    constructor(
        private readonly _providers: DataProviders,
        private readonly _bus: GovernanceEventBus,
        private readonly _workspaceState: vscode.Memento,
        private readonly _refreshIntervalMs: number,
        thresholdMs?: number,
    ) {
        this._thresholdMs = thresholdMs ?? DEFAULT_THRESHOLD_MS;
        const persisted = _workspaceState.get<SlotConfig>(SLOT_CONFIG_KEY);
        this._state = {
            slots: persisted ?? DEFAULT_SLOTS,
            slo: null, audit: null, topology: null, policy: null,
            stats: null, kernel: null, memory: null, hub: null,
            stalePanels: [],
        };
        for (const key of ALL_SOURCES) {
            this._timings.set(key, createTiming());
        }
        this._interval = setInterval(() => this._tick(), this._refreshIntervalMs);
    }

    getState(): SidebarState { return this._state; }

    subscribe(listener: (state: SidebarState) => void): Disposable {
        return this._bus.subscribe((event) => {
            if (event.type === 'stateChanged') { listener(event.state); }
        });
    }

    refreshNow(): void { this._tick(); }

    setSlots(slots: SlotConfig): void {
        this._state = { ...this._state, slots };
        this._workspaceState.update(SLOT_CONFIG_KEY, slots);
        this._bus.publish({ type: 'slotConfigChanged', slots });
        this._emitIfChanged();
    }

    setVisible(visible: boolean): void {
        this._visible = visible;
        this._bus.publish({ type: 'visibilityChanged', visible });
        if (visible) { this._emitIfChanged(); }
    }

    dispose(): void {
        if (this._interval) { clearInterval(this._interval); this._interval = undefined; }
        for (const timer of this._isolatedTimers.values()) { clearInterval(timer); }
        this._isolatedTimers.clear();
    }

    private async _tick(): Promise<void> {
        if (this._fetching) { return; }
        this._fetching = true;
        try {
            const activeSources = ALL_SOURCES.filter(k => !this._isIsolated(k));
            await this._fetchSources(activeSources);
            this._emitIfChanged();
        } finally {
            this._fetching = false;
        }
    }

    private async _fetchSources(sources: DataSourceKey[]): Promise<void> {
        const patch: Partial<Record<DataSourceKey, unknown>> = {};
        for (const key of sources) {
            const start = performance.now();
            patch[key] = await this._fetchOne(key);
            const elapsed = performance.now() - start;
            this._trackLatency(key, elapsed);
        }
        this._state = { ...this._state, ...patch } as SidebarState;
        const hub = deriveHub(this._state);
        this._state = { ...this._state, hub };
    }

    private async _fetchOne(key: DataSourceKey): Promise<unknown> {
        switch (key) {
            case 'slo': return await fetchSLO(this._providers) ?? this._state.slo;
            case 'topology': return fetchTopology(this._providers) ?? this._state.topology;
            case 'audit': return fetchAudit(this._providers) ?? this._state.audit;
            case 'policy': return await fetchPolicy(this._providers) ?? this._state.policy;
            case 'stats': return fetchStats(this._providers) ?? this._state.stats;
            case 'kernel': return fetchKernel(this._providers) ?? this._state.kernel;
            case 'memory': return fetchMemory(this._providers) ?? this._state.memory;
        }
    }

    private _trackLatency(key: DataSourceKey, elapsed: number): void {
        let timing = this._timings.get(key)!;
        timing = recordDuration(timing, elapsed);
        const panelId = SOURCE_TO_PANEL[key];

        if (timing.isolated) {
            timing = elapsed <= this._thresholdMs ? recordFastTick(timing) : resetFastTick(timing);
            if (shouldRejoin(timing)) {
                timing = markRejoined(timing);
                this._clearIsolatedTimer(key);
                this._updateStalePanels(key, false);
                this._bus.publish({ type: 'panelRejoined', panelId });
            }
        } else if (shouldIsolate(timing, this._thresholdMs)) {
            timing = markIsolated(timing);
            this._startIsolatedTimer(key);
            this._updateStalePanels(key, true);
            this._bus.publish({ type: 'panelIsolated', panelId });
        }

        this._timings.set(key, timing);
    }

    private _isIsolated(key: DataSourceKey): boolean {
        return this._timings.get(key)?.isolated === true;
    }

    private _startIsolatedTimer(key: DataSourceKey): void {
        const offset = this._refreshIntervalMs / 2;
        const timer = setInterval(() => {
            this._fetchSources([key])
                .then(() => this._emitIfChanged())
                .catch(() => { /* provider errors handled by fetchOne fallbacks */ });
        }, offset);
        this._isolatedTimers.set(key, timer);
    }

    private _clearIsolatedTimer(key: DataSourceKey): void {
        const timer = this._isolatedTimers.get(key);
        if (timer) { clearInterval(timer); this._isolatedTimers.delete(key); }
    }

    private _updateStalePanels(key: DataSourceKey, stale: boolean): void {
        const current = this._state.stalePanels;
        const panelId = SOURCE_TO_PANEL[key];
        if (stale && !current.includes(panelId)) {
            this._state = { ...this._state, stalePanels: [...current, panelId] };
        } else if (!stale) {
            this._state = { ...this._state, stalePanels: current.filter(p => p !== panelId) };
        }
    }

    private _emitIfChanged(): void {
        if (!this._visible) { return; }
        const json = JSON.stringify(this._state);
        if (json === this._lastJson) { return; }
        this._lastJson = json;
        this._bus.publish({ type: 'stateChanged', state: this._state });
    }
}
