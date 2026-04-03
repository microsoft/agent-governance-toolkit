// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/** Extension-scoped state owner for the governance sidebar.
 * Event-driven refresh from LiveSREClient/AuditLogger with heartbeat safety net. */

import type * as vscode from 'vscode';
import type { SidebarState, SlotConfig, PanelId, AttentionMode, DetailPanelType } from './types';
import { DEFAULT_SLOTS } from './types';
import { GovernanceEventBus, Disposable } from './governanceEventBus';
import {
    DataProviders,
    fetchSLO, fetchTopology, fetchAudit, fetchPolicy,
    fetchStats, fetchKernel, fetchMemory, deriveHub,
} from './dataAggregator';
import {
    fetchSLODetail, fetchTopologyDetail, fetchAuditDetail,
    fetchPolicyDetail, fetchHubDetail,
    fetchKernelDetail, fetchMemoryDetail, fetchStatsDetail,
} from './detailFetchers';
import {
    type PanelTiming, createTiming, recordDuration,
    shouldIsolate, shouldRejoin, markIsolated, markRejoined,
    recordFastTick, resetFastTick,
} from './panelLatencyTracker';
import { rankPanelsByUrgency } from './priorityEngine';
import { wireStoreEvents, ChangeSource } from './storeEventWiring';

const SLOT_CONFIG_KEY = 'agentOS.slotConfig';
const ATTENTION_MODE_KEY = 'agentOS.attentionMode';
const DEFAULT_THRESHOLD_MS = 2000;
const HEARTBEAT_MULTIPLIER = 3;
const MIN_HEARTBEAT_MS = 15000;
type DataSourceKey = 'slo' | 'topology' | 'audit' | 'policy' | 'stats' | 'kernel' | 'memory';
const ALL_SOURCES: DataSourceKey[] = ['slo', 'topology', 'audit', 'policy', 'stats', 'kernel', 'memory'];
const LIVE_SOURCES: DataSourceKey[] = ['slo', 'topology', 'policy'];
const LOCAL_SOURCES: DataSourceKey[] = ['audit', 'stats', 'kernel', 'memory'];
const SOURCE_TO_PANEL: Record<DataSourceKey, PanelId> = {
    slo: 'slo-dashboard', topology: 'agent-topology', audit: 'audit-log',
    policy: 'active-policies', stats: 'safety-stats', kernel: 'kernel-debugger', memory: 'memory-browser',
};

export class GovernanceStore {
    private _state: SidebarState;
    private _lastJson = '';
    private _visible = false;
    private _fetching = false;
    private _interval: ReturnType<typeof setInterval> | undefined;
    private readonly _timings = new Map<DataSourceKey, PanelTiming>();
    private readonly _isolatedTimers = new Map<DataSourceKey, ReturnType<typeof setInterval>>();
    private readonly _eventSubs: vscode.Disposable[] = [];
    private readonly _thresholdMs: number;
    private readonly _detailSubs = new Map<DetailPanelType, Set<(data: unknown) => void>>();
    constructor(
        private _providers: DataProviders,
        private readonly _bus: GovernanceEventBus,
        private readonly _workspaceState: vscode.Memento,
        private readonly _refreshIntervalMs: number,
        thresholdMs?: number,
        liveClient?: ChangeSource,
        auditLogger?: ChangeSource,
    ) {
        this._thresholdMs = thresholdMs ?? DEFAULT_THRESHOLD_MS;
        const slots = _workspaceState.get<SlotConfig>(SLOT_CONFIG_KEY) ?? DEFAULT_SLOTS;
        const mode = _workspaceState.get<AttentionMode>(ATTENTION_MODE_KEY) ?? 'auto';
        this._state = {
            slots, userSlots: slots, attentionMode: mode,
            slo: null, audit: null, topology: null, policy: null,
            stats: null, kernel: null, memory: null, hub: null,
            stalePanels: [],
        };
        for (const k of ALL_SOURCES) { this._timings.set(k, createTiming()); }
        this._interval = setInterval(() => this._tick(),
            Math.max(this._refreshIntervalMs * HEARTBEAT_MULTIPLIER, MIN_HEARTBEAT_MS));
        this._eventSubs = wireStoreEvents(
            liveClient, auditLogger,
            () => this._fetchGroupAndEmit(LIVE_SOURCES),
            () => this._fetchGroupAndEmit(LOCAL_SOURCES),
        );
    }
    getState(): SidebarState { return this._state; }
    subscribe(listener: (state: SidebarState) => void): Disposable {
        return this._bus.subscribe((event) => {
            if (event.type === 'stateChanged') { listener(event.state); }
        });
    }
    /** Subscribe a detail panel to receive rich data on each refresh cycle. */
    onDetailSubscribe(panelType: DetailPanelType, cb: (data: unknown) => void): Disposable {
        if (!this._detailSubs.has(panelType)) { this._detailSubs.set(panelType, new Set()); }
        this._detailSubs.get(panelType)!.add(cb);
        this._fetchDetailAndNotify(panelType).catch(() => { /* initial fetch error is non-fatal */ });
        return {
            dispose: () => {
                const set = this._detailSubs.get(panelType);
                set?.delete(cb);
                if (set?.size === 0) { this._detailSubs.delete(panelType); }
            },
        };
    }
    refreshNow(): void { this._tick(); }
    setSlots(slots: SlotConfig): void {
        this._state = { ...this._state, slots, userSlots: slots };
        this._workspaceState.update(SLOT_CONFIG_KEY, slots);
        this._bus.publish({ type: 'slotConfigChanged', slots });
        this._emitIfChanged();
    }
    setAttentionMode(mode: AttentionMode): void {
        const s = this._state;
        this._state = mode === 'manual'
            ? { ...s, attentionMode: mode, slots: s.userSlots }
            : { ...s, attentionMode: mode, userSlots: s.slots };
        this._workspaceState.update(ATTENTION_MODE_KEY, mode);
        this._emitIfChanged();
    }
    setVisible(visible: boolean): void {
        this._visible = visible;
        this._bus.publish({ type: 'visibilityChanged', visible });
        if (visible) { this._emitIfChanged(); }
    }
    /** Hot-swap providers and re-wire event subscriptions (called after async createProviders). */
    upgradeProviders(providers: DataProviders, liveClient?: ChangeSource, auditLogger?: ChangeSource): void {
        this._providers = providers;
        // Tear down old event subs and re-wire with new sources
        for (const sub of this._eventSubs) { sub.dispose(); }
        this._eventSubs.length = 0;
        this._eventSubs.push(...wireStoreEvents(
            liveClient, auditLogger,
            () => this._fetchGroupAndEmit(LIVE_SOURCES),
            () => this._fetchGroupAndEmit(LOCAL_SOURCES),
        ));
        // Immediate refresh with the new providers
        this._tick();
    }
    dispose(): void {
        if (this._interval) { clearInterval(this._interval); this._interval = undefined; }
        for (const t of this._isolatedTimers.values()) { clearInterval(t); }
        this._isolatedTimers.clear();
        for (const sub of this._eventSubs) { sub.dispose(); }
        this._eventSubs.length = 0;
        this._detailSubs.clear();
    }
    private async _tick(): Promise<void> {
        if (this._fetching) { return; }
        this._fetching = true;
        try {
            const activeSources = ALL_SOURCES.filter(k => !this._isIsolated(k));
            await this._fetchSources(activeSources);
            this._applyPriority();
            this._emitIfChanged();
            for (const pt of this._detailSubs.keys()) {
                this._fetchDetailAndNotify(pt).catch(() => { /* detail fetch errors are non-fatal */ });
            }
        } finally {
            this._fetching = false;
        }
    }
    /** Fetch detail data for a panel type and notify its subscribers. */
    private async _fetchDetailAndNotify(panelType: DetailPanelType): Promise<void> {
        const subs = this._detailSubs.get(panelType);
        if (!subs || subs.size === 0) { return; }
        const fetchers: Record<DetailPanelType, () => Promise<unknown>> = {
            slo: () => fetchSLODetail(this._providers),
            topology: async () => fetchTopologyDetail(this._providers),
            audit: async () => fetchAuditDetail(this._providers),
            policy: () => fetchPolicyDetail(this._providers),
            hub: () => fetchHubDetail(this._providers),
            kernel: async () => fetchKernelDetail(this._providers),
            memory: async () => fetchMemoryDetail(this._providers),
            stats: async () => fetchStatsDetail(this._providers),
        };
        const data = await (fetchers[panelType]?.() ?? Promise.resolve(null));
        for (const cb of subs) { cb(data); }
    }
    private async _fetchSources(sources: DataSourceKey[]): Promise<void> {
        const results = await Promise.all(sources.map(async (k) => {
            const t0 = performance.now();
            const value = await this._fetchOne(k);
            this._trackLatency(k, performance.now() - t0);
            return [k, value] as const;
        }));
        const patch: Partial<Record<DataSourceKey, unknown>> = {};
        for (const [k, value] of results) { patch[k] = value; }
        const merged = { ...this._state, ...patch } as SidebarState;
        this._state = { ...merged, hub: deriveHub(merged) };
    }
    private async _fetchOne(key: DataSourceKey): Promise<unknown> {
        try {
            switch (key) {
                case 'slo': return await fetchSLO(this._providers) ?? this._state.slo;
                case 'topology': return fetchTopology(this._providers) ?? this._state.topology;
                case 'audit': return fetchAudit(this._providers) ?? this._state.audit;
                case 'policy': return await fetchPolicy(this._providers) ?? this._state.policy;
                case 'stats': return fetchStats(this._providers) ?? this._state.stats;
                case 'kernel': return fetchKernel(this._providers) ?? this._state.kernel;
                case 'memory': return fetchMemory(this._providers) ?? this._state.memory;
            }
        } catch { return this._state[key]; }
    }
    private _trackLatency(key: DataSourceKey, elapsed: number): void {
        let timing = recordDuration(this._timings.get(key)!, elapsed);
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

    private _isIsolated(key: DataSourceKey): boolean { return this._timings.get(key)?.isolated === true; }
    private _startIsolatedTimer(key: DataSourceKey): void {
        const timer = setInterval(() => {
            this._fetchSources([key])
                .then(() => { this._applyPriority(); this._emitIfChanged(); })
                .catch(() => { /* provider errors handled by fetchOne fallbacks */ });
        }, this._refreshIntervalMs / 2);
        this._isolatedTimers.set(key, timer);
    }

    private _clearIsolatedTimer(key: DataSourceKey): void {
        const t = this._isolatedTimers.get(key);
        if (t) { clearInterval(t); this._isolatedTimers.delete(key); }
    }
    private _updateStalePanels(key: DataSourceKey, stale: boolean): void {
        const panelId = SOURCE_TO_PANEL[key];
        const current = this._state.stalePanels;
        if (stale && !current.includes(panelId)) {
            this._state = { ...this._state, stalePanels: [...current, panelId] };
        } else if (!stale) {
            this._state = { ...this._state, stalePanels: current.filter(p => p !== panelId) };
        }
    }
    private async _fetchGroupAndEmit(sources: DataSourceKey[]): Promise<void> {
        if (this._fetching) { return; }
        this._fetching = true;
        try {
            const active = sources.filter(k => !this._isIsolated(k));
            await this._fetchSources(active);
            this._applyPriority();
            this._emitIfChanged();
        } finally {
            this._fetching = false;
        }
    }
    private _applyPriority(): void {
        if (this._state.attentionMode !== 'auto') { return; }
        const ranked = rankPanelsByUrgency(this._state, this._state.userSlots);
        const s = this._state.slots;
        if (ranked.slotA !== s.slotA || ranked.slotB !== s.slotB || ranked.slotC !== s.slotC) {
            this._state = { ...this._state, slots: ranked };
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
