// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Event Bus
 *
 * Minimal typed pub/sub for host-side coordination between
 * GovernanceStore, SidebarProvider, and future consumers.
 * Synchronous dispatch — events are coordination signals, not data transport.
 */

import type { GovernanceEvent } from './types';

/** Disposable subscription handle. */
export interface Disposable {
    dispose(): void;
}

/**
 * Typed event bus for governance sidebar coordination.
 */
export class GovernanceEventBus {
    private readonly _listeners = new Set<(event: GovernanceEvent) => void>();

    /** Publish an event to all current subscribers. Fault-isolated per listener. */
    publish(event: GovernanceEvent): void {
        for (const listener of this._listeners) {
            try { listener(event); } catch { /* fault-isolated: one bad listener cannot break others */ }
        }
    }

    /** Subscribe to all events. Returns a disposable to unsubscribe. */
    subscribe(listener: (event: GovernanceEvent) => void): Disposable {
        this._listeners.add(listener);
        return {
            dispose: () => { this._listeners.delete(listener); },
        };
    }

    /** Remove all subscribers. */
    dispose(): void {
        this._listeners.clear();
    }
}
