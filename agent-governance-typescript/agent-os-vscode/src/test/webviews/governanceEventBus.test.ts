// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import { GovernanceEventBus } from '../../webviews/sidebar/governanceEventBus';
import type { GovernanceEvent, SidebarState, SlotConfig } from '../../webviews/sidebar/types';
import { DEFAULT_SLOTS } from '../../webviews/sidebar/types';

function makeState(): SidebarState {
    return {
        slots: DEFAULT_SLOTS, userSlots: DEFAULT_SLOTS, attentionMode: 'auto',
        slo: null, audit: null, topology: null, policy: null,
        stats: null, kernel: null, memory: null, hub: null,
        stalePanels: [],
    };
}

suite('GovernanceEventBus', () => {
    let bus: GovernanceEventBus;

    setup(() => { bus = new GovernanceEventBus(); });
    teardown(() => { bus.dispose(); });

    test('subscriber receives published events', () => {
        const received: GovernanceEvent[] = [];
        bus.subscribe((e) => received.push(e));
        const event: GovernanceEvent = { type: 'stateChanged', state: makeState() };
        bus.publish(event);
        assert.strictEqual(received.length, 1);
        assert.strictEqual(received[0].type, 'stateChanged');
    });

    test('disposed subscriber does not receive events', () => {
        const received: GovernanceEvent[] = [];
        const sub = bus.subscribe((e) => received.push(e));
        sub.dispose();
        bus.publish({ type: 'refreshRequested' });
        assert.strictEqual(received.length, 0);
    });

    test('dispose clears all subscribers', () => {
        const received: GovernanceEvent[] = [];
        bus.subscribe((e) => received.push(e));
        bus.subscribe((e) => received.push(e));
        bus.dispose();
        bus.publish({ type: 'refreshRequested' });
        assert.strictEqual(received.length, 0);
    });

    test('throwing listener does not break other subscribers', () => {
        const received: GovernanceEvent[] = [];
        bus.subscribe(() => { throw new Error('bad listener'); });
        bus.subscribe((e) => received.push(e));
        bus.publish({ type: 'refreshRequested' });
        assert.strictEqual(received.length, 1, 'Second subscriber should still receive event');
    });

    test('multiple subscribers all receive the same event', () => {
        const a: GovernanceEvent[] = [];
        const b: GovernanceEvent[] = [];
        bus.subscribe((e) => a.push(e));
        bus.subscribe((e) => b.push(e));
        bus.publish({ type: 'visibilityChanged', visible: true });
        assert.strictEqual(a.length, 1);
        assert.strictEqual(b.length, 1);
        assert.strictEqual(a[0].type, 'visibilityChanged');
    });
});
