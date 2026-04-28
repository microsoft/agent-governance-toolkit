// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import { wireStoreEvents, ChangeSource } from '../../webviews/sidebar/storeEventWiring';

/** Minimal mock EventEmitter matching vscode.Event<void> pattern. */
function createMockSource(): ChangeSource & { fire: () => void; listeners: Set<() => void> } {
    const listeners = new Set<() => void>();
    return {
        listeners,
        fire: () => { for (const l of listeners) { l(); } },
        onDidChange: (listener: () => void) => {
            listeners.add(listener);
            return { dispose: () => { listeners.delete(listener); } };
        },
    };
}

suite('wireStoreEvents', () => {
    test('both sources undefined returns empty array', () => {
        const subs = wireStoreEvents(undefined, undefined, () => {}, () => {});
        assert.strictEqual(subs.length, 0);
    });

    test('both sources defined returns two disposables', () => {
        const live = createMockSource();
        const audit = createMockSource();
        const subs = wireStoreEvents(live, audit, () => {}, () => {});
        assert.strictEqual(subs.length, 2);
    });

    test('live source fires onLiveChange callback', () => {
        const live = createMockSource();
        let called = false;
        wireStoreEvents(live, undefined, () => { called = true; }, () => {});
        live.fire();
        assert.strictEqual(called, true);
    });

    test('audit source fires onLocalChange callback', () => {
        const audit = createMockSource();
        let called = false;
        wireStoreEvents(undefined, audit, () => {}, () => { called = true; });
        audit.fire();
        assert.strictEqual(called, true);
    });

    test('disposing returned disposables unsubscribes', () => {
        const live = createMockSource();
        let count = 0;
        const subs = wireStoreEvents(live, undefined, () => { count++; }, () => {});
        live.fire();
        assert.strictEqual(count, 1);
        for (const s of subs) { s.dispose(); }
        live.fire();
        assert.strictEqual(count, 1, 'Should not fire after dispose');
    });

    test('only liveClient defined returns one disposable', () => {
        const live = createMockSource();
        const subs = wireStoreEvents(live, undefined, () => {}, () => {});
        assert.strictEqual(subs.length, 1);
    });
});
