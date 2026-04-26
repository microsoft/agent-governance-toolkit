// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * React hook for receiving typed messages from the extension host.
 *
 * Wraps the low-level onMessage listener with automatic cleanup
 * and message-type filtering.
 */

import { useState, useEffect } from 'react';
import { onMessage } from './vscode';

/**
 * Subscribe to extension host messages of a specific type.
 *
 * Returns the latest payload for the given message type, or null
 * if no message has been received yet.
 *
 * @param type - Message type to filter on (e.g. 'sloDetailUpdate')
 * @returns Latest payload of type T, or null
 */
export function useExtensionMessage<T>(type: string): T | null {
    const [data, setData] = useState<T | null>(null);

    useEffect(() => {
        const cleanup = onMessage((msg) => {
            if (msg.type === type) {
                setData(msg.data as T);
            }
        });
        return cleanup;
    }, [type]);

    return data;
}
