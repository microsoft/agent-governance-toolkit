// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * VS Code Webview API Wrapper
 *
 * Typed interface for communication between webview and extension host.
 * Ensures acquireVsCodeApi is called exactly once per webview lifecycle.
 */

/** Typed subset of the VS Code webview API. */
interface VSCodeAPI {
    postMessage(message: { type: string; [key: string]: unknown }): void;
    getState<T>(): T | undefined;
    setState<T>(state: T): void;
}

declare function acquireVsCodeApi(): VSCodeAPI;

let api: VSCodeAPI | undefined;

/**
 * Get the VS Code webview API singleton.
 *
 * @returns Typed VS Code API instance
 */
export function getVSCodeAPI(): VSCodeAPI {
    if (!api) {
        api = acquireVsCodeApi();
    }
    return api;
}

/** Message shape received from the extension host. */
export interface ExtensionMessage {
    type: string;
    [key: string]: unknown;
}

/**
 * Subscribe to messages from the extension host.
 *
 * @param handler - Callback invoked for each message
 * @returns Cleanup function to remove the listener
 */
export function onMessage(handler: (msg: ExtensionMessage) => void): () => void {
    const listener = (e: MessageEvent) => handler(e.data);
    window.addEventListener('message', listener);
    return () => window.removeEventListener('message', listener);
}
