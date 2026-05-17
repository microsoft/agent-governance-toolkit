// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as assert from 'assert';
import * as vscode from 'vscode';
import { PolicyEngine } from '../policyEngine';

suite('policyEngine allow-once', () => {
    const dangerousSnippet = 'const password = "supersecret-password";';
    let originalGetConfiguration: typeof vscode.workspace.getConfiguration;
    let originalWorkspaceFolders: typeof vscode.workspace.workspaceFolders;

    setup(() => {
        originalGetConfiguration = vscode.workspace.getConfiguration;
        originalWorkspaceFolders = vscode.workspace.workspaceFolders;

        const configStub = {
            get<T>(key: string, defaultValue?: T): T {
                if (key === 'policies.blockSecretExposure') {
                    return true as T;
                }
                if (key === 'policies.blockDestructiveSQL'
                    || key === 'policies.blockFileDeletes'
                    || key === 'policies.blockPrivilegeEscalation'
                    || key === 'policies.blockUnsafeNetworkCalls') {
                    return false as T;
                }
                return defaultValue as T;
            },
        };

        (vscode.workspace as any).getConfiguration = () => configStub;
        (vscode.workspace as any).workspaceFolders = undefined;
    });

    teardown(() => {
        (vscode.workspace as any).getConfiguration = originalGetConfiguration;
        (vscode.workspace as any).workspaceFolders = originalWorkspaceFolders;
    });

    test('does not consume allow-once on unrelated edits', async () => {
        const engine = new PolicyEngine();

        const initial = await engine.analyzeCode(dangerousSnippet, 'typescript');
        assert.strictEqual(initial.blocked, true);
        assert.strictEqual(initial.violation, 'hardcoded_password');

        engine.allowOnce(initial.violation);

        const unrelated = await engine.analyzeCode('const x = 1;', 'typescript');
        assert.strictEqual(unrelated.blocked, false);

        const firstReuse = await engine.analyzeCode(dangerousSnippet, 'typescript');
        assert.strictEqual(firstReuse.blocked, false);

        const secondReuse = await engine.analyzeCode(dangerousSnippet, 'typescript');
        assert.strictEqual(secondReuse.blocked, true);
        assert.strictEqual(secondReuse.violation, 'hardcoded_password');
    });

    test('allow-once still works for immediate re-analysis of same blocked content', async () => {
        const engine = new PolicyEngine();

        const first = await engine.analyzeCode(dangerousSnippet, 'typescript');
        assert.strictEqual(first.blocked, true);
        engine.allowOnce(first.violation);

        const second = await engine.analyzeCode(dangerousSnippet, 'typescript');
        assert.strictEqual(second.blocked, false);
    });

    test('fallback allow-once remains one-shot when called without prior blocked context', async () => {
        const engine = new PolicyEngine();

        engine.allowOnce('hardcoded_password');

        const first = await engine.analyzeCode(dangerousSnippet, 'typescript');
        assert.strictEqual(first.blocked, false);

        const second = await engine.analyzeCode(dangerousSnippet, 'typescript');
        assert.strictEqual(second.blocked, true);
    });

    test('fallback allow-once expires after the next unrelated analyze cycle', async () => {
        const engine = new PolicyEngine();

        engine.allowOnce('hardcoded_password');

        const unrelated = await engine.analyzeCode('const x = 1;', 'typescript');
        assert.strictEqual(unrelated.blocked, false);

        const blocked = await engine.analyzeCode(dangerousSnippet, 'typescript');
        assert.strictEqual(blocked.blocked, true);
        assert.strictEqual(blocked.violation, 'hardcoded_password');
    });
});
