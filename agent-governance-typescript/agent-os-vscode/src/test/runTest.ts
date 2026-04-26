// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Test Runner Entry Point
 *
 * Launches VS Code Extension Development Host and runs tests.
 */

import * as path from 'path';
import { runTests } from '@vscode/test-electron';

async function main() {
    try {
        // The folder containing the Extension Manifest package.json
        const extensionDevelopmentPath = path.resolve(__dirname, '../../');

        // The path to the extension test script
        const extensionTestsPath = path.resolve(__dirname, './suite/index');

        // Download VS Code, unzip it and run the integration test
        await runTests({
            extensionDevelopmentPath,
            extensionTestsPath,
            // Use minimal launch args compatible with all VS Code versions
            launchArgs: ['--disable-telemetry'],
        });
    } catch (err) {
        console.error('Failed to run tests:', err);
        process.exit(1);
    }
}

main();
