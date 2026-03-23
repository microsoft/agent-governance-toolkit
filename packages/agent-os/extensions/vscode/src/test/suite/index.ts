// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Test Suite Loader
 *
 * Discovers and runs all Mocha test files in the test directory.
 */

import * as path from 'path';
import Mocha from 'mocha';
import { glob } from 'glob';

export async function run(): Promise<void> {
    // Create the mocha test
    const mocha = new Mocha({
        ui: 'tdd',
        color: true,
        timeout: 60000,
    });

    const testsRoot = path.resolve(__dirname, '..');

    // Find all test files recursively
    const files = await glob('**/*.test.js', { cwd: testsRoot });

    // Add files to the test suite
    files.forEach((f: string) => mocha.addFile(path.resolve(testsRoot, f)));

    return new Promise<void>((resolve, reject) => {
        try {
            // Run the mocha test
            mocha.run((failures: number) => {
                if (failures > 0) {
                    reject(new Error(`${failures} tests failed.`));
                } else {
                    resolve();
                }
            });
        } catch (runErr) {
            console.error(runErr);
            reject(runErr);
        }
    });
}
