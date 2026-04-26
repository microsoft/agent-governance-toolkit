// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * esbuild configuration for React webview bundles.
 *
 * Each webview gets a single bundled JS file in out/webviews/.
 * CSS is pre-processed by Tailwind CLI (npm run build:css).
 * Run: node esbuild.webview.mjs [--watch]
 */

import * as esbuild from 'esbuild';

const isWatch = process.argv.includes('--watch');
const isProd = process.env.NODE_ENV === 'production';

/** @type {import('esbuild').BuildOptions} */
const config = {
    entryPoints: [
        'src/webviews/sidebar/main.tsx',
        'src/webviews/sloDetail/main.tsx',
        'src/webviews/topologyDetail/main.tsx',
        'src/webviews/hubDetail/main.tsx',
        'src/webviews/kernelDetail/main.tsx',
        'src/webviews/memoryDetail/main.tsx',
        'src/webviews/statsDetail/main.tsx',
        'src/webviews/auditDetail/main.tsx',
        'src/webviews/policyDetail/main.tsx',
    ],
    bundle: true,
    outdir: 'out/webviews',
    entryNames: '[dir]/[name]',
    format: 'iife',
    target: 'es2020',
    minify: isProd,
    sourcemap: !isProd,
    loader: {
        '.css': 'css',
    },
    define: {
        'process.env.NODE_ENV': JSON.stringify(isProd ? 'production' : 'development'),
    },
    logLevel: 'info',
};

if (isWatch) {
    const ctx = await esbuild.context(config);
    await ctx.watch();
} else {
    await esbuild.build(config);
}
