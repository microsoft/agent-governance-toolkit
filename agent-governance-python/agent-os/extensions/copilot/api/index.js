// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Vercel Serverless Function Entry Point
 *
 * Imports the compiled Express app from dist/ which contains the full
 * CopilotExtension with all handlers:
 * - Agent creation from natural language
 * - 50+ agent templates
 * - Policy-aware code suggestions (25+ security rules)
 * - CMVK multi-model verification
 * - Compliance checking (GDPR, HIPAA, SOC2, PCI DSS)
 * - Security audits (SQL injection, XSS, secrets, CWE-tagged)
 * - Test scenario generation and simulation
 * - GitHub Actions workflow generation
 * - Debug diagnosis and performance analysis
 */

// Set Vercel environment flag before importing the app
process.env.VERCEL = '1';

const { app } = require('../dist/index');

module.exports = app;
