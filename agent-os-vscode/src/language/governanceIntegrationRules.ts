// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Python integration rules (GOV1xx) and cross-language rules (GOV2xx)
 * for the governance diagnostic provider.
 */

import * as vscode from 'vscode';

import { GovernanceDiagnosticRule, DIAGNOSTIC_SOURCE } from './governanceRules';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Check whether a line near `lineNumber` contains the word "audit". */
function hasNearbyAuditRef(
    document: vscode.TextDocument,
    lineNumber: number,
    radius: number,
): boolean {
    const start = Math.max(0, lineNumber - radius);
    const end = Math.min(document.lineCount - 1, lineNumber + radius);
    for (let i = start; i <= end; i++) {
        if (/\baudit\b/i.test(document.lineAt(i).text)) {
            return true;
        }
    }
    return false;
}

/**
 * Check whether a line near `lineNumber` matches any of the given patterns.
 * Returns true if at least one pattern is found within the search radius.
 */
function hasNearbyPattern(
    document: vscode.TextDocument,
    lineNumber: number,
    radius: number,
    patterns: RegExp[],
): boolean {
    const start = Math.max(0, lineNumber - radius);
    const end = Math.min(document.lineCount - 1, lineNumber + radius);
    for (let i = start; i <= end; i++) {
        const lineText = document.lineAt(i).text;
        if (patterns.some(p => p.test(lineText))) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Python rules (GOV1xx)
// ---------------------------------------------------------------------------

/**
 * Build the list of Python-specific rules (GOV1xx).
 */
export function buildPythonRules(): GovernanceDiagnosticRule[] {
    return [
        // GOV101 - ToolCallInterceptor without error handling
        {
            code: 'GOV101',
            message: 'ToolCallInterceptor.intercept() called without error handling. Wrap in try/except to handle governance failures gracefully.',
            severity: vscode.DiagnosticSeverity.Warning,
            analyze(document, text, diagnostics) {
                const pattern = /interceptor\.intercept\s*\(/g;
                let match: RegExpExecArray | null;
                while ((match = pattern.exec(text)) !== null) {
                    const lineNumber = document.positionAt(match.index).line;
                    const hasTryExcept = hasNearbyPattern(
                        document, lineNumber, 5, [/\b(try|except)\b/],
                    );
                    if (hasTryExcept) { continue; }
                    const startPos = document.positionAt(match.index);
                    const endPos = document.positionAt(match.index + match[0].length);
                    const range = new vscode.Range(startPos, endPos);
                    const diag = new vscode.Diagnostic(range, this.message, this.severity);
                    diag.code = this.code;
                    diag.source = DIAGNOSTIC_SOURCE;
                    diagnostics.push(diag);
                }
            },
        },
        // GOV102 - KillSwitch without audit logging
        {
            code: 'GOV102',
            message: 'KillSwitch invocation detected without audit logging. Always log kill switch activations for compliance.',
            severity: vscode.DiagnosticSeverity.Warning,
            analyze(document, text, diagnostics) {
                const patterns = [
                    /kill_switch\.activate\s*\(/g,
                    /KillSwitch\s*\(/g,
                ];
                for (const pattern of patterns) {
                    let match: RegExpExecArray | null;
                    while ((match = pattern.exec(text)) !== null) {
                        const lineNumber = document.positionAt(match.index).line;
                        if (!hasNearbyAuditRef(document, lineNumber, 10)) {
                            const startPos = document.positionAt(match.index);
                            const endPos = document.positionAt(match.index + match[0].length);
                            const range = new vscode.Range(startPos, endPos);
                            const diag = new vscode.Diagnostic(range, this.message, this.severity);
                            diag.code = this.code;
                            diag.source = DIAGNOSTIC_SOURCE;
                            diagnostics.push(diag);
                        }
                    }
                }
            },
        },
        // GOV103 - Hardcoded execution ring assignment
        {
            code: 'GOV103',
            message: 'Hardcoded execution ring assignment. Use policy-based ring assignment for dynamic governance.',
            severity: vscode.DiagnosticSeverity.Warning,
            pattern: /ExecutionRing\.RING_[0-3](?:_ROOT|_PRIVILEGED|_USER|_SANDBOX)?/g,
        },
        // GOV104 - Missing governance context in agent registration
        {
            code: 'GOV104',
            message: 'Agent registration without governance context. Include "governance_context" or "policy" parameter for compliance tracking.',
            severity: vscode.DiagnosticSeverity.Information,
            analyze(document, text, diagnostics) {
                const pattern = /register_agent\s*\([^)]*\)/g;
                let match: RegExpExecArray | null;
                while ((match = pattern.exec(text)) !== null) {
                    const callText = match[0];
                    if (!/governance_context|policy/i.test(callText)) {
                        const startPos = document.positionAt(match.index);
                        const endPos = document.positionAt(match.index + match[0].length);
                        const range = new vscode.Range(startPos, endPos);
                        const diag = new vscode.Diagnostic(range, this.message, this.severity);
                        diag.code = this.code;
                        diag.source = DIAGNOSTIC_SOURCE;
                        diagnostics.push(diag);
                    }
                }
            },
        },
    ];
}

// ---------------------------------------------------------------------------
// Cross-language rules (GOV2xx)
// ---------------------------------------------------------------------------

/**
 * Build the list of cross-language rules (GOV2xx).
 */
export function buildCrossLanguageRules(): GovernanceDiagnosticRule[] {
    return [
        // GOV201 - Agent DID format violation
        {
            code: 'GOV201',
            message: 'Malformed agent DID. Expected format: "did:mesh:<hex>" or "did:myth:<persona>:<hex>".',
            severity: vscode.DiagnosticSeverity.Error,
            analyze(document, text, diagnostics) {
                const didPattern = /["']?(did:(mesh|myth):[^"'\s,)}\]]*)/g;
                let match: RegExpExecArray | null;
                while ((match = didPattern.exec(text)) !== null) {
                    const did = match[1];
                    const isValid = isValidAgentDID(did);
                    if (!isValid) {
                        const didStart = match.index + (match[0].startsWith('"') || match[0].startsWith("'") ? 1 : 0);
                        const startPos = document.positionAt(didStart);
                        const endPos = document.positionAt(didStart + did.length);
                        const range = new vscode.Range(startPos, endPos);
                        const diag = new vscode.Diagnostic(
                            range,
                            `${this.message} Found: "${did}".`,
                            this.severity,
                        );
                        diag.code = this.code;
                        diag.source = DIAGNOSTIC_SOURCE;
                        diagnostics.push(diag);
                    }
                }
            },
        },
        // GOV202 - Trust score comparison with magic numbers
        {
            code: 'GOV202',
            message: 'Trust score compared against a magic number. Define a named constant (e.g., MINIMUM_TRUST_THRESHOLD) for maintainability.',
            severity: vscode.DiagnosticSeverity.Warning,
            pattern: /trust(?:_score|Score|_level|Level)?\s*[<>=!]+\s*\d{2,}/gi,
        },
    ];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Validate an agent DID string.
 *
 * Valid formats:
 *   did:mesh:<32+ hex chars>
 *   did:myth:<persona>:<32 hex chars>
 *
 * Personas: scrivener, sentinel, judge, overseer (and future additions).
 */
export function isValidAgentDID(did: string): boolean {
    // did:mesh:<hex-hash>
    if (/^did:mesh:[0-9a-fA-F]{32,}$/.test(did)) {
        return true;
    }
    // did:myth:<persona>:<hex-hash>
    if (/^did:myth:[a-z]+:[0-9a-fA-F]{32}$/.test(did)) {
        return true;
    }
    return false;
}
