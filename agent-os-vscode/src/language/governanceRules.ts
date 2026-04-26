// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance diagnostic rule types, constants, and policy file rules (GOV0xx).
 *
 * Rule prefixes:
 *   GOV0xx  - Policy file rules (YAML/JSON)
 */

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GovernanceDiagnosticRule {
    code: string;
    message: string;
    severity: vscode.DiagnosticSeverity;
    /** When present the rule uses simple regex matching via applyRegexRule. */
    pattern?: RegExp;
    /** When present the rule requires custom analysis logic. */
    analyze?: (
        document: vscode.TextDocument,
        text: string,
        diagnostics: vscode.Diagnostic[]
    ) => void;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const DIAGNOSTIC_SOURCE = 'Agent OS Governance';
export const DIAGNOSTIC_COLLECTION_NAME = 'agentOS.governance';

export const VALID_POLICY_ACTIONS = ['ALLOW', 'DENY', 'AUDIT', 'BLOCK'];
export const VALID_RING_VALUES = [0, 1, 2, 3];
export const TRUST_SCORE_MIN = 0;
export const TRUST_SCORE_MAX = 1000;

export const SUPPORTED_LANGUAGES = [
    'javascript', 'typescript', 'python', 'yaml', 'json',
    'shellscript', 'bash', 'sh',
];

// ---------------------------------------------------------------------------
// Policy file rules (GOV0xx)
// ---------------------------------------------------------------------------

/**
 * Build the list of policy-file rules (GOV0xx).
 * These only apply to YAML/JSON files whose name matches the policy pattern.
 */
export function buildPolicyFileRules(): GovernanceDiagnosticRule[] {
    return [
        // GOV001 - Missing version field
        {
            code: 'GOV001',
            message: 'Missing "version" field in policy document. Every policy document must declare a version.',
            severity: vscode.DiagnosticSeverity.Error,
            analyze(document, text, diagnostics) {
                const hasVersion = /^\s*["']?version["']?\s*[:=]/m.test(text);
                if (!hasVersion) {
                    const range = new vscode.Range(
                        new vscode.Position(0, 0),
                        new vscode.Position(0, Math.min(document.lineAt(0).text.length, 1)),
                    );
                    const diag = new vscode.Diagnostic(range, this.message, this.severity);
                    diag.code = this.code;
                    diag.source = DIAGNOSTIC_SOURCE;
                    diagnostics.push(diag);
                }
            },
        },
        // GOV002 - Rule without action field
        {
            code: 'GOV002',
            message: `Policy rule is missing an "action" field. Must be one of: ${VALID_POLICY_ACTIONS.join(', ')}.`,
            severity: vscode.DiagnosticSeverity.Error,
            analyze(document, text, diagnostics) {
                const ruleBlockPattern = /^[ \t]*-\s*\n?((?:[ \t]+\S.*\n?)*)/gm;
                let blockMatch: RegExpExecArray | null;
                ruleBlockPattern.lastIndex = 0;
                while ((blockMatch = ruleBlockPattern.exec(text)) !== null) {
                    if (!matchMissingActionBlock(blockMatch[0])) { continue; }
                    const startPos = document.positionAt(blockMatch.index);
                    const endLine = document.lineAt(startPos.line);
                    const range = new vscode.Range(startPos, endLine.range.end);
                    const diag = new vscode.Diagnostic(range, this.message, this.severity);
                    diag.code = this.code;
                    diag.source = DIAGNOSTIC_SOURCE;
                    diagnostics.push(diag);
                }
            },
        },
        // GOV003 - trust_threshold outside 0-1000
        {
            code: 'GOV003',
            message: `trust_threshold must be between ${TRUST_SCORE_MIN} and ${TRUST_SCORE_MAX}.`,
            severity: vscode.DiagnosticSeverity.Error,
            analyze(document, text, diagnostics) {
                const pattern = /trust_threshold\s*:\s*(-?\d+)/gi;
                let match: RegExpExecArray | null;
                while ((match = pattern.exec(text)) !== null) {
                    const value = parseInt(match[1], 10);
                    if (value < TRUST_SCORE_MIN || value > TRUST_SCORE_MAX) {
                        const startPos = document.positionAt(match.index);
                        const endPos = document.positionAt(match.index + match[0].length);
                        const range = new vscode.Range(startPos, endPos);
                        const diag = new vscode.Diagnostic(
                            range,
                            `${this.message} Found: ${value}.`,
                            this.severity,
                        );
                        diag.code = this.code;
                        diag.source = DIAGNOSTIC_SOURCE;
                        diagnostics.push(diag);
                    }
                }
            },
        },
        // GOV004 - DENY/BLOCK without escalation config
        {
            code: 'GOV004',
            message: 'DENY/BLOCK rule without escalation configuration. Consider adding an "escalation" section for operational safety.',
            severity: vscode.DiagnosticSeverity.Warning,
            analyze(document, text, diagnostics) {
                const actionPattern = /\baction\s*:\s*(DENY|BLOCK)\b/gi;
                let match: RegExpExecArray | null;
                while ((match = actionPattern.exec(text)) !== null) {
                    const contextStart = Math.max(0, match.index - 300);
                    const contextEnd = Math.min(text.length, match.index + match[0].length + 300);
                    const context = text.substring(contextStart, contextEnd);
                    if (!/\bescalation\s*:/i.test(context)) {
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
        // GOV005 - Invalid execution_ring value
        {
            code: 'GOV005',
            message: `execution_ring must be one of: ${VALID_RING_VALUES.join(', ')}. Maps to RING_0_ROOT through RING_3_SANDBOX.`,
            severity: vscode.DiagnosticSeverity.Error,
            analyze(document, text, diagnostics) {
                const pattern = /execution_ring\s*:\s*(\d+)/gi;
                let match: RegExpExecArray | null;
                while ((match = pattern.exec(text)) !== null) {
                    const value = parseInt(match[1], 10);
                    if (!VALID_RING_VALUES.includes(value)) {
                        const startPos = document.positionAt(match.index);
                        const endPos = document.positionAt(match.index + match[0].length);
                        const range = new vscode.Range(startPos, endPos);
                        const diag = new vscode.Diagnostic(
                            range,
                            `${this.message} Found: ${value}.`,
                            this.severity,
                        );
                        diag.code = this.code;
                        diag.source = DIAGNOSTIC_SOURCE;
                        diagnostics.push(diag);
                    }
                }
            },
        },
        // GOV006 - No OWASP ASI coverage mapping
        {
            code: 'GOV006',
            message: 'Policy document does not include an OWASP Agentic Security Initiative (ASI) coverage mapping. Consider adding an "owasp" or "coverage" section.',
            severity: vscode.DiagnosticSeverity.Information,
            analyze(document, text, diagnostics) {
                const hasOwasp = /\b(owasp|asi_coverage|coverage_map|agentic_top_10)\s*:/i.test(text);
                if (!hasOwasp) {
                    const lastLine = document.lineCount - 1;
                    const lastLineText = document.lineAt(lastLine).text;
                    const range = new vscode.Range(
                        new vscode.Position(lastLine, 0),
                        new vscode.Position(lastLine, Math.min(lastLineText.length, 1)),
                    );
                    const diag = new vscode.Diagnostic(range, this.message, this.severity);
                    diag.code = this.code;
                    diag.source = DIAGNOSTIC_SOURCE;
                    diagnostics.push(diag);
                }
            },
        },
    ];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Match a YAML rule block that is missing an "action" field.
 * Returns the match index if the block has a rule indicator but no action,
 * or null if the block is valid.
 */
export function matchMissingActionBlock(
    block: string,
): boolean {
    const hasRuleIndicator = /\b(name|match|pattern|rule|when|condition)\s*:/i.test(block);
    const hasAction = /\baction\s*:/i.test(block);
    return hasRuleIndicator && !hasAction;
}

/**
 * Determine whether a document is a governance policy file
 * based on its file name.
 */
export function isPolicyFile(document: vscode.TextDocument): boolean {
    const fileName = document.fileName.toLowerCase();
    return (
        (document.languageId === 'yaml' || document.languageId === 'json') &&
        (fileName.includes('policy') ||
            fileName.includes('agent-os') ||
            fileName.includes('.agents'))
    );
}
