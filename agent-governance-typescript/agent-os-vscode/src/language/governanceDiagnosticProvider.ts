// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Diagnostic Provider for Agent OS
 *
 * Orchestrates real-time diagnostics for governance-specific policy violations
 * by composing rules from governanceRules, governanceIntegrationRules, and
 * code actions from governanceCodeActions.
 */

import * as vscode from 'vscode';

import {
    GovernanceDiagnosticRule,
    DIAGNOSTIC_COLLECTION_NAME,
    SUPPORTED_LANGUAGES,
    isPolicyFile,
    buildPolicyFileRules,
} from './governanceRules';
import { buildPythonRules, buildCrossLanguageRules } from './governanceIntegrationRules';
import { GovernanceCodeActionProvider } from './governanceCodeActions';

// ---------------------------------------------------------------------------
// GovernanceDiagnosticProvider
// ---------------------------------------------------------------------------

export class GovernanceDiagnosticProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private disposables: vscode.Disposable[] = [];

    private readonly policyFileRules: GovernanceDiagnosticRule[];
    private readonly pythonRules: GovernanceDiagnosticRule[];
    private readonly crossLanguageRules: GovernanceDiagnosticRule[];

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection(
            DIAGNOSTIC_COLLECTION_NAME,
        );
        this.policyFileRules = buildPolicyFileRules();
        this.pythonRules = buildPythonRules();
        this.crossLanguageRules = buildCrossLanguageRules();
    }

    /**
     * Activate the provider and subscribe to document lifecycle events.
     */
    activate(context: vscode.ExtensionContext): void {
        this.disposables.push(
            vscode.workspace.onDidOpenTextDocument(doc => this.analyzeDocument(doc)),
        );
        this.disposables.push(
            vscode.workspace.onDidChangeTextDocument(event =>
                this.analyzeDocument(event.document),
            ),
        );
        this.disposables.push(
            vscode.workspace.onDidSaveTextDocument(doc => this.analyzeDocument(doc)),
        );

        vscode.workspace.textDocuments.forEach(doc => this.analyzeDocument(doc));

        this.disposables.push(
            vscode.languages.registerCodeActionsProvider(
                [
                    { scheme: 'file', language: 'python' },
                    { scheme: 'file', language: 'yaml' },
                    { scheme: 'file', language: 'json' },
                    { scheme: 'file', language: 'javascript' },
                    { scheme: 'file', language: 'typescript' },
                ],
                new GovernanceCodeActionProvider(),
                { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
            ),
        );

        context.subscriptions.push(this.diagnosticCollection, ...this.disposables);
    }

    /**
     * Analyze a single document and produce governance diagnostics.
     */
    private analyzeDocument(document: vscode.TextDocument): void {
        const config = vscode.workspace.getConfiguration('agentOS');
        if (!config.get<boolean>('enabled', true)) {
            this.diagnosticCollection.delete(document.uri);
            return;
        }

        if (!SUPPORTED_LANGUAGES.includes(document.languageId)) {
            return;
        }

        const text = document.getText();
        const diagnostics: vscode.Diagnostic[] = [];

        if (isPolicyFile(document)) {
            for (const rule of this.policyFileRules) {
                this.applyRule(document, text, rule, diagnostics);
            }
        }

        if (document.languageId === 'python') {
            for (const rule of this.pythonRules) {
                this.applyRule(document, text, rule, diagnostics);
            }
        }

        for (const rule of this.crossLanguageRules) {
            this.applyRule(document, text, rule, diagnostics);
        }

        this.diagnosticCollection.set(document.uri, diagnostics);
    }

    /**
     * Apply a single rule. Delegates to the rule's custom analyze function
     * if present, otherwise falls back to simple regex matching.
     */
    private applyRule(
        document: vscode.TextDocument,
        text: string,
        rule: GovernanceDiagnosticRule,
        diagnostics: vscode.Diagnostic[],
    ): void {
        if (rule.analyze) {
            rule.analyze(document, text, diagnostics);
            return;
        }
        if (rule.pattern) {
            this.applyRegexRule(document, text, rule, diagnostics);
        }
    }

    /**
     * Simple regex-based rule application.
     */
    private applyRegexRule(
        document: vscode.TextDocument,
        text: string,
        rule: GovernanceDiagnosticRule,
        diagnostics: vscode.Diagnostic[],
    ): void {
        if (!rule.pattern) {
            return;
        }
        rule.pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = rule.pattern.exec(text)) !== null) {
            const startPos = document.positionAt(match.index);
            const endPos = document.positionAt(match.index + match[0].length);
            const range = new vscode.Range(startPos, endPos);
            const diagnostic = new vscode.Diagnostic(range, rule.message, rule.severity);
            diagnostic.code = rule.code;
            diagnostic.source = 'Agent OS Governance';
            diagnostics.push(diagnostic);
        }
    }

    /**
     * Dispose of all subscriptions and the diagnostic collection.
     */
    dispose(): void {
        this.diagnosticCollection.dispose();
        this.disposables.forEach(d => d.dispose());
    }
}

export { GovernanceCodeActionProvider } from './governanceCodeActions';
