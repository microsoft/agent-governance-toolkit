// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance code action provider and quick-fix registry.
 *
 * Provides inline quick fixes for governance diagnostics (GOV0xx, GOV1xx)
 * and language-appropriate suppression comments.
 */

import * as vscode from 'vscode';

import { DIAGNOSTIC_SOURCE, TRUST_SCORE_MIN, TRUST_SCORE_MAX } from './governanceRules';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GovernanceQuickFix {
    title: string;
    createEdit: (
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic
    ) => vscode.WorkspaceEdit | undefined;
}

// ---------------------------------------------------------------------------
// Quick-fix registry (keyed by diagnostic code)
// ---------------------------------------------------------------------------

const QUICK_FIXES: Record<string, GovernanceQuickFix> = {
    GOV001: {
        title: 'Insert version field',
        createEdit(document, _diagnostic) {
            const edit = new vscode.WorkspaceEdit();
            edit.insert(
                document.uri,
                new vscode.Position(0, 0),
                'version: "1.0"\n',
            );
            return edit;
        },
    },
    GOV003: {
        title: 'Clamp trust_threshold to valid range (0-1000)',
        createEdit(document, diagnostic) {
            const text = document.getText(diagnostic.range);
            const numMatch = text.match(/(\d+)/);
            if (!numMatch) {
                return undefined;
            }
            const value = parseInt(numMatch[1], 10);
            const clamped = Math.max(TRUST_SCORE_MIN, Math.min(TRUST_SCORE_MAX, value));
            const replacement = text.replace(numMatch[1], String(clamped));
            const edit = new vscode.WorkspaceEdit();
            edit.replace(document.uri, diagnostic.range, replacement);
            return edit;
        },
    },
    GOV005: {
        title: 'Show valid execution ring values (0-3)',
        createEdit(document, diagnostic) {
            const edit = new vscode.WorkspaceEdit();
            const line = document.lineAt(diagnostic.range.start.line);
            const comment = '  # Valid rings: 0 (ROOT), 1 (PRIVILEGED), 2 (USER), 3 (SANDBOX)';
            edit.insert(
                document.uri,
                new vscode.Position(line.lineNumber, line.text.length),
                comment,
            );
            return edit;
        },
    },
    GOV103: {
        title: 'Use policy-based ring assignment instead of hardcoded ring',
        createEdit(document, diagnostic) {
            const text = document.getText(diagnostic.range);
            const edit = new vscode.WorkspaceEdit();
            edit.replace(
                document.uri,
                diagnostic.range,
                `policy_engine.assign_ring(agent_did)  # was: ${text}`,
            );
            return edit;
        },
    },
};

// ---------------------------------------------------------------------------
// GovernanceCodeActionProvider
// ---------------------------------------------------------------------------

export class GovernanceCodeActionProvider implements vscode.CodeActionProvider {
    provideCodeActions(
        document: vscode.TextDocument,
        _range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        _token: vscode.CancellationToken,
    ): vscode.ProviderResult<(vscode.CodeAction | vscode.Command)[]> {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== DIAGNOSTIC_SOURCE) {
                continue;
            }

            const code = diagnostic.code as string;
            this.addQuickFix(document, diagnostic, code, actions);
            this.addSuppressAction(document, diagnostic, code, actions);
            this.addLearnMoreAction(code, actions);
        }

        return actions;
    }

    private addQuickFix(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        code: string,
        actions: vscode.CodeAction[],
    ): void {
        const quickFix = QUICK_FIXES[code];
        if (!quickFix) {
            return;
        }
        const edit = quickFix.createEdit(document, diagnostic);
        if (!edit) {
            return;
        }
        const action = new vscode.CodeAction(
            quickFix.title,
            vscode.CodeActionKind.QuickFix,
        );
        action.edit = edit;
        action.diagnostics = [diagnostic];
        action.isPreferred = true;
        actions.push(action);
    }

    private addSuppressAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        code: string,
        actions: vscode.CodeAction[],
    ): void {
        const suppressAction = new vscode.CodeAction(
            `Suppress: ${code}`,
            vscode.CodeActionKind.QuickFix,
        );
        suppressAction.edit = new vscode.WorkspaceEdit();
        const line = document.lineAt(diagnostic.range.start.line);
        const suppressComment = getSuppressComment(document.languageId, code);
        suppressAction.edit.insert(
            document.uri,
            new vscode.Position(line.lineNumber, line.text.length),
            suppressComment,
        );
        suppressAction.diagnostics = [diagnostic];
        actions.push(suppressAction);
    }

    private addLearnMoreAction(
        code: string,
        actions: vscode.CodeAction[],
    ): void {
        const learnMoreAction = new vscode.CodeAction(
            `Learn more about ${code}`,
            vscode.CodeActionKind.Empty,
        );
        learnMoreAction.command = {
            command: 'vscode.open',
            title: 'Learn more',
            arguments: [
                vscode.Uri.parse(
                    `https://agent-os.dev/docs/rules/${code}`,
                ),
            ],
        };
        actions.push(learnMoreAction);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a language-appropriate inline suppression comment.
 */
export function getSuppressComment(languageId: string, code: string): string {
    switch (languageId) {
        case 'python':
            return `  # noqa: ${code}`;
        case 'yaml':
        case 'json':
            return `  # @agent-os-ignore ${code}`;
        case 'javascript':
        case 'typescript':
            return `  // @agent-os-ignore ${code}`;
        default:
            return `  // @agent-os-ignore ${code}`;
    }
}
