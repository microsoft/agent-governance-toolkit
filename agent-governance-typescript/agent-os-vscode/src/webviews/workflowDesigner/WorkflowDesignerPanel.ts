// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Workflow Designer Panel - Visual agent workflow builder
 * 
 * Provides a drag-and-drop canvas for designing agent workflows
 * with policy attachment and code generation.
 */

import * as vscode from 'vscode';
import * as crypto from 'crypto';

interface WorkflowNode {
    id: string;
    type: 'start' | 'end' | 'action' | 'condition' | 'loop' | 'parallel';
    label: string;
    position: { x: number; y: number };
    config: Record<string, any>;
    policy?: string;
}

interface WorkflowEdge {
    id: string;
    source: string;
    target: string;
    label?: string;
}

interface Workflow {
    id: string;
    name: string;
    description: string;
    nodes: WorkflowNode[];
    edges: WorkflowEdge[];
    policies: string[];
}

export class WorkflowDesignerPanel {
    public static currentPanel: WorkflowDesignerPanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private _disposables: vscode.Disposable[] = [];
    private _workflow: Workflow;

    public static readonly viewType = 'agentOS.workflowDesigner';

    private static readonly nodeTypes = [
        {
            type: 'action',
            label: 'Action',
            icon: '⚡',
            description: 'Execute a tool or API call',
            actions: [
                'database_query',
                'database_write',
                'file_read',
                'file_write',
                'http_request',
                'llm_call',
                'send_email',
                'code_execution'
            ]
        },
        {
            type: 'condition',
            label: 'Condition',
            icon: '🔀',
            description: 'Branch based on a condition'
        },
        {
            type: 'loop',
            label: 'Loop',
            icon: '🔄',
            description: 'Repeat actions'
        },
        {
            type: 'parallel',
            label: 'Parallel',
            icon: '⚔️',
            description: 'Execute actions in parallel'
        }
    ];

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._workflow = {
            id: 'workflow-' + Date.now(),
            name: 'New Workflow',
            description: '',
            nodes: [
                { id: 'start', type: 'start', label: 'Start', position: { x: 100, y: 100 }, config: {} },
                { id: 'end', type: 'end', label: 'End', position: { x: 500, y: 100 }, config: {} }
            ],
            edges: [],
            policies: []
        };

        this._update();

        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
        
        this._panel.webview.onDidReceiveMessage(
            async message => {
                switch (message.type) {
                    case 'addNode':
                        this._addNode(message.nodeType, message.position);
                        break;
                    case 'removeNode':
                        this._removeNode(message.nodeId);
                        break;
                    case 'updateNode':
                        this._updateNode(message.nodeId, message.updates);
                        break;
                    case 'addEdge':
                        this._addEdge(message.source, message.target);
                        break;
                    case 'removeEdge':
                        this._removeEdge(message.edgeId);
                        break;
                    case 'attachPolicy':
                        this._attachPolicy(message.nodeId, message.policy);
                        break;
                    case 'exportCode':
                        await this._exportCode(message.language);
                        break;
                    case 'saveWorkflow':
                        await this._saveWorkflow();
                        break;
                    case 'loadWorkflow':
                        await this._loadWorkflow();
                        break;
                    case 'simulate':
                        await this._simulate();
                        break;
                    case 'updateWorkflow':
                        this._workflow = message.workflow;
                        break;
                }
            },
            null,
            this._disposables
        );
    }

    public static createOrShow(extensionUri: vscode.Uri) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (WorkflowDesignerPanel.currentPanel) {
            WorkflowDesignerPanel.currentPanel._panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            WorkflowDesignerPanel.viewType,
            'Workflow Designer',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );

        WorkflowDesignerPanel.currentPanel = new WorkflowDesignerPanel(panel, extensionUri);
    }

    private _addNode(nodeType: string, position: { x: number; y: number }): void {
        const node: WorkflowNode = {
            id: 'node-' + Date.now(),
            type: nodeType as any,
            label: nodeType.charAt(0).toUpperCase() + nodeType.slice(1),
            position,
            config: {}
        };
        this._workflow.nodes.push(node);
        this._panel.webview.postMessage({ type: 'nodeAdded', node });
    }

    private _removeNode(nodeId: string): void {
        this._workflow.nodes = this._workflow.nodes.filter(n => n.id !== nodeId);
        this._workflow.edges = this._workflow.edges.filter(
            e => e.source !== nodeId && e.target !== nodeId
        );
        this._panel.webview.postMessage({ type: 'nodeRemoved', nodeId });
    }

    private _updateNode(nodeId: string, updates: Record<string, unknown>): void {
        const node = this._workflow.nodes.find(n => n.id === nodeId);
        if (!node) { return; }
        const ALLOWED_KEYS: ReadonlySet<string> = new Set([
            'name', 'description', 'type', 'position', 'config', 'enabled', 'label',
        ]);
        for (const key of Object.keys(updates)) {
            if (ALLOWED_KEYS.has(key) && key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
                (node as unknown as Record<string, unknown>)[key] = updates[key];
            }
        }
    }

    private _addEdge(source: string, target: string): void {
        const edge: WorkflowEdge = {
            id: 'edge-' + Date.now(),
            source,
            target
        };
        this._workflow.edges.push(edge);
        this._panel.webview.postMessage({ type: 'edgeAdded', edge });
    }

    private _removeEdge(edgeId: string): void {
        this._workflow.edges = this._workflow.edges.filter(e => e.id !== edgeId);
    }

    private _attachPolicy(nodeId: string, policy: string): void {
        const node = this._workflow.nodes.find(n => n.id === nodeId);
        if (node) {
            node.policy = policy;
        }
    }

    private async _exportCode(language: 'python' | 'typescript' | 'go'): Promise<void> {
        let code: string;
        
        switch (language) {
            case 'python':
                code = this._generatePythonCode();
                break;
            case 'typescript':
                code = this._generateTypeScriptCode();
                break;
            case 'go':
                code = this._generateGoCode();
                break;
        }

        const doc = await vscode.workspace.openTextDocument({
            language,
            content: code
        });
        await vscode.window.showTextDocument(doc);
    }

    private _quoteGeneratedString(value: string): string {
        return JSON.stringify(value);
    }

    private _getNodeAction(node: WorkflowNode): string {
        const configuredAction = typeof node.config.action === 'string' ? node.config.action.trim() : '';
        return configuredAction || 'custom_action';
    }

    private _getNodeDescription(node: WorkflowNode): string {
        const configuredDescription = typeof node.config.description === 'string' ? node.config.description.trim() : '';
        return configuredDescription || `Execute ${node.label}`;
    }

    private _generatePythonCode(): string {
        const actionNodes = this._workflow.nodes
            .filter(n => n.type === 'action')
            .map((node, index) => ({
                node,
                action: this._getNodeAction(node),
                description: this._getNodeDescription(node),
                functionName: this._toSnakeCase(node.label, `step_${index + 1}`),
            }));
        const imports = [
            'from agent_os import KernelSpace',
            'from agent_os.tools import create_safe_toolkit'
        ];
        const scaffoldReason = 'Replace this scaffold with a governed implementation before executing the workflow.';
        const emptyWorkflowReason = 'Add at least one Action node in the Workflow Designer before exporting runnable code.';

        if (actionNodes.length === 0) {
            return `"""
${this._workflow.name || 'New Workflow'}

Auto-generated by Agent OS Workflow Designer
"""

${imports.join('\n')}

# Initialize kernel with policy
kernel = KernelSpace(policy="strict")
toolkit = create_safe_toolkit("standard")

@kernel.register
async def run_workflow(task: str):
    """Exported workflow requires at least one action node before it can run."""
    return {
        "status": "blocked",
        "reason": ${this._quoteGeneratedString(emptyWorkflowReason)},
        "steps": [],
        "input": {"task": task},
    }

if __name__ == "__main__":
    import asyncio
    result = asyncio.run(kernel.execute(run_workflow, "example task"))
    print(result)
`;
        }

        const functions = actionNodes.map(({ node, action, description, functionName }) => `
async def ${functionName}(context):
    """Generated scaffold for ${node.label}."""
    _ = context
    step = {
        "step": ${this._quoteGeneratedString(node.label)},
        "action": ${this._quoteGeneratedString(action)},
        "status": "blocked",
        "reason": ${this._quoteGeneratedString(scaffoldReason)},
        "details": {
            "description": ${this._quoteGeneratedString(description)}
        }
    }
    ${node.policy ? `step["policy"] = ${this._quoteGeneratedString(node.policy)}` : ''}
    return step
`).join('\n');

        const workflowSteps = actionNodes
            .map(({ functionName }) => `steps.append(await ${functionName}(context))`)
            .join('\n    ');

        return `"""
${this._workflow.name || 'New Workflow'}

Auto-generated by Agent OS Workflow Designer
"""

${imports.join('\n')}

# Initialize kernel with policy
kernel = KernelSpace(policy="strict")
toolkit = create_safe_toolkit("standard")

${functions}

@kernel.register
async def run_workflow(task: str):
    """${this._workflow.description || 'Agent workflow'}"""
    context = {"task": task, "toolkit": toolkit}
    steps = []
    
    ${workflowSteps}

    blocked_step = next((step for step in steps if step.get("status") != "completed"), None)
    if blocked_step:
        return {
            "status": "blocked",
            "reason": "Workflow contains scaffolded steps that must be implemented before execution.",
            "blocked_step": blocked_step,
            "steps": steps,
        }

    return {"status": "completed", "steps": steps}

if __name__ == "__main__":
    import asyncio
    result = asyncio.run(kernel.execute(run_workflow, "example task"))
    print(result)
`;
    }

    private _generateTypeScriptCode(): string {
        const actionNodes = this._workflow.nodes
            .filter(n => n.type === 'action')
            .map((node, index) => ({
                node,
                action: this._getNodeAction(node),
                description: this._getNodeDescription(node),
                functionName: this._toCamelCase(node.label, `step${index + 1}`),
            }));
        const workflowName = this._workflow.name || 'New Workflow';
        const scaffoldReason = 'Replace this scaffold with a governed implementation before executing the workflow.';
        const emptyWorkflowReason = 'Add at least one Action node in the Workflow Designer before exporting runnable code.';
        const stepResultType = `type WorkflowStepResult = {
  step: string;
  action: string;
  status: 'blocked' | 'completed';
  reason?: string;
  policy?: string;
  details?: Record<string, unknown>;
};`;
        const blockedStepHelper = `function blockedStep(
  step: string,
  action: string,
  reason: string,
  policy?: string,
  details?: Record<string, unknown>,
): WorkflowStepResult {
  return {
    step,
    action,
    status: 'blocked',
    reason,
    ...(policy ? { policy } : {}),
    ...(details ? { details } : {}),
  };
}`;

        if (actionNodes.length === 0) {
            return `/**
 * ${workflowName}
 * 
 * Auto-generated by Agent OS Workflow Designer
 */

import { AgentOS } from '@agent-governance-python/agent-os/sdk';

${stepResultType}

const agentOS = new AgentOS({
  policy: 'strict',
  apiKey: process.env.AGENT_OS_KEY
});

export async function runWorkflow(task: string): Promise<Record<string, unknown>> {
  return agentOS.execute(async () => ({
    status: 'blocked',
    reason: ${this._quoteGeneratedString(emptyWorkflowReason)},
    steps: [] as WorkflowStepResult[],
    input: { task },
  }));
}
`;
        }

        const functionDefs = actionNodes.map(({ node, action, description, functionName }) => `
async function ${functionName}(context: Record<string, unknown>): Promise<WorkflowStepResult> {
  void context;
  return blockedStep(
    ${this._quoteGeneratedString(node.label)},
    ${this._quoteGeneratedString(action)},
    ${this._quoteGeneratedString(scaffoldReason)},
    ${node.policy ? this._quoteGeneratedString(node.policy) : 'undefined'},
    { description: ${this._quoteGeneratedString(description)} },
  );
}
`).join('');

        const workflowSteps = actionNodes
            .map(({ functionName }) => `steps.push(await ${functionName}(context));`)
            .join('\n    ');

        return `/**
 * ${workflowName}
 * 
 * Auto-generated by Agent OS Workflow Designer
 */

import { AgentOS } from '@agent-governance-python/agent-os/sdk';

${stepResultType}

const agentOS = new AgentOS({
  policy: 'strict',
  apiKey: process.env.AGENT_OS_KEY
});

${blockedStepHelper}
${functionDefs}

export async function runWorkflow(task: string): Promise<Record<string, unknown>> {
  return agentOS.execute(async () => {
    const context: Record<string, unknown> = { task };
    const steps: WorkflowStepResult[] = [];
    
    ${workflowSteps}

    const blockedStepResult = steps.find(step => step.status !== 'completed');
    if (blockedStepResult) {
      return {
        status: 'blocked',
        reason: 'Workflow contains scaffolded steps that must be implemented before execution.',
        blockedStep: blockedStepResult,
        steps,
      };
    }

    return { status: 'completed', steps };
  });
}
`;
    }

    private _generateGoCode(): string {
        const actionNodes = this._workflow.nodes
            .filter(n => n.type === 'action')
            .map((node, index) => ({
                node,
                action: this._getNodeAction(node),
                description: this._getNodeDescription(node),
                functionName: this._toSnakeCase(node.label, `step_${index + 1}`),
            }));
        const workflowName = this._workflow.name || 'New Workflow';
        const scaffoldReason = 'Replace this scaffold with a governed implementation before executing the workflow.';
        const emptyWorkflowReason = 'Add at least one Action node in the Workflow Designer before exporting runnable code.';
        const stepResultType = `type StepResult struct {
\tStep    string                 \`json:"step"\`
\tAction  string                 \`json:"action"\`
\tStatus  string                 \`json:"status"\`
\tReason  string                 \`json:"reason,omitempty"\`
\tPolicy  string                 \`json:"policy,omitempty"\`
\tDetails map[string]interface{} \`json:"details,omitempty"\`
}

func blockedStep(step string, action string, reason string, policy string, details map[string]interface{}) StepResult {
\treturn StepResult{
\t\tStep:    step,
\t\tAction:  action,
\t\tStatus:  "blocked",
\t\tReason:  reason,
\t\tPolicy:  policy,
\t\tDetails: details,
\t}
}`;

        if (actionNodes.length === 0) {
            return `// ${workflowName}
//
// Auto-generated by Agent OS Workflow Designer

package main

import (
\t"context"
\t"fmt"
\t
\tagentos "github.com/microsoft/agent-governance-toolkit/sdk/go"
)

${stepResultType}

func main() {
\tkernel, err := agentos.NewKernel(agentos.WithPolicy("strict"))
\tif err != nil {
\t\tpanic(err)
\t}

\tresult, err := kernel.Execute(context.Background(), runWorkflow, "example task")
\tif err != nil {
\t\tpanic(err)
\t}
\t
\tfmt.Printf("Result: %v\\n", result)
}

func runWorkflow(ctx context.Context, task string) (map[string]interface{}, error) {
\t_ = ctx
\treturn map[string]interface{}{
\t\t"status": "blocked",
\t\t"reason": ${this._quoteGeneratedString(emptyWorkflowReason)},
\t\t"steps":  []StepResult{},
\t\t"input": map[string]interface{}{
\t\t\t"task": task,
\t\t},
\t}, nil
}
`;
        }

        const workflowSteps = actionNodes.map(({ functionName }) => `
\tstepResult, err := ${functionName}(ctx, workflowCtx)
\tif err != nil {
\t\treturn nil, err
\t}
\tsteps = append(steps, stepResult)`).join('\n');

        const functionDefs = actionNodes.map(({ node, action, description, functionName }) => `
func ${functionName}(ctx context.Context, workflowCtx map[string]interface{}) (StepResult, error) {
\t_ = ctx
\t_ = workflowCtx
\treturn blockedStep(
\t\t${this._quoteGeneratedString(node.label)},
\t\t${this._quoteGeneratedString(action)},
\t\t${this._quoteGeneratedString(scaffoldReason)},
\t\t${node.policy ? this._quoteGeneratedString(node.policy) : '""'},
\t\tmap[string]interface{}{"description": ${this._quoteGeneratedString(description)}},
\t), nil
}
`).join('');

        return `// ${workflowName}
//
// Auto-generated by Agent OS Workflow Designer

package main

import (
\t"context"
\t"fmt"
\t
\tagentos "github.com/microsoft/agent-governance-toolkit/sdk/go"
)

${stepResultType}

func main() {
\tkernel, err := agentos.NewKernel(agentos.WithPolicy("strict"))
\tif err != nil {
\t\tpanic(err)
\t}

\tresult, err := kernel.Execute(context.Background(), runWorkflow, "example task")
\tif err != nil {
\t\tpanic(err)
\t}
\t
\tfmt.Printf("Result: %v\\n", result)
}

func runWorkflow(ctx context.Context, task string) (map[string]interface{}, error) {
\tworkflowCtx := map[string]interface{}{"task": task}
\tsteps := []StepResult{}
\t${workflowSteps}

\tfor _, step := range steps {
\t\tif step.Status != "completed" {
\t\t\treturn map[string]interface{}{
\t\t\t\t"status": "blocked",
\t\t\t\t"reason": "Workflow contains scaffolded steps that must be implemented before execution.",
\t\t\t\t"blockedStep": step,
\t\t\t\t"steps": steps,
\t\t\t}, nil
\t\t}
\t}

\treturn map[string]interface{}{"status": "completed", "steps": steps}, nil
}
${functionDefs}
`;
    }

    private _toSnakeCase(str: string, fallback = 'step'): string {
        const normalized = str
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '_')
            .replace(/^_+|_+$/g, '');
        const safe = normalized || fallback;
        return /^[a-z_]/.test(safe) ? safe : `step_${safe}`;
    }

    private _toCamelCase(str: string, fallback = 'step'): string {
        const segments = str
            .trim()
            .split(/[^a-zA-Z0-9]+/)
            .filter(Boolean)
            .map(segment => segment.toLowerCase());
        if (segments.length === 0) {
            return fallback;
        }
        const [first, ...rest] = segments;
        const safe = first + rest.map(segment => segment.charAt(0).toUpperCase() + segment.slice(1)).join('');
        return /^[a-zA-Z_$]/.test(safe) ? safe : `step${safe.charAt(0).toUpperCase()}${safe.slice(1)}`;
    }

    private async _saveWorkflow(): Promise<void> {
        const uri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(`${this._workflow.name.toLowerCase().replace(/\s+/g, '-')}.workflow.json`),
            filters: { 'Workflow': ['workflow.json', 'json'] }
        });

        if (uri) {
            await vscode.workspace.fs.writeFile(
                uri,
                Buffer.from(JSON.stringify(this._workflow, null, 2))
            );
            vscode.window.showInformationMessage(`Workflow saved to ${uri.fsPath}`);
        }
    }

    private async _loadWorkflow(): Promise<void> {
        const uris = await vscode.window.showOpenDialog({
            canSelectMany: false,
            filters: { 'Workflow': ['workflow.json', 'json'] }
        });

        if (uris && uris[0]) {
            const content = await vscode.workspace.fs.readFile(uris[0]);
            let parsed: unknown;
            try {
                parsed = JSON.parse(content.toString());
            } catch (err) {
                const message = err instanceof Error ? err.message : String(err);
                vscode.window.showErrorMessage(`Could not load workflow: invalid JSON (${message}).`);
                return;
            }

            if (!WorkflowDesignerPanel._isWorkflow(parsed)) {
                vscode.window.showErrorMessage(
                    'Could not load workflow: file does not match the Workflow schema (expected id, name, description, nodes[], edges[], policies[]).'
                );
                return;
            }

            this._workflow = parsed;
            this._panel.webview.postMessage({ type: 'workflowLoaded', workflow: this._workflow });
        }
    }

    /**
     * Structural validation for an unknown payload claiming to be a Workflow.
     *
     * Loaded workflow files arrive from disk and may have been hand-edited,
     * truncated, or generated by an older / unrelated tool. Without this
     * guard a malformed file silently replaces the in-memory workflow and
     * the next save / simulate / postMessage call dereferences `.nodes`,
     * `.edges`, etc. on whatever shape was parsed.
     *
     * Field-level checks mirror the `Workflow` / `WorkflowNode` /
     * `WorkflowEdge` interfaces above. Inner object content is only
     * shallow-checked — the strict-typing UI consumers already tolerate
     * additional unknown fields on nodes / edges.
     */
    private static _isWorkflow(value: unknown): value is Workflow {
        if (!value || typeof value !== 'object') {
            return false;
        }
        const v = value as Record<string, unknown>;
        if (typeof v.id !== 'string' || typeof v.name !== 'string' || typeof v.description !== 'string') {
            return false;
        }
        if (!Array.isArray(v.nodes) || !v.nodes.every(WorkflowDesignerPanel._isWorkflowNode)) {
            return false;
        }
        if (!Array.isArray(v.edges) || !v.edges.every(WorkflowDesignerPanel._isWorkflowEdge)) {
            return false;
        }
        if (!Array.isArray(v.policies) || !v.policies.every(p => typeof p === 'string')) {
            return false;
        }
        return true;
    }

    private static _isWorkflowNode(value: unknown): value is WorkflowNode {
        if (!value || typeof value !== 'object') {
            return false;
        }
        const n = value as Record<string, unknown>;
        const validTypes: readonly WorkflowNode['type'][] = ['start', 'end', 'action', 'condition', 'loop', 'parallel'];
        if (typeof n.id !== 'string' || typeof n.label !== 'string') {
            return false;
        }
        if (typeof n.type !== 'string' || !(validTypes as readonly string[]).includes(n.type)) {
            return false;
        }
        const pos = n.position as Record<string, unknown> | null | undefined;
        if (!pos || typeof pos !== 'object' || typeof pos.x !== 'number' || typeof pos.y !== 'number') {
            return false;
        }
        if (!n.config || typeof n.config !== 'object') {
            return false;
        }
        if (n.policy !== undefined && typeof n.policy !== 'string') {
            return false;
        }
        return true;
    }

    private static _isWorkflowEdge(value: unknown): value is WorkflowEdge {
        if (!value || typeof value !== 'object') {
            return false;
        }
        const e = value as Record<string, unknown>;
        if (typeof e.id !== 'string' || typeof e.source !== 'string' || typeof e.target !== 'string') {
            return false;
        }
        if (e.label !== undefined && typeof e.label !== 'string') {
            return false;
        }
        return true;
    }

    private async _simulate(): Promise<void> {
        // Validate workflow
        const issues: string[] = [];
        
        // Check for start node
        if (!this._workflow.nodes.find(n => n.type === 'start')) {
            issues.push('Workflow must have a Start node');
        }
        
        // Check for end node
        if (!this._workflow.nodes.find(n => n.type === 'end')) {
            issues.push('Workflow must have an End node');
        }
        
        // Check for disconnected nodes
        const connectedNodes = new Set<string>();
        this._workflow.edges.forEach(e => {
            connectedNodes.add(e.source);
            connectedNodes.add(e.target);
        });
        
        const disconnected = this._workflow.nodes.filter(
            n => !connectedNodes.has(n.id) && n.type !== 'start'
        );
        
        if (disconnected.length > 0) {
            issues.push(`Disconnected nodes: ${disconnected.map(n => n.label).join(', ')}`);
        }

        if (issues.length > 0) {
            vscode.window.showWarningMessage(`Workflow issues:\n${issues.join('\n')}`);
            return;
        }

        // Simulate execution
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Simulating workflow',
            cancellable: true
        }, async (progress, token) => {
            const actionNodes = this._workflow.nodes.filter(n => n.type === 'action');
            
            for (let i = 0; i < actionNodes.length; i++) {
                if (token.isCancellationRequested) {
                    break;
                }
                
                const node = actionNodes[i];
                progress.report({
                    message: `Executing: ${node.label}`,
                    increment: (100 / actionNodes.length)
                });
                
                // Check policy
                if (node.policy) {
                    this._panel.webview.postMessage({
                        type: 'simulationStep',
                        nodeId: node.id,
                        status: 'checking_policy'
                    });
                }
                
                await new Promise(resolve => setTimeout(resolve, 500));
                
                this._panel.webview.postMessage({
                    type: 'simulationStep',
                    nodeId: node.id,
                    status: 'completed'
                });
            }
            
            vscode.window.showInformationMessage('Workflow simulation completed successfully!');
        });
    }

    public dispose() {
        WorkflowDesignerPanel.currentPanel = undefined;
        this._panel.dispose();
        while (this._disposables.length) {
            const disposable = this._disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }

    private _update() {
        this._panel.title = 'Agent OS Workflow Designer';
        this._panel.webview.html = this._getHtmlForWebview();
    }

    private _getHtmlForWebview() {
        const nonce = crypto.randomBytes(16).toString('base64');
        const webview = this._panel.webview;
        const cspSource = webview.cspSource;

        const nodeTypesJson = JSON.stringify(WorkflowDesignerPanel.nodeTypes);
        const workflowJson = JSON.stringify(this._workflow);

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <!-- SECURITY: 'unsafe-inline' for styles required by VS Code theme CSS variable injection. Scripts nonce-gated. -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src ${cspSource} https:; font-src ${cspSource};">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Workflow Designer</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--vscode-font-family);
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            overflow: hidden;
        }
        .container {
            display: flex;
            height: 100vh;
        }
        .sidebar {
            width: 250px;
            background: var(--vscode-sideBar-background);
            border-right: 1px solid var(--vscode-panel-border);
            padding: 15px;
            overflow-y: auto;
        }
        .sidebar h3 {
            font-size: 12px;
            text-transform: uppercase;
            color: var(--vscode-sideBarSectionHeader-foreground);
            margin-bottom: 10px;
        }
        .node-palette {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .palette-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px;
            background: var(--vscode-editor-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            cursor: grab;
            transition: all 0.2s;
        }
        .palette-item:focus-visible,
        .workflow-node:focus-visible {
            outline: 2px solid var(--vscode-focusBorder);
            outline-offset: 2px;
        }
        .palette-item:hover {
            border-color: var(--vscode-focusBorder);
            background: var(--vscode-list-hoverBackground);
        }
        .palette-item:active {
            cursor: grabbing;
        }
        .palette-icon {
            font-size: 20px;
        }
        .palette-info h4 {
            font-size: 13px;
            margin-bottom: 2px;
        }
        .palette-info p {
            font-size: 11px;
            color: var(--vscode-descriptionForeground);
        }
        .canvas-container {
            flex: 1;
            display: flex;
            flex-direction: column;
        }
        .toolbar {
            display: flex;
            gap: 10px;
            padding: 10px 15px;
            background: var(--vscode-editorGroupHeader-tabsBackground);
            border-bottom: 1px solid var(--vscode-panel-border);
        }
        button {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        button:hover {
            background: var(--vscode-button-hoverBackground);
        }
        button.secondary {
            background: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }
        select {
            background: var(--vscode-dropdown-background);
            color: var(--vscode-dropdown-foreground);
            border: 1px solid var(--vscode-dropdown-border);
            padding: 5px 10px;
            border-radius: 4px;
        }
        .canvas {
            flex: 1;
            position: relative;
            background: 
                linear-gradient(var(--vscode-panel-border) 1px, transparent 1px),
                linear-gradient(90deg, var(--vscode-panel-border) 1px, transparent 1px);
            background-size: 20px 20px;
            overflow: hidden;
        }
        .workflow-node {
            position: absolute;
            min-width: 120px;
            background: var(--vscode-editor-background);
            border: 2px solid var(--vscode-panel-border);
            border-radius: 8px;
            padding: 10px 15px;
            cursor: move;
            user-select: none;
            transition: box-shadow 0.2s;
        }
        .workflow-node:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }
        .workflow-node.selected {
            border-color: var(--vscode-focusBorder);
        }
        .workflow-node.start {
            background: #28a74520;
            border-color: #28a745;
        }
        .workflow-node.end {
            background: #dc354520;
            border-color: #dc3545;
        }
        .workflow-node.action {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
        }
        .workflow-node.condition {
            background: #ffc10720;
            border-color: #ffc107;
        }
        .node-header {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 5px;
        }
        .node-icon {
            font-size: 16px;
        }
        .node-label {
            font-size: 13px;
            font-weight: bold;
        }
        .node-policy {
            font-size: 10px;
            color: var(--vscode-descriptionForeground);
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .node-connectors {
            position: absolute;
            width: 100%;
            height: 100%;
            top: 0;
            left: 0;
            pointer-events: none;
        }
        .connector {
            position: absolute;
            width: 12px;
            height: 12px;
            background: var(--vscode-button-background);
            border: 2px solid var(--vscode-editor-background);
            border-radius: 50%;
            pointer-events: all;
            cursor: crosshair;
        }
        .connector.input {
            top: 50%;
            left: -6px;
            transform: translateY(-50%);
        }
        .connector.output {
            top: 50%;
            right: -6px;
            transform: translateY(-50%);
        }
        svg.connections {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
        }
        svg.connections path {
            fill: none;
            stroke: var(--vscode-button-background);
            stroke-width: 2;
        }
        .properties-panel {
            width: 280px;
            background: var(--vscode-sideBar-background);
            border-left: 1px solid var(--vscode-panel-border);
            padding: 15px;
            overflow-y: auto;
        }
        .properties-panel h3 {
            font-size: 14px;
            margin-bottom: 15px;
        }
        .property-group {
            margin-bottom: 15px;
        }
        .property-group label {
            display: block;
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
            margin-bottom: 5px;
        }
        .property-group input,
        .property-group select,
        .property-group textarea {
            width: 100%;
            background: var(--vscode-input-background);
            color: var(--vscode-input-foreground);
            border: 1px solid var(--vscode-input-border);
            padding: 6px 10px;
            border-radius: 4px;
            font-size: 13px;
        }
        .property-group textarea {
            min-height: 60px;
            resize: vertical;
        }
        .empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: var(--vscode-descriptionForeground);
            text-align: center;
            padding: 20px;
        }
        .empty-state .icon {
            font-size: 48px;
            margin-bottom: 15px;
        }
        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            white-space: nowrap;
            border: 0;
        }
    </style>
</head>
<body>
    <main class="container" aria-label="Workflow designer">
        <aside class="sidebar" aria-label="Workflow components">
            <h3>Components</h3>
            <p class="sr-only">Press Enter on a component to add it to the canvas. Use arrow keys to move a selected node.</p>
            <div class="node-palette" id="palette" role="list"></div>
        </aside>
        
        <section class="canvas-container" aria-labelledby="workflow-canvas-heading">
            <h2 id="workflow-canvas-heading" class="sr-only">Workflow canvas</h2>
            <div class="toolbar" role="toolbar" aria-label="Workflow actions">
                <button data-action="simulate">▶️ Simulate</button>
                <button data-action="save">💾 Save</button>
                <button class="secondary" data-action="load">📂 Load</button>
                <div style="flex:1"></div>
                <label class="sr-only" for="exportLang">Export language</label>
                <select id="exportLang" aria-label="Export language">
                    <option value="python">Python</option>
                    <option value="typescript">TypeScript</option>
                    <option value="go">Go</option>
                </select>
                <button data-action="export">📤 Export Code</button>
            </div>
            <div class="canvas" id="canvas" tabindex="0" role="region" aria-label="Workflow canvas">
                <svg class="connections" id="connections"></svg>
            </div>
        </section>
        
        <aside class="properties-panel" id="properties" aria-label="Selected node properties">
            <div class="empty-state">
                <div class="icon">📝</div>
                <p>Select a node to edit its properties</p>
            </div>
        </aside>
    </main>

    <script nonce="${nonce}">
        const vscode = acquireVsCodeApi();
        const nodeTypes = ${nodeTypesJson};
        let workflow = ${workflowJson};
        let selectedNode = null;
        let draggingNode = null;
        let connectingFrom = null;
        const KEYBOARD_MOVE_STEP = 20;

        function escapeHtml(value) {
            return String(value ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        // Render palette
        const palette = document.getElementById('palette');
        nodeTypes.forEach(nt => {
            const item = document.createElement('button');
            item.type = 'button';
            item.className = 'palette-item';
            item.draggable = true;
            item.dataset.type = nt.type;
            item.setAttribute('role', 'listitem');
            item.setAttribute('aria-label', 'Add ' + nt.label + ' node. ' + nt.description);
            item.innerHTML = \`
                <span class="palette-icon">\${escapeHtml(nt.icon)}</span>
                <div class="palette-info">
                    <h4>\${escapeHtml(nt.label)}</h4>
                    <p>\${escapeHtml(nt.description)}</p>
                </div>
            \`;
            item.addEventListener('dragstart', e => {
                e.dataTransfer.setData('nodeType', nt.type);
            });
            item.addEventListener('click', () => addNode(nt.type, getCanvasCenterPosition()));
            item.addEventListener('keydown', e => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    addNode(nt.type, getCanvasCenterPosition());
                }
            });
            palette.appendChild(item);
        });

        // Render nodes
        function renderNodes() {
            const canvas = document.getElementById('canvas');
            // Clear existing nodes
            canvas.querySelectorAll('.workflow-node').forEach(n => n.remove());
            
            workflow.nodes.forEach(node => {
                const div = document.createElement('div');
                div.className = \`workflow-node \${node.type}\${selectedNode?.id === node.id ? ' selected' : ''}\`;
                div.style.left = node.position.x + 'px';
                div.style.top = node.position.y + 'px';
                div.dataset.id = node.id;
                div.tabIndex = 0;
                div.setAttribute('role', 'button');
                
                const nodeType = nodeTypes.find(t => t.type === node.type);
                div.setAttribute(
                    'aria-label',
                    node.label + '. Type ' + node.type + '. ' +
                    (node.policy ? 'Policy ' + node.policy + '. ' : '') +
                    'Press Enter to edit or arrow keys to move.'
                );
                const icon = nodeType?.icon || (node.type === 'start' ? '▶️' : node.type === 'end' ? '🏁' : '⚡');
                
                div.innerHTML = \`
                    <div class="node-header">
                        <span class="node-icon">\${escapeHtml(icon)}</span>
                        <span class="node-label">\${escapeHtml(node.label)}</span>
                    </div>
                    \${node.policy ? \`<div class="node-policy">🛡️ \${escapeHtml(node.policy)}</div>\` : ''}
                    <div class="node-connectors">
                        \${node.type !== 'start' ? '<div class="connector input" data-connector="input"></div>' : ''}
                        \${node.type !== 'end' ? '<div class="connector output" data-connector="output"></div>' : ''}
                    </div>
                \`;
                
                // Make draggable
                div.addEventListener('mousedown', e => {
                    if (e.target.classList.contains('connector')) return;
                    draggingNode = node;
                    selectNode(node);
                });
                div.addEventListener('click', () => selectNode(node));
                div.addEventListener('keydown', e => handleNodeKeydown(e, node));
                
                // Handle connector clicks for edges
                div.querySelectorAll('.connector').forEach(conn => {
                    conn.addEventListener('mousedown', e => {
                        e.stopPropagation();
                        if (conn.dataset.connector === 'output') {
                            connectingFrom = node.id;
                        }
                    });
                    conn.addEventListener('mouseup', e => {
                        if (connectingFrom && conn.dataset.connector === 'input') {
                            addEdge(connectingFrom, node.id);
                        }
                        connectingFrom = null;
                    });
                });
                
                canvas.appendChild(div);
            });
            
            renderEdges();
            focusSelectedNode();
        }

        function renderEdges() {
            const svg = document.getElementById('connections');
            svg.innerHTML = '';
            
            workflow.edges.forEach(edge => {
                const sourceNode = workflow.nodes.find(n => n.id === edge.source);
                const targetNode = workflow.nodes.find(n => n.id === edge.target);
                if (!sourceNode || !targetNode) return;
                
                const sourceEl = document.querySelector(\`[data-id="\${edge.source}"]\`);
                const targetEl = document.querySelector(\`[data-id="\${edge.target}"]\`);
                if (!sourceEl || !targetEl) return;
                
                const x1 = sourceNode.position.x + sourceEl.offsetWidth;
                const y1 = sourceNode.position.y + sourceEl.offsetHeight / 2;
                const x2 = targetNode.position.x;
                const y2 = targetNode.position.y + targetEl.offsetHeight / 2;
                
                const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                const cx = (x1 + x2) / 2;
                path.setAttribute('d', \`M \${x1} \${y1} C \${cx} \${y1}, \${cx} \${y2}, \${x2} \${y2}\`);
                svg.appendChild(path);
            });
        }

        function selectNode(node) {
            selectedNode = node;
            renderNodes();
            renderProperties(node);
        }

        function focusSelectedNode() {
            if (!selectedNode) return;
            const selectedElement = document.querySelector(\`[data-id="\${selectedNode.id}"]\`);
            if (selectedElement && document.activeElement !== selectedElement) {
                selectedElement.focus();
            }
        }

        function moveNode(node, deltaX, deltaY) {
            node.position.x = Math.max(0, node.position.x + deltaX);
            node.position.y = Math.max(0, node.position.y + deltaY);
            vscode.postMessage({ type: 'updateWorkflow', workflow });
            renderNodes();
        }

        function handleNodeKeydown(event, node) {
            switch (event.key) {
                case 'Enter':
                case ' ':
                    event.preventDefault();
                    selectNode(node);
                    break;
                case 'ArrowLeft':
                    event.preventDefault();
                    moveNode(node, -KEYBOARD_MOVE_STEP, 0);
                    break;
                case 'ArrowRight':
                    event.preventDefault();
                    moveNode(node, KEYBOARD_MOVE_STEP, 0);
                    break;
                case 'ArrowUp':
                    event.preventDefault();
                    moveNode(node, 0, -KEYBOARD_MOVE_STEP);
                    break;
                case 'ArrowDown':
                    event.preventDefault();
                    moveNode(node, 0, KEYBOARD_MOVE_STEP);
                    break;
                case 'Delete':
                case 'Backspace':
                    if (node.type !== 'start' && node.type !== 'end') {
                        event.preventDefault();
                        deleteNode(node.id);
                    }
                    break;
            }
        }

        function renderProperties(node) {
            const panel = document.getElementById('properties');
            if (!node) {
                panel.innerHTML = \`
                    <div class="empty-state">
                        <div class="icon">📝</div>
                        <p>Select a node to edit its properties</p>
                    </div>
                \`;
                return;
            }
            
            const nodeType = nodeTypes.find(t => t.type === node.type);
            
            panel.innerHTML = \`
                <h3>\${escapeHtml(node.label)} Properties</h3>
                <div class="property-group">
                    <label>Label</label>
                    <input type="text" id="prop-label" value="\${escapeHtml(node.label)}">
                </div>
                \${node.type === 'action' && nodeType?.actions ? \`
                <div class="property-group">
                    <label>Action Type</label>
                    <select id="prop-action">
                        \${nodeType.actions.map(a => \`<option value="\${escapeHtml(a)}" \${node.config.action === a ? 'selected' : ''}>\${escapeHtml(a)}</option>\`).join('')}
                    </select>
                </div>
                \` : ''}
                <div class="property-group">
                    <label>Description</label>
                    <textarea id="prop-description">\${escapeHtml(node.config.description || '')}</textarea>
                </div>
                <div class="property-group">
                    <label>Policy</label>
                    <select id="prop-policy">
                        <option value="">None</option>
                        <option value="strict" \${node.policy === 'strict' ? 'selected' : ''}>Strict</option>
                        <option value="rate_limit" \${node.policy === 'rate_limit' ? 'selected' : ''}>Rate Limit</option>
                        <option value="approval_required" \${node.policy === 'approval_required' ? 'selected' : ''}>Approval Required</option>
                    </select>
                </div>
                \${node.type !== 'start' && node.type !== 'end' ? \`
                <div class="property-group">
                    <button class="secondary delete-btn" data-node-id="\${escapeHtml(node.id)}" style="width:100%">🗑️ Delete Node</button>
                </div>
                \` : ''}
            \`;
            
            // Bind change events
            document.getElementById('prop-label')?.addEventListener('change', e => {
                node.label = e.target.value;
                updateNode(node);
            });
            document.getElementById('prop-action')?.addEventListener('change', e => {
                node.config.action = e.target.value;
                updateNode(node);
            });
            document.getElementById('prop-description')?.addEventListener('change', e => {
                node.config.description = e.target.value;
                updateNode(node);
            });
            document.getElementById('prop-policy')?.addEventListener('change', e => {
                node.policy = e.target.value || undefined;
                updateNode(node);
            });
            
            // Bind delete button
            const deleteBtn = document.querySelector('.delete-btn');
            if (deleteBtn) {
                deleteBtn.addEventListener('click', () => {
                    deleteNode(deleteBtn.dataset.nodeId);
                });
            }
        }

        function updateNode(node) {
            vscode.postMessage({ type: 'updateNode', nodeId: node.id, updates: node });
            renderNodes();
        }

        function addEdge(source, target) {
            if (source === target) return;
            if (workflow.edges.some(e => e.source === source && e.target === target)) return;
            
            const edge = { id: 'edge-' + Date.now(), source, target };
            workflow.edges.push(edge);
            vscode.postMessage({ type: 'addEdge', source, target });
            renderEdges();
        }

        function deleteNode(nodeId) {
            workflow.nodes = workflow.nodes.filter(n => n.id !== nodeId);
            workflow.edges = workflow.edges.filter(e => e.source !== nodeId && e.target !== nodeId);
            selectedNode = null;
            vscode.postMessage({ type: 'removeNode', nodeId });
            renderNodes();
            renderProperties(null);
        }

        function getCanvasCenterPosition() {
            const rect = canvas.getBoundingClientRect();
            return {
                x: Math.max(20, rect.width / 2 - 60),
                y: Math.max(20, rect.height / 2 - 20)
            };
        }

        // Canvas drop handling
        const canvas = document.getElementById('canvas');
        canvas.addEventListener('dragover', e => e.preventDefault());
        canvas.addEventListener('drop', e => {
            e.preventDefault();
            const nodeType = e.dataTransfer.getData('nodeType');
            if (nodeType) {
                const rect = canvas.getBoundingClientRect();
                const position = {
                    x: e.clientX - rect.left - 60,
                    y: e.clientY - rect.top - 20
                };
                addNode(nodeType, position);
            }
        });

        // Mouse move for dragging
        document.addEventListener('mousemove', e => {
            if (draggingNode) {
                const rect = canvas.getBoundingClientRect();
                draggingNode.position.x = e.clientX - rect.left - 60;
                draggingNode.position.y = e.clientY - rect.top - 20;
                vscode.postMessage({ type: 'updateWorkflow', workflow });
                renderNodes();
            }
        });

        document.addEventListener('mouseup', () => {
            draggingNode = null;
            connectingFrom = null;
        });

        function addNode(type, position) {
            const nodeType = nodeTypes.find(t => t.type === type);
            const node = {
                id: 'node-' + Date.now(),
                type,
                label: nodeType?.label || type,
                position,
                config: {}
            };
            workflow.nodes.push(node);
            vscode.postMessage({ type: 'addNode', nodeType: type, position });
            renderNodes();
        }

        function simulate() {
            vscode.postMessage({ type: 'simulate' });
        }

        function saveWorkflow() {
            vscode.postMessage({ type: 'saveWorkflow' });
        }

        function loadWorkflow() {
            vscode.postMessage({ type: 'loadWorkflow' });
        }

        function exportCode() {
            const lang = document.getElementById('exportLang').value;
            vscode.postMessage({ type: 'exportCode', language: lang });
        }

        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.type) {
                case 'workflowLoaded':
                    workflow = message.workflow;
                    renderNodes();
                    break;
                case 'simulationStep':
                    const el = document.querySelector(\`[data-id="\${message.nodeId}"]\`);
                    if (el) {
                        el.style.boxShadow = message.status === 'completed' 
                            ? '0 0 10px #28a745' 
                            : '0 0 10px #ffc107';
                    }
                    break;
            }
        });

        // Toolbar buttons use "data-action" rather than inline "onclick="
        // attributes so the page is CSP-compliant under
        // "script-src 'nonce-...'" (which blocks inline event handlers).
        // A single delegated click listener bound from this nonce-gated
        // script dispatches to the appropriate function.
        const __toolbarActions = {
            simulate: simulate,
            save: saveWorkflow,
            load: loadWorkflow,
            export: exportCode,
        };
        document.addEventListener('click', (event) => {
            const target = event.target.closest('[data-action]');
            if (!target) return;
            const handler = __toolbarActions[target.dataset.action];
            if (handler) {
                handler();
            }
        });

        // Initial render
        renderNodes();
    </script>
</body>
</html>`;
    }
}
