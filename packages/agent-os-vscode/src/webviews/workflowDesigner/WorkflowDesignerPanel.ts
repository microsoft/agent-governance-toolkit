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
import { escapeHtml } from '../../utils/escapeHtml';

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

    private _generatePythonCode(): string {
        const nodes = this._workflow.nodes.filter(n => n.type === 'action');
        const imports = [
            'from agent_os import KernelSpace, Policy',
            'from agent_os.tools import create_safe_toolkit'
        ];

        if (nodes.length === 0) {
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
    """Add action nodes to your workflow to generate code"""
    context = {"task": task}
    # TODO: Add workflow steps
    return {"status": "success"}

if __name__ == "__main__":
    import asyncio
    result = asyncio.run(kernel.execute(run_workflow, "example task"))
    print(result)
`;
        }

        const functions = nodes.map(node => {
            const action = node.config.action || 'execute_task';
            return `
async def ${this._toSnakeCase(node.label)}(context):
    """${node.config.description || 'Execute ' + node.label}"""
    ${node.policy ? `# Policy: ${node.policy}` : '# No policy attached'}
    # TODO: Implement ${action}
    return {"status": "success"}
`;
        });

        const workflowSteps = nodes.length > 0 
            ? nodes.map(n => `result = await ${this._toSnakeCase(n.label)}(context)`).join('\n    ')
            : '# No action nodes defined';

        const workflow = `
async def run_workflow(task: str):
    """${this._workflow.description || 'Agent workflow'}"""
    context = {"task": task}
    
    ${workflowSteps}
    
    return result if 'result' in dir() else {"status": "success"}
`;

        return `"""
${this._workflow.name || 'New Workflow'}

Auto-generated by Agent OS Workflow Designer
"""

${imports.join('\n')}

# Initialize kernel with policy
kernel = KernelSpace(policy="strict")
toolkit = create_safe_toolkit("standard")

${functions.join('\n')}

@kernel.register
${workflow}

if __name__ == "__main__":
    import asyncio
    result = asyncio.run(kernel.execute(run_workflow, "example task"))
    print(result)
`;
    }

    private _generateTypeScriptCode(): string {
        const nodes = this._workflow.nodes.filter(n => n.type === 'action');
        const workflowName = this._workflow.name || 'New Workflow';

        if (nodes.length === 0) {
            return `/**
 * ${workflowName}
 * 
 * Auto-generated by Agent OS Workflow Designer
 */

import { AgentOS } from '@agent-os/sdk';

const agentOS = new AgentOS({
  policy: 'strict',
  apiKey: process.env.AGENT_OS_KEY
});

export async function runWorkflow(task: string) {
  return agentOS.execute(async () => {
    const context = { task };
    // TODO: Add workflow steps by adding Action nodes in the designer
    return { success: true };
  });
}
`;
        }

        const functionDefs = nodes.map(node => `
async function ${this._toCamelCase(node.label)}(context: Record<string, unknown>): Promise<Record<string, unknown>> {
  // ${node.config.description || 'Execute ' + node.label}
  ${node.policy ? `// Policy: ${node.policy}` : '// No policy attached'}
  // TODO: Implement ${node.config.action || 'action'}
  return { status: 'success' };
}
`).join('');

        const workflowSteps = nodes.map(n => 
            `const ${this._toCamelCase(n.label)}Result = await ${this._toCamelCase(n.label)}(context);`
        ).join('\n    ');

        return `/**
 * ${workflowName}
 * 
 * Auto-generated by Agent OS Workflow Designer
 */

import { AgentOS } from '@agent-os/sdk';

const agentOS = new AgentOS({
  policy: 'strict',
  apiKey: process.env.AGENT_OS_KEY
});
${functionDefs}

export async function runWorkflow(task: string): Promise<Record<string, unknown>> {
  return agentOS.execute(async () => {
    const context: Record<string, unknown> = { task };
    
    ${workflowSteps}
    
    return { success: true };
  });
}
`;
    }

    private _generateGoCode(): string {
        const nodes = this._workflow.nodes.filter(n => n.type === 'action');
        const workflowName = this._workflow.name || 'New Workflow';

        if (nodes.length === 0) {
            return `// ${workflowName}
//
// Auto-generated by Agent OS Workflow Designer

package main

import (
	"context"
	"fmt"
	
	agentos "github.com/microsoft/agent-governance-toolkit/sdk/go"
)

func main() {
	kernel, err := agentos.NewKernel(agentos.WithPolicy("strict"))
	if err != nil {
		panic(err)
	}

	result, err := kernel.Execute(context.Background(), runWorkflow, "example task")
	if err != nil {
		panic(err)
	}
	
	fmt.Printf("Result: %v\\n", result)
}

func runWorkflow(ctx context.Context, task string) (map[string]interface{}, error) {
	_ = ctx  // TODO: Use context
	_ = task // TODO: Use task
	// Add Action nodes in the designer to generate workflow steps
	return map[string]interface{}{"status": "success"}, nil
}
`;
        }

        const workflowSteps = nodes.map(n => `
	// ${n.config.description || 'Execute ' + n.label}
	${this._toSnakeCase(n.label)}Result, err := ${this._toSnakeCase(n.label)}(ctx, workflowCtx)
	if err != nil {
		return nil, err
	}
	_ = ${this._toSnakeCase(n.label)}Result`).join('\n');

        const functionDefs = nodes.map(node => `
func ${this._toSnakeCase(node.label)}(ctx context.Context, workflowCtx map[string]interface{}) (map[string]interface{}, error) {
	_ = ctx         // TODO: Use context
	_ = workflowCtx // TODO: Use workflow context
	// TODO: Implement ${node.config.action || 'action'}
	return map[string]interface{}{"status": "success"}, nil
}
`).join('');

        return `// ${workflowName}
//
// Auto-generated by Agent OS Workflow Designer

package main

import (
	"context"
	"fmt"
	
	agentos "github.com/microsoft/agent-governance-toolkit/sdk/go"
)

func main() {
	kernel, err := agentos.NewKernel(agentos.WithPolicy("strict"))
	if err != nil {
		panic(err)
	}

	result, err := kernel.Execute(context.Background(), runWorkflow, "example task")
	if err != nil {
		panic(err)
	}
	
	fmt.Printf("Result: %v\\n", result)
}

func runWorkflow(ctx context.Context, task string) (map[string]interface{}, error) {
	workflowCtx := map[string]interface{}{"task": task}
	${workflowSteps}
	
	return map[string]interface{}{"status": "success"}, nil
}
${functionDefs}
`;
    }

    private _toSnakeCase(str: string): string {
        return str.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');
    }

    private _toCamelCase(str: string): string {
        return str.toLowerCase()
            .replace(/[^a-zA-Z0-9]+(.)/g, (m, chr) => chr.toUpperCase());
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
            this._workflow = JSON.parse(content.toString());
            this._panel.webview.postMessage({ type: 'workflowLoaded', workflow: this._workflow });
        }
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
                <button onclick="simulate()">▶️ Simulate</button>
                <button onclick="saveWorkflow()">💾 Save</button>
                <button class="secondary" onclick="loadWorkflow()">📂 Load</button>
                <div style="flex:1"></div>
                <label class="sr-only" for="exportLang">Export language</label>
                <select id="exportLang" aria-label="Export language">
                    <option value="python">Python</option>
                    <option value="typescript">TypeScript</option>
                    <option value="go">Go</option>
                </select>
                <button onclick="exportCode()">📤 Export Code</button>
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

        // Initial render
        renderNodes();
    </script>
</body>
</html>`;
    }
}
