// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import * as assert from 'assert';

const Module = require('module') as {
    _load: (request: string, parent: NodeModule | undefined, isMain: boolean) => unknown;
};
const originalLoad = Module._load;
const workflowDesignerModulePath = '../../webviews/workflowDesigner/WorkflowDesignerPanel';
let WorkflowDesignerPanel: typeof import('../../webviews/workflowDesigner/WorkflowDesignerPanel').WorkflowDesignerPanel;

type WorkflowShape = {
    id: string;
    name: string;
    description: string;
    nodes: Array<{
        id: string;
        type: 'start' | 'end' | 'action' | 'condition' | 'loop' | 'parallel';
        label: string;
        position: { x: number; y: number };
        config: Record<string, unknown>;
        policy?: string;
    }>;
    edges: Array<{ id: string; source: string; target: string; label?: string }>;
    policies: string[];
};

function makeWorkflow(overrides?: Partial<WorkflowShape>): WorkflowShape {
    return {
        id: 'workflow-1',
        name: 'Generated Workflow',
        description: 'Generated workflow description',
        nodes: [
            { id: 'start', type: 'start', label: 'Start', position: { x: 0, y: 0 }, config: {} },
            { id: 'end', type: 'end', label: 'End', position: { x: 200, y: 0 }, config: {} },
        ],
        edges: [],
        policies: [],
        ...overrides,
    };
}

function createPanel(workflow: WorkflowShape): any {
    const panel = Object.create(WorkflowDesignerPanel.prototype) as any;
    panel._workflow = workflow;
    return panel;
}

suite('WorkflowDesignerPanel code generation', () => {
    setup(() => {
        Module._load = ((request: string, parent: NodeModule | undefined, isMain: boolean) => {
            if (request === 'vscode') {
                return {
                    window: {},
                    workspace: {},
                    Uri: { file: (fsPath: string) => ({ fsPath }) },
                    ProgressLocation: { Notification: 15 },
                    ViewColumn: { One: 1 },
                };
            }
            return originalLoad(request, parent, isMain);
        }) as typeof Module._load;
        delete require.cache[require.resolve(workflowDesignerModulePath)];
        WorkflowDesignerPanel = require(workflowDesignerModulePath).WorkflowDesignerPanel;
    });

    teardown(() => {
        Module._load = originalLoad;
        delete require.cache[require.resolve(workflowDesignerModulePath)];
    });

    test('empty exports fail closed without TODO placeholders', () => {
        const panel = createPanel(makeWorkflow());

        const python = panel._generatePythonCode() as string;
        const typescript = panel._generateTypeScriptCode() as string;
        const go = panel._generateGoCode() as string;

        for (const code of [python, typescript, go]) {
            assert.ok(!code.includes('TODO'), 'generated scaffold should not contain TODO placeholders');
            assert.ok(code.includes('blocked'), 'generated scaffold should fail closed');
            assert.ok(
                code.includes('Add at least one Action node in the Workflow Designer before exporting runnable code.'),
                'empty export should explain how to unblock execution',
            );
        }
    });

    test('action exports generate blocked scaffolds with step metadata', () => {
        const panel = createPanel(makeWorkflow({
            nodes: [
                { id: 'start', type: 'start', label: 'Start', position: { x: 0, y: 0 }, config: {} },
                {
                    id: 'action-1',
                    type: 'action',
                    label: '1 Review Input',
                    position: { x: 120, y: 0 },
                    config: {
                        action: 'file_read',
                        description: 'Read the input payload before validation.',
                    },
                    policy: 'restricted',
                },
                { id: 'end', type: 'end', label: 'End', position: { x: 240, y: 0 }, config: {} },
            ],
        }));

        const python = panel._generatePythonCode() as string;
        const typescript = panel._generateTypeScriptCode() as string;
        const go = panel._generateGoCode() as string;

        for (const code of [python, typescript, go]) {
            assert.ok(!code.includes('TODO'), 'generated scaffold should not contain TODO placeholders');
            assert.ok(
                code.includes('Replace this scaffold with a governed implementation before executing the workflow.'),
                'action scaffold should explain why execution is blocked',
            );
            assert.ok(code.includes('file_read'), 'configured action should be preserved in the scaffold');
            assert.ok(code.includes('restricted'), 'attached policy should be preserved in the scaffold');
        }

        assert.ok(python.includes('step_1_review_input'), 'python export should fall back to a safe identifier');
        assert.ok(typescript.includes('step1ReviewInput'), 'typescript export should fall back to a safe identifier');
        assert.ok(go.includes('step_1_review_input'), 'go export should fall back to a safe identifier');
        assert.ok(typescript.includes('type WorkflowStepResult = {'), 'typescript export should expose structured step results');
        assert.ok(go.includes('type StepResult struct {'), 'go export should expose structured step results');
    });
});
