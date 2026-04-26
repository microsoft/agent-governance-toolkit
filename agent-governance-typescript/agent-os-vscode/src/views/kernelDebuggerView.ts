// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent OS - Kernel Debugger View
 * 
 * Real-time visualization of agent execution, kernel state, and signals.
 * Provides time-travel debugging capabilities for agent decisions.
 */

import * as vscode from 'vscode';

interface AgentState {
    id: string;
    name: string;
    status: 'running' | 'paused' | 'stopped' | 'error';
    currentTask?: string;
    memoryUsage: number;
    checkpoints: Checkpoint[];
    signals: SignalEvent[];
}

interface Checkpoint {
    id: string;
    name: string;
    timestamp: Date;
    state: Record<string, any>;
    reasoning: string;
}

interface SignalEvent {
    signal: 'SIGKILL' | 'SIGSTOP' | 'SIGCONT' | 'SIGTERM';
    timestamp: Date;
    reason: string;
    source: string;
}

interface KernelState {
    activeAgents: AgentState[];
    policyViolations: number;
    totalCheckpoints: number;
    uptime: number;
}

export class KernelDebuggerProvider implements vscode.TreeDataProvider<DebuggerItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<DebuggerItem | undefined | null | void> =
        new vscode.EventEmitter<DebuggerItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<DebuggerItem | undefined | null | void> =
        this._onDidChangeTreeData.event;

    private kernelState: KernelState = {
        activeAgents: [],
        policyViolations: 0,
        totalCheckpoints: 0,
        uptime: 0
    };

    private selectedCheckpoint: Checkpoint | null = null;
    private _refreshInterval: ReturnType<typeof setInterval> | undefined;

    constructor() {
        // Start polling for kernel state updates
        this.startPolling();
    }

    /** Release the polling timer and event emitter. */
    dispose(): void {
        if (this._refreshInterval) {
            clearInterval(this._refreshInterval);
            this._refreshInterval = undefined;
        }
        this._onDidChangeTreeData.dispose();
    }

    private startPolling(): void {
        this._refreshInterval = setInterval(() => {
            this.updateKernelState();
            this._onDidChangeTreeData.fire();
        }, 1000);
    }

    private async updateKernelState(): Promise<void> {
        // In production, this would connect to the actual Agent OS kernel
        // For now, we simulate state updates
        this.kernelState.uptime += 1;
        
        // Simulate agent activity
        if (this.kernelState.activeAgents.length === 0) {
            this.kernelState.activeAgents = [
                {
                    id: 'agent-001',
                    name: 'DataAnalyzer',
                    status: 'running',
                    currentTask: 'Processing Q4 sales data',
                    memoryUsage: 45,
                    checkpoints: [],
                    signals: []
                }
            ];
        }
    }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: DebuggerItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: DebuggerItem): Thenable<DebuggerItem[]> {
        if (!element) {
            // Root level - show main categories
            return Promise.resolve([
                new DebuggerItem(
                    'Kernel Status',
                    vscode.TreeItemCollapsibleState.Expanded,
                    'category',
                    { type: 'kernel-status' }
                ),
                new DebuggerItem(
                    'Active Agents',
                    vscode.TreeItemCollapsibleState.Expanded,
                    'category',
                    { type: 'agents' }
                ),
                new DebuggerItem(
                    'Time-Travel',
                    vscode.TreeItemCollapsibleState.Collapsed,
                    'category',
                    { type: 'time-travel' }
                ),
                new DebuggerItem(
                    'Signal History',
                    vscode.TreeItemCollapsibleState.Collapsed,
                    'category',
                    { type: 'signals' }
                )
            ]);
        }

        // Children based on category
        const data = element.data;
        
        if (data?.type === 'kernel-status') {
            return Promise.resolve([
                new DebuggerItem(
                    `Uptime: ${this.formatUptime(this.kernelState.uptime)}`,
                    vscode.TreeItemCollapsibleState.None,
                    'info',
                    { icon: '$(clock)' }
                ),
                new DebuggerItem(
                    `Active Agents: ${this.kernelState.activeAgents.length}`,
                    vscode.TreeItemCollapsibleState.None,
                    'info',
                    { icon: '$(person)' }
                ),
                new DebuggerItem(
                    `Policy Violations: ${this.kernelState.policyViolations}`,
                    vscode.TreeItemCollapsibleState.None,
                    this.kernelState.policyViolations > 0 ? 'warning' : 'info',
                    { icon: this.kernelState.policyViolations > 0 ? '$(warning)' : '$(check)' }
                ),
                new DebuggerItem(
                    `Checkpoints: ${this.kernelState.totalCheckpoints}`,
                    vscode.TreeItemCollapsibleState.None,
                    'info',
                    { icon: '$(history)' }
                )
            ]);
        }

        if (data?.type === 'agents') {
            return Promise.resolve(
                this.kernelState.activeAgents.map(agent => 
                    new DebuggerItem(
                        `${this.getStatusIcon(agent.status)} ${agent.name}`,
                        vscode.TreeItemCollapsibleState.Collapsed,
                        'agent',
                        { type: 'agent', agent }
                    )
                )
            );
        }

        if (data?.type === 'agent' && data.agent) {
            const agent = data.agent as AgentState;
            return Promise.resolve([
                new DebuggerItem(
                    `ID: ${agent.id}`,
                    vscode.TreeItemCollapsibleState.None,
                    'info'
                ),
                new DebuggerItem(
                    `Status: ${agent.status}`,
                    vscode.TreeItemCollapsibleState.None,
                    agent.status === 'running' ? 'info' : 'warning'
                ),
                new DebuggerItem(
                    `Task: ${agent.currentTask || 'None'}`,
                    vscode.TreeItemCollapsibleState.None,
                    'info'
                ),
                new DebuggerItem(
                    `Memory: ${agent.memoryUsage}%`,
                    vscode.TreeItemCollapsibleState.None,
                    agent.memoryUsage > 80 ? 'warning' : 'info'
                ),
                new DebuggerItem(
                    'View Checkpoints',
                    vscode.TreeItemCollapsibleState.None,
                    'action',
                    { command: 'agent-os.viewCheckpoints', agent }
                ),
                new DebuggerItem(
                    'Send Signal',
                    vscode.TreeItemCollapsibleState.None,
                    'action',
                    { command: 'agent-os.sendSignal', agent }
                )
            ]);
        }

        if (data?.type === 'time-travel') {
            return Promise.resolve([
                new DebuggerItem(
                    'Select Checkpoint...',
                    vscode.TreeItemCollapsibleState.None,
                    'action',
                    { command: 'agent-os.selectCheckpoint' }
                ),
                new DebuggerItem(
                    'Replay from Start',
                    vscode.TreeItemCollapsibleState.None,
                    'action',
                    { command: 'agent-os.replayFromStart' }
                ),
                new DebuggerItem(
                    'Compare Sessions',
                    vscode.TreeItemCollapsibleState.None,
                    'action',
                    { command: 'agent-os.compareSessions' }
                )
            ]);
        }

        return Promise.resolve([]);
    }

    private getStatusIcon(status: string): string {
        switch (status) {
            case 'running': return '🟢';
            case 'paused': return '🟡';
            case 'stopped': return '🔴';
            case 'error': return '❌';
            default: return '⚪';
        }
    }

    private formatUptime(seconds: number): string {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        return `${hours}h ${minutes}m ${secs}s`;
    }

    // Public methods for external control
    
    addAgent(agent: AgentState): void {
        this.kernelState.activeAgents.push(agent);
        this._onDidChangeTreeData.fire();
    }

    removeAgent(agentId: string): void {
        this.kernelState.activeAgents = this.kernelState.activeAgents.filter(a => a.id !== agentId);
        this._onDidChangeTreeData.fire();
    }

    updateAgentStatus(agentId: string, status: AgentState['status']): void {
        const agent = this.kernelState.activeAgents.find(a => a.id === agentId);
        if (agent) {
            agent.status = status;
            this._onDidChangeTreeData.fire();
        }
    }

    addCheckpoint(agentId: string, checkpoint: Checkpoint): void {
        const agent = this.kernelState.activeAgents.find(a => a.id === agentId);
        if (agent) {
            agent.checkpoints.push(checkpoint);
            this.kernelState.totalCheckpoints++;
            this._onDidChangeTreeData.fire();
        }
    }

    recordViolation(): void {
        this.kernelState.policyViolations++;
        this._onDidChangeTreeData.fire();
    }

    /** Returns a compact kernel summary for the sidebar. */
    getKernelSummary(): {
        activeAgents: number;
        policyViolations: number;
        totalCheckpoints: number;
        uptime: number;
    } {
        return {
            activeAgents: this.kernelState.activeAgents.length,
            policyViolations: this.kernelState.policyViolations,
            totalCheckpoints: this.kernelState.totalCheckpoints,
            uptime: this.kernelState.uptime,
        };
    }
}

export class DebuggerItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string,
        public readonly data?: Record<string, any>
    ) {
        super(label, collapsibleState);
        this.accessibilityInformation = {
            label: DebuggerItem.getAccessibilityLabel(label, data),
            role: 'treeitem'
        };

        // Set icon based on context
        if (data?.icon) {
            this.iconPath = new vscode.ThemeIcon(data.icon.replace('$(', '').replace(')', ''));
        } else {
            switch (contextValue) {
                case 'category':
                    this.iconPath = new vscode.ThemeIcon('folder');
                    break;
                case 'agent':
                    this.iconPath = new vscode.ThemeIcon('person');
                    break;
                case 'info':
                    this.iconPath = new vscode.ThemeIcon('info');
                    break;
                case 'warning':
                    this.iconPath = new vscode.ThemeIcon('warning');
                    break;
                case 'action':
                    this.iconPath = new vscode.ThemeIcon('play');
                    break;
            }
        }

        // Set command if this is an action item
        if (data?.command) {
            this.command = {
                command: data.command,
                title: label,
                arguments: data.agent ? [data.agent] : []
            };
        }
    }

    private static getAccessibilityLabel(label: string, data?: Record<string, any>): string {
        const sanitizedLabel = label
            .replace(/[^\x20-\x7E]+/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();

        if (data?.type === 'agent' && data.agent) {
            return `${data.agent.name}. Status ${data.agent.status}. ${data.agent.currentTask ? `Current task ${data.agent.currentTask}.` : ''}`.trim();
        }

        return sanitizedLabel || 'Debugger item';
    }
}

/**
 * Memory Browser View
 * 
 * Visualizes the Agent VFS (Virtual File System) for debugging agent memory.
 */
export class MemoryBrowserProvider implements vscode.TreeDataProvider<MemoryItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<MemoryItem | undefined | null | void> = 
        new vscode.EventEmitter<MemoryItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<MemoryItem | undefined | null | void> = 
        this._onDidChangeTreeData.event;

    private vfsRoot: VFSNode = {
        name: '/',
        type: 'directory',
        children: [
            {
                name: 'mem',
                type: 'directory',
                children: [
                    { name: 'working', type: 'directory', children: [] },
                    { name: 'episodic', type: 'directory', children: [] },
                    { name: 'semantic', type: 'directory', children: [] }
                ]
            },
            {
                name: 'policy',
                type: 'directory',
                children: [
                    { name: 'rules.yaml', type: 'file', content: '# Active policies' }
                ]
            },
            {
                name: 'proc',
                type: 'directory',
                children: [
                    { name: 'status', type: 'file', content: 'running' }
                ]
            }
        ]
    };

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: MemoryItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: MemoryItem): Thenable<MemoryItem[]> {
        if (!element) {
            // Root level
            return Promise.resolve(
                (this.vfsRoot.children || []).map(node => this.nodeToItem(node, '/'))
            );
        }

        // Get children of this node
        const node = this.findNode(element.path);
        if (node && node.children) {
            return Promise.resolve(
                node.children.map(child => this.nodeToItem(child, element.path))
            );
        }

        return Promise.resolve([]);
    }

    private nodeToItem(node: VFSNode, parentPath: string): MemoryItem {
        const path = `${parentPath}${node.name}${node.type === 'directory' ? '/' : ''}`;
        return new MemoryItem(
            node.name,
            node.type === 'directory' 
                ? vscode.TreeItemCollapsibleState.Collapsed 
                : vscode.TreeItemCollapsibleState.None,
            node.type,
            path,
            node.content
        );
    }

    private findNode(path: string): VFSNode | null {
        const parts = path.split('/').filter(p => p);
        let current: VFSNode = this.vfsRoot;

        for (const part of parts) {
            const child = current.children?.find(c => c.name === part);
            if (!child) {
                return null;
            }
            current = child;
        }

        return current;
    }

    // Write to VFS
    writeFile(path: string, content: string): void {
        const parts = path.split('/').filter(p => p);
        const fileName = parts.pop()!;
        
        let current: VFSNode = this.vfsRoot;
        for (const part of parts) {
            let child = current.children?.find(c => c.name === part);
            if (!child) {
                child = { name: part, type: 'directory', children: [] };
                current.children = current.children || [];
                current.children.push(child);
            }
            current = child;
        }

        const existingFile = current.children?.find(c => c.name === fileName);
        if (existingFile) {
            existingFile.content = content;
        } else {
            current.children = current.children || [];
            current.children.push({ name: fileName, type: 'file', content });
        }

        this._onDidChangeTreeData.fire();
    }

    /** Returns a compact VFS summary for the sidebar. */
    getVfsSummary(): {
        directoryCount: number;
        fileCount: number;
        rootPaths: string[];
    } {
        let dirs = 0;
        let files = 0;
        const rootPaths: string[] = [];

        const walk = (node: VFSNode): void => {
            if (node.type === 'directory') {
                dirs++;
                node.children?.forEach(walk);
            } else {
                files++;
            }
        };

        if (this.vfsRoot.children) {
            for (const child of this.vfsRoot.children) {
                rootPaths.push('/' + child.name);
                walk(child);
            }
        }

        return { directoryCount: dirs, fileCount: files, rootPaths };
    }
}

interface VFSNode {
    name: string;
    type: 'file' | 'directory';
    children?: VFSNode[];
    content?: string;
}

export class MemoryItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly nodeType: 'file' | 'directory',
        public readonly path: string,
        public readonly content?: string
    ) {
        super(label, collapsibleState);

        this.iconPath = nodeType === 'directory' 
            ? new vscode.ThemeIcon('folder')
            : new vscode.ThemeIcon('file');

        this.contextValue = nodeType;
        this.tooltip = path;
        this.accessibilityInformation = {
            label: nodeType === 'directory'
                ? `Directory ${label}. Path ${path}`
                : `File ${label}. Path ${path}`,
            role: 'treeitem'
        };

        if (nodeType === 'file') {
            this.command = {
                command: 'agent-os.viewMemoryFile',
                title: 'View File',
                arguments: [this]
            };
        }
    }
}
