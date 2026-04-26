// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Completion Provider for Agent OS
 * 
 * Provides context-aware code completion for AgentOS APIs and policy files.
 */

import * as vscode from 'vscode';

interface CompletionItem {
    label: string;
    kind: vscode.CompletionItemKind;
    detail: string;
    documentation: string;
    insertText: string;
    sortText?: string;
}

export class AgentOSCompletionProvider implements vscode.CompletionItemProvider {
    
    private readonly policyKeywords: CompletionItem[] = [
        {
            label: 'kernel',
            kind: vscode.CompletionItemKind.Module,
            detail: 'Kernel configuration section',
            documentation: 'Defines the kernel version, mode, and template for the policy.',
            insertText: 'kernel:\n  version: "1.0"\n  mode: ${1|strict,permissive,audit|}\n'
        },
        {
            label: 'policies',
            kind: vscode.CompletionItemKind.Module,
            detail: 'Policies section',
            documentation: 'Defines the list of policy rules to enforce.',
            insertText: 'policies:\n  - name: ${1:policy_name}\n    severity: ${2|critical,high,medium,low|}\n    ${3}'
        },
        {
            label: 'signals',
            kind: vscode.CompletionItemKind.Module,
            detail: 'Allowed signals section',
            documentation: 'Defines which POSIX-style signals the kernel can send.',
            insertText: 'signals:\n  - SIGSTOP\n  - SIGKILL\n  - SIGCONT\n'
        },
        {
            label: 'observability',
            kind: vscode.CompletionItemKind.Module,
            detail: 'Observability configuration',
            documentation: 'Configure metrics, traces, and flight recorder.',
            insertText: 'observability:\n  metrics: true\n  traces: true\n  flight_recorder: true\n'
        },
        {
            label: 'audit',
            kind: vscode.CompletionItemKind.Module,
            detail: 'Audit logging configuration',
            documentation: 'Configure audit logging and export destinations.',
            insertText: 'audit:\n  enabled: true\n  format: json\n  retention_days: ${1:365}\n'
        }
    ];

    private readonly policyRuleKeywords: CompletionItem[] = [
        {
            label: 'deny',
            kind: vscode.CompletionItemKind.Keyword,
            detail: 'Deny rule',
            documentation: 'Specifies actions or patterns to block.',
            insertText: 'deny:\n  - action: ${1:action_name}\n    ${2}'
        },
        {
            label: 'allow',
            kind: vscode.CompletionItemKind.Keyword,
            detail: 'Allow rule',
            documentation: 'Specifies actions or patterns to explicitly allow.',
            insertText: 'allow:\n  - action: ${1:action_name}\n    ${2}'
        },
        {
            label: 'action',
            kind: vscode.CompletionItemKind.Keyword,
            detail: 'Signal action',
            documentation: 'The signal to send when this rule is triggered.',
            insertText: 'action: ${1|SIGKILL,SIGSTOP,SIGCONT,SIGTERM|}'
        },
        {
            label: 'severity',
            kind: vscode.CompletionItemKind.Property,
            detail: 'Rule severity level',
            documentation: 'The severity level of this policy rule.',
            insertText: 'severity: ${1|critical,high,medium,low|}'
        },
        {
            label: 'patterns',
            kind: vscode.CompletionItemKind.Property,
            detail: 'Regex patterns to match',
            documentation: 'List of regular expression patterns to detect violations.',
            insertText: 'patterns:\n  - \'${1:pattern}\'\n'
        },
        {
            label: 'limits',
            kind: vscode.CompletionItemKind.Property,
            detail: 'Rate limits',
            documentation: 'Define rate limits for actions.',
            insertText: 'limits:\n  - action: ${1:action_name}\n    max_per_minute: ${2:60}\n'
        }
    ];

    private readonly pythonAPICompletions: CompletionItem[] = [
        {
            label: 'KernelSpace',
            kind: vscode.CompletionItemKind.Class,
            detail: 'Agent OS Kernel Space',
            documentation: 'Creates a kernel space for governing agent execution with policy enforcement.',
            insertText: 'KernelSpace(policy="${1|strict,permissive,audit|}")'
        },
        {
            label: 'kernel.register',
            kind: vscode.CompletionItemKind.Method,
            detail: 'Register agent with kernel',
            documentation: 'Decorator to register an agent function with the kernel.',
            insertText: '@kernel.register\nasync def ${1:agent_name}(task: str):\n    ${2:pass}'
        },
        {
            label: 'kernel.execute',
            kind: vscode.CompletionItemKind.Method,
            detail: 'Execute agent with safety',
            documentation: 'Execute an agent function with full policy enforcement.',
            insertText: 'await kernel.execute(${1:agent_func}, ${2:task})'
        },
        {
            label: 'SignalDispatcher',
            kind: vscode.CompletionItemKind.Class,
            detail: 'Signal dispatcher',
            documentation: 'Manages POSIX-style signals for agent control.',
            insertText: 'SignalDispatcher()'
        },
        {
            label: 'AgentSignal',
            kind: vscode.CompletionItemKind.Enum,
            detail: 'Agent signal types',
            documentation: 'POSIX-inspired signals for agent control.',
            insertText: 'AgentSignal.${1|SIGKILL,SIGSTOP,SIGCONT,SIGTERM,SIGINT|}'
        },
        {
            label: 'AgentVFS',
            kind: vscode.CompletionItemKind.Class,
            detail: 'Agent Virtual File System',
            documentation: 'Provides a virtual file system for agent memory and state.',
            insertText: 'AgentVFS(agent_id="${1:agent_id}")'
        },
        {
            label: 'Policy.load',
            kind: vscode.CompletionItemKind.Method,
            detail: 'Load policy from file',
            documentation: 'Load a policy configuration from a YAML or JSON file.',
            insertText: 'Policy.load("${1:policy.yaml}")'
        },
        {
            label: 'create_safe_toolkit',
            kind: vscode.CompletionItemKind.Function,
            detail: 'Create safe tool toolkit',
            documentation: 'Creates a set of safe, rate-limited tools for agents.',
            insertText: 'create_safe_toolkit("${1|standard,minimal,extended|}")'
        }
    ];

    private readonly typescriptAPICompletions: CompletionItem[] = [
        {
            label: 'AgentOS',
            kind: vscode.CompletionItemKind.Class,
            detail: 'AgentOS SDK',
            documentation: 'Main entry point for the AgentOS TypeScript SDK.',
            insertText: 'const agentOS = new AgentOS({\n  policy: "${1|strict,permissive|}",\n  apiKey: process.env.AGENT_OS_KEY\n});'
        },
        {
            label: 'agentOS.execute',
            kind: vscode.CompletionItemKind.Method,
            detail: 'Execute with safety',
            documentation: 'Execute a function with full AgentOS policy enforcement.',
            insertText: 'await agentOS.execute(async () => {\n  ${1}\n});'
        },
        {
            label: 'agentOS.checkPolicy',
            kind: vscode.CompletionItemKind.Method,
            detail: 'Check policy compliance',
            documentation: 'Check if an action would be allowed by the current policy.',
            insertText: 'const result = await agentOS.checkPolicy({\n  action: "${1:action}",\n  params: ${2:{}}\n});'
        },
        {
            label: 'PolicyEngine',
            kind: vscode.CompletionItemKind.Class,
            detail: 'Local policy engine',
            documentation: 'Local-first policy engine for offline validation.',
            insertText: 'const engine = new PolicyEngine();\nconst result = engine.validate(${1:code});'
        }
    ];

    private readonly actionTypes: string[] = [
        'database_query',
        'database_write',
        'file_read',
        'file_write',
        'file_delete',
        'http_request',
        'api_call',
        'code_execution',
        'send_email',
        'llm_call',
        'cmvk_review',
        'shell_exec'
    ];

    provideCompletionItems(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken,
        context: vscode.CompletionContext
    ): vscode.ProviderResult<vscode.CompletionItem[] | vscode.CompletionList> {
        const linePrefix = document.lineAt(position).text.substring(0, position.character);
        const language = document.languageId;

        // Policy file completions (YAML/JSON)
        if (language === 'yaml' || language === 'json') {
            return this.getPolicyCompletions(document, position, linePrefix);
        }

        // Python completions
        if (language === 'python') {
            return this.getPythonCompletions(document, position, linePrefix);
        }

        // TypeScript/JavaScript completions
        if (language === 'typescript' || language === 'javascript') {
            return this.getTypeScriptCompletions(document, position, linePrefix);
        }

        return [];
    }

    private getPolicyCompletions(
        document: vscode.TextDocument,
        position: vscode.Position,
        linePrefix: string
    ): vscode.CompletionItem[] {
        const items: vscode.CompletionItem[] = [];
        const indent = linePrefix.match(/^\s*/)?.[0].length || 0;

        // Top-level completions
        if (indent === 0) {
            for (const kw of this.policyKeywords) {
                const item = new vscode.CompletionItem(kw.label, kw.kind);
                item.detail = kw.detail;
                item.documentation = new vscode.MarkdownString(kw.documentation);
                item.insertText = new vscode.SnippetString(kw.insertText);
                item.sortText = '0' + kw.label;
                items.push(item);
            }
        }

        // Rule-level completions
        if (indent >= 2) {
            for (const kw of this.policyRuleKeywords) {
                const item = new vscode.CompletionItem(kw.label, kw.kind);
                item.detail = kw.detail;
                item.documentation = new vscode.MarkdownString(kw.documentation);
                item.insertText = new vscode.SnippetString(kw.insertText);
                items.push(item);
            }
        }

        // Action type completions
        if (linePrefix.includes('action:') && !linePrefix.includes('[')) {
            for (const action of this.actionTypes) {
                const item = new vscode.CompletionItem(action, vscode.CompletionItemKind.EnumMember);
                item.detail = 'Action type';
                item.documentation = new vscode.MarkdownString(`Action type: \`${action}\``);
                items.push(item);
            }
        }

        return items;
    }

    private getPythonCompletions(
        document: vscode.TextDocument,
        position: vscode.Position,
        linePrefix: string
    ): vscode.CompletionItem[] {
        const items: vscode.CompletionItem[] = [];
        const text = document.getText();

        // Check if agent_os is imported
        if (!text.includes('from agent_os') && !text.includes('import agent_os')) {
            return items;
        }

        for (const api of this.pythonAPICompletions) {
            const item = new vscode.CompletionItem(api.label, api.kind);
            item.detail = api.detail;
            item.documentation = new vscode.MarkdownString(api.documentation);
            item.insertText = new vscode.SnippetString(api.insertText);
            items.push(item);
        }

        // Add import suggestion
        if (linePrefix.trim().startsWith('from ')) {
            const importItem = new vscode.CompletionItem('agent_os', vscode.CompletionItemKind.Module);
            importItem.detail = 'Import AgentOS';
            importItem.documentation = new vscode.MarkdownString('Import the AgentOS kernel and safety primitives.');
            importItem.insertText = new vscode.SnippetString('agent_os import ${1|KernelSpace,Policy,AgentSignal,AgentVFS|}');
            items.push(importItem);
        }

        return items;
    }

    private getTypeScriptCompletions(
        document: vscode.TextDocument,
        position: vscode.Position,
        linePrefix: string
    ): vscode.CompletionItem[] {
        const items: vscode.CompletionItem[] = [];

        for (const api of this.typescriptAPICompletions) {
            const item = new vscode.CompletionItem(api.label, api.kind);
            item.detail = api.detail;
            item.documentation = new vscode.MarkdownString(api.documentation);
            item.insertText = new vscode.SnippetString(api.insertText);
            items.push(item);
        }

        // Add import suggestion
        if (linePrefix.trim().startsWith('import ')) {
            const importItem = new vscode.CompletionItem('@agent-os/sdk', vscode.CompletionItemKind.Module);
            importItem.detail = 'Import AgentOS SDK';
            importItem.documentation = new vscode.MarkdownString('Import the AgentOS TypeScript SDK.');
            importItem.insertText = new vscode.SnippetString('{ AgentOS, PolicyEngine } from \'@agent-os/sdk\'');
            items.push(importItem);
        }

        return items;
    }

    resolveCompletionItem(
        item: vscode.CompletionItem,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<vscode.CompletionItem> {
        return item;
    }
}

export class AgentOSHoverProvider implements vscode.HoverProvider {
    
    private readonly hoverInfo: Map<string, { title: string; description: string; example?: string }> = new Map([
        ['SIGKILL', {
            title: 'SIGKILL Signal',
            description: 'Immediately terminate the agent. Cannot be caught or ignored.',
            example: 'Used for critical policy violations that require immediate termination.'
        }],
        ['SIGSTOP', {
            title: 'SIGSTOP Signal',
            description: 'Pause agent execution for review. Cannot be caught or ignored.',
            example: 'Used to pause an agent for human review before continuing.'
        }],
        ['SIGCONT', {
            title: 'SIGCONT Signal',
            description: 'Resume a paused agent.',
            example: 'Sent after human approval to continue execution.'
        }],
        ['KernelSpace', {
            title: 'KernelSpace',
            description: 'The core AgentOS kernel that provides policy enforcement and safety guarantees.',
            example: '```python\nfrom agent_os import KernelSpace\nkernel = KernelSpace(policy="strict")\n```'
        }],
        ['strict', {
            title: 'Strict Mode',
            description: 'Policy violations trigger SIGKILL - the agent is immediately terminated.',
            example: 'Recommended for production environments.'
        }],
        ['permissive', {
            title: 'Permissive Mode',
            description: 'Policy violations are logged but allowed to proceed.',
            example: 'Useful for development and testing.'
        }],
        ['audit', {
            title: 'Audit Mode',
            description: 'All actions are logged with no enforcement.',
            example: 'Useful for understanding agent behavior before enabling enforcement.'
        }]
    ]);

    provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<vscode.Hover> {
        const wordRange = document.getWordRangeAtPosition(position);
        if (!wordRange) {
            return null;
        }

        const word = document.getText(wordRange);
        const info = this.hoverInfo.get(word);

        if (info) {
            const markdown = new vscode.MarkdownString();
            markdown.appendMarkdown(`**${info.title}**\n\n`);
            markdown.appendMarkdown(info.description);
            if (info.example) {
                markdown.appendMarkdown(`\n\n${info.example}`);
            }
            return new vscode.Hover(markdown, wordRange);
        }

        return null;
    }
}
