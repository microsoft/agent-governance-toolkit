// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Policy Engine for Agent OS VS Code Extension
 * 
 * Provides local-first code safety analysis.
 * Runs entirely in the extension without network calls.
 */

import * as vscode from 'vscode';

function safeRegExp(pattern: string, flags?: string): RegExp | null {
    // Reject patterns with known ReDoS constructs
    const redosPatterns = /(\+\+|\*\+|\+\*|\{\d+,\}\+|(\.\*){2}|\(\?:.*\)\+\$)/;
    if (redosPatterns.test(pattern)) {
        return null;
    }
    try {
        return new RegExp(pattern, flags || 'i');
    } catch {
        return null;
    }
}

export interface PolicyViolation {
    blocked: boolean;
    reason: string;
    violation: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    suggestion?: string;
    lineNumber?: number;
}

export interface AnalysisResult {
    blocked: boolean;
    reason: string;
    violation: string;
    warnings: string[];
    suggestion?: string;
}

interface PolicyRule {
    name: string;
    pattern: RegExp;
    severity: 'critical' | 'high' | 'medium' | 'low';
    message: string;
    suggestion?: string;
    languages?: string[];
}

export class PolicyEngine {
    private allowedOnce: Set<string> = new Set();
    private rules: PolicyRule[] = [];

    constructor() {
        this.loadPolicies();
    }

    /**
     * Load policies from configuration
     */
    loadPolicies(): void {
        const config = vscode.workspace.getConfiguration('agentOS');
        this.rules = [];

        // Destructive SQL
        if (config.get<boolean>('policies.blockDestructiveSQL', true)) {
            this.rules.push(
                {
                    name: 'drop_table',
                    pattern: /DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\s+/i,
                    severity: 'critical',
                    message: 'Destructive SQL: DROP operation detected',
                    suggestion: '-- Consider using soft delete or archiving instead',
                    languages: ['sql', 'javascript', 'typescript', 'python', 'php', 'ruby', 'java', 'csharp']
                },
                {
                    name: 'delete_all',
                    pattern: /DELETE\s+FROM\s+\w+\s*(;|$|WHERE\s+1\s*=\s*1)/i,
                    severity: 'critical',
                    message: 'Destructive SQL: DELETE without proper WHERE clause',
                    suggestion: '-- Add a specific WHERE clause to limit deletion',
                    languages: ['sql', 'javascript', 'typescript', 'python', 'php', 'ruby', 'java', 'csharp']
                },
                {
                    name: 'truncate_table',
                    pattern: /TRUNCATE\s+TABLE\s+/i,
                    severity: 'critical',
                    message: 'Destructive SQL: TRUNCATE operation detected',
                    suggestion: '-- Consider archiving data before truncating',
                    languages: ['sql', 'javascript', 'typescript', 'python', 'php', 'ruby', 'java', 'csharp']
                }
            );
        }

        // File deletion
        if (config.get<boolean>('policies.blockFileDeletes', true)) {
            this.rules.push(
                {
                    name: 'rm_rf',
                    pattern: /rm\s+(-rf|-fr|--recursive\s+--force)\s+/i,
                    severity: 'critical',
                    message: 'Destructive operation: Recursive force delete (rm -rf)',
                    suggestion: '# Use safer alternatives like trash-cli or move to backup',
                    languages: ['shellscript', 'bash', 'sh', 'zsh']
                },
                {
                    name: 'rm_root',
                    pattern: /rm\s+.*\s+(\/|~|\$HOME|\$\{HOME\})/i,
                    severity: 'critical',
                    message: 'Destructive operation: Deleting from root or home directory',
                    languages: ['shellscript', 'bash', 'sh', 'zsh']
                },
                {
                    name: 'unlink_recursive',
                    pattern: /\.(unlink|rmdir|remove)Sync?\s*\(\s*['"]/i,
                    severity: 'high',
                    message: 'File deletion operation detected',
                    suggestion: '// Consider moving to a backup location first',
                    languages: ['javascript', 'typescript']
                },
                {
                    name: 'shutil_rmtree',
                    pattern: /shutil\s*\.\s*rmtree\s*\(/i,
                    severity: 'high',
                    message: 'Recursive directory deletion (shutil.rmtree)',
                    suggestion: '# Consider using send2trash for safer deletion',
                    languages: ['python']
                },
                {
                    name: 'os_remove',
                    pattern: /os\s*\.\s*(remove|unlink|rmdir)\s*\(/i,
                    severity: 'medium',
                    message: 'File/directory deletion operation detected',
                    languages: ['python']
                }
            );
        }

        // Secret exposure
        if (config.get<boolean>('policies.blockSecretExposure', true)) {
            this.rules.push(
                {
                    name: 'hardcoded_api_key',
                    pattern: /(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["'][a-zA-Z0-9_-]{20,}["']/i,
                    severity: 'critical',
                    message: 'Hardcoded API key detected',
                    suggestion: '// Use environment variables: process.env.API_KEY'
                },
                {
                    name: 'hardcoded_password',
                    pattern: /(password|passwd|pwd)\s*[=:]\s*["'][^"']+["']/i,
                    severity: 'critical',
                    message: 'Hardcoded password detected',
                    suggestion: '// Use environment variables or a secrets manager'
                },
                {
                    name: 'aws_key',
                    pattern: /AKIA[0-9A-Z]{16}/,
                    severity: 'critical',
                    message: 'AWS Access Key ID detected in code'
                },
                {
                    name: 'private_key',
                    pattern: /-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----/,
                    severity: 'critical',
                    message: 'Private key detected in code'
                },
                {
                    name: 'github_token',
                    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/,
                    severity: 'critical',
                    message: 'GitHub token detected in code'
                },
                {
                    name: 'jwt_token',
                    pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,
                    severity: 'high',
                    message: 'JWT token detected in code',
                    suggestion: '// Never commit JWT tokens - use environment variables'
                }
            );
        }

        // Privilege escalation
        if (config.get<boolean>('policies.blockPrivilegeEscalation', true)) {
            this.rules.push(
                {
                    name: 'sudo',
                    pattern: /sudo\s+/i,
                    severity: 'high',
                    message: 'Privilege escalation: sudo command detected',
                    suggestion: '# Avoid sudo in scripts - run with appropriate permissions',
                    languages: ['shellscript', 'bash', 'sh', 'zsh']
                },
                {
                    name: 'chmod_777',
                    pattern: /chmod\s+777\s+/i,
                    severity: 'high',
                    message: 'Insecure permissions: chmod 777 detected',
                    suggestion: '# Use more restrictive permissions: chmod 755 or chmod 644',
                    languages: ['shellscript', 'bash', 'sh', 'zsh']
                },
                {
                    name: 'chown_root',
                    pattern: /chown\s+root/i,
                    severity: 'medium',
                    message: 'Ownership change to root detected',
                    languages: ['shellscript', 'bash', 'sh', 'zsh']
                },
                {
                    name: 'setuid',
                    pattern: /os\s*\.\s*set(e)?uid\s*\(\s*0\s*\)/i,
                    severity: 'critical',
                    message: 'Setting UID to root (0) detected',
                    languages: ['python']
                }
            );
        }

        // Unsafe network calls (optional)
        if (config.get<boolean>('policies.blockUnsafeNetworkCalls', false)) {
            this.rules.push(
                {
                    name: 'http_not_https',
                    pattern: /["']http:\/\/(?!localhost|127\.0\.0\.1)/i,
                    severity: 'medium',
                    message: 'Insecure HTTP connection (use HTTPS)',
                    suggestion: '// Use HTTPS for secure connections'
                },
                {
                    name: 'eval_remote',
                    pattern: /eval\s*\(\s*(await\s+)?fetch\s*\(/i,
                    severity: 'critical',
                    message: 'Remote code execution: eval(fetch()) detected'
                }
            );
        }

        // Always-on safety rules (cannot be disabled)
        this.rules.push(
            {
                name: 'format_c',
                pattern: /format\s+c:/i,
                severity: 'critical',
                message: 'System destructive operation: format C: drive',
                languages: ['bat', 'cmd', 'powershell']
            },
            {
                name: 'fork_bomb',
                pattern: /:\s*\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/,
                severity: 'critical',
                message: 'Fork bomb detected - would crash system',
                languages: ['shellscript', 'bash', 'sh', 'zsh']
            },
            {
                name: 'dd_disk',
                pattern: /dd\s+if=.*\s+of=\/dev\/(sd[a-z]|nvme|hd[a-z])/i,
                severity: 'critical',
                message: 'Direct disk write operation (dd) - could corrupt disk',
                languages: ['shellscript', 'bash', 'sh', 'zsh']
            }
        );

        // Load custom rules from workspace config
        this.loadCustomRules();
    }

    /**
     * Load custom rules from .vscode/agent-os.json
     */
    private loadCustomRules(): void {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) return;

        const configPath = vscode.Uri.joinPath(workspaceFolder.uri, '.vscode', 'agent-os.json');
        
        vscode.workspace.fs.readFile(configPath).then(
            (content) => {
                try {
                    const config = JSON.parse(content.toString());
                    if (config.customRules && Array.isArray(config.customRules)) {
                        for (const rule of config.customRules) {
                            if (rule.pattern && rule.message) {
                                const compiledPattern = safeRegExp(rule.pattern, rule.flags);
                                if (!compiledPattern) {
                                    console.warn(`Skipping rule "${rule.name || 'custom_rule'}": unsafe or invalid regex pattern`);
                                    continue;
                                }
                                this.rules.push({
                                    name: rule.name || 'custom_rule',
                                    pattern: compiledPattern,
                                    severity: rule.severity || 'medium',
                                    message: rule.message,
                                    suggestion: rule.suggestion,
                                    languages: rule.languages
                                });
                            }
                        }
                    }
                } catch (e) {
                    console.error('Failed to parse agent-os.json:', e);
                }
            },
            () => {
                // File doesn't exist, ignore
            }
        );
    }

    /**
     * Analyze code for policy violations
     */
    async analyzeCode(code: string, language: string): Promise<AnalysisResult> {
        const warnings: string[] = [];
        let blocked = false;
        let blockReason = '';
        let blockViolation = '';
        let suggestion: string | undefined;

        for (const rule of this.rules) {
            // Skip if language doesn't match
            if (rule.languages && !rule.languages.includes(language)) {
                continue;
            }

            // Skip if allowed once
            if (this.allowedOnce.has(rule.name)) {
                this.allowedOnce.delete(rule.name);  // Remove after one use
                continue;
            }

            if (rule.pattern.test(code)) {
                if (rule.severity === 'critical' || rule.severity === 'high') {
                    blocked = true;
                    blockReason = rule.message;
                    blockViolation = rule.name;
                    suggestion = rule.suggestion;
                } else {
                    warnings.push(rule.message);
                }
            }
        }

        return {
            blocked,
            reason: blockReason,
            violation: blockViolation,
            warnings,
            suggestion
        };
    }

    /**
     * Allow a specific violation once
     */
    allowOnce(violation: string): void {
        this.allowedOnce.add(violation);
    }

    /**
     * Get all active policies for display
     */
    getActivePolicies(): { name: string; enabled: boolean; severity: string }[] {
        const config = vscode.workspace.getConfiguration('agentOS');
        
        return [
            { name: 'Destructive SQL', enabled: config.get('policies.blockDestructiveSQL', true), severity: 'critical' },
            { name: 'File Deletes', enabled: config.get('policies.blockFileDeletes', true), severity: 'critical' },
            { name: 'Secret Exposure', enabled: config.get('policies.blockSecretExposure', true), severity: 'critical' },
            { name: 'Privilege Escalation', enabled: config.get('policies.blockPrivilegeEscalation', true), severity: 'high' },
            { name: 'Unsafe Network', enabled: config.get('policies.blockUnsafeNetworkCalls', false), severity: 'medium' }
        ];
    }

    /**
     * Get rule count
     */
    getRuleCount(): number {
        return this.rules.length;
    }
}
