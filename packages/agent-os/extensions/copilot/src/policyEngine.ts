// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Policy Engine for Agent OS Copilot Extension
 * 
 * Shared policy engine - ported from VS Code extension.
 */

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

interface PolicyConfig {
    blockDestructiveSQL: boolean;
    blockFileDeletes: boolean;
    blockSecretExposure: boolean;
    blockPrivilegeEscalation: boolean;
    blockUnsafeNetworkCalls: boolean;
}

export class PolicyEngine {
    private rules: PolicyRule[] = [];
    private allowedOnce: Set<string> = new Set();
    private config: PolicyConfig;

    constructor(config?: Partial<PolicyConfig>) {
        this.config = {
            blockDestructiveSQL: true,
            blockFileDeletes: true,
            blockSecretExposure: true,
            blockPrivilegeEscalation: true,
            blockUnsafeNetworkCalls: false,
            ...config
        };
        this.loadRules();
    }

    private loadRules(): void {
        this.rules = [];

        // Destructive SQL
        if (this.config.blockDestructiveSQL) {
            this.rules.push(
                {
                    name: 'drop_table',
                    pattern: /DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\s+/i,
                    severity: 'critical',
                    message: 'Destructive SQL: DROP operation detected',
                    suggestion: 'Consider using soft delete or archiving instead'
                },
                {
                    name: 'delete_all',
                    pattern: /DELETE\s+FROM\s+\w+\s*(;|$|WHERE\s+1\s*=\s*1)/i,
                    severity: 'critical',
                    message: 'Destructive SQL: DELETE without proper WHERE clause',
                    suggestion: 'Add a specific WHERE clause to limit deletion'
                },
                {
                    name: 'truncate_table',
                    pattern: /TRUNCATE\s+TABLE\s+/i,
                    severity: 'critical',
                    message: 'Destructive SQL: TRUNCATE operation detected',
                    suggestion: 'Consider archiving data before truncating'
                }
            );
        }

        // File deletion
        if (this.config.blockFileDeletes) {
            this.rules.push(
                {
                    name: 'rm_rf',
                    pattern: /rm\s+(-rf|-fr|--recursive\s+--force)\s+/i,
                    severity: 'critical',
                    message: 'Destructive operation: Recursive force delete (rm -rf)',
                    suggestion: 'Use safer alternatives like trash-cli or move to backup'
                },
                {
                    name: 'rm_root',
                    pattern: /rm\s+.*\s+(\/|~|\$HOME)/i,
                    severity: 'critical',
                    message: 'Destructive operation: Deleting from root or home directory'
                },
                {
                    name: 'shutil_rmtree',
                    pattern: /shutil\s*\.\s*rmtree\s*\(/i,
                    severity: 'high',
                    message: 'Recursive directory deletion (shutil.rmtree)',
                    suggestion: 'Consider using send2trash for safer deletion',
                    languages: ['python']
                },
                {
                    name: 'fs_rm_recursive',
                    pattern: /fs\.(rm|rmdir)Sync?\s*\([^)]*recursive\s*:\s*true/i,
                    severity: 'high',
                    message: 'Recursive file deletion operation',
                    languages: ['javascript', 'typescript']
                }
            );
        }

        // Secret exposure
        if (this.config.blockSecretExposure) {
            this.rules.push(
                {
                    name: 'hardcoded_api_key',
                    pattern: /(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["'][a-zA-Z0-9_-]{20,}["']/i,
                    severity: 'critical',
                    message: 'Hardcoded API key detected',
                    suggestion: 'Use environment variables: process.env.API_KEY'
                },
                {
                    name: 'hardcoded_password',
                    pattern: /(password|passwd|pwd)\s*[=:]\s*["'][^"']+["']/i,
                    severity: 'critical',
                    message: 'Hardcoded password detected',
                    suggestion: 'Use environment variables or a secrets manager'
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
                    suggestion: 'Never commit JWT tokens - use environment variables'
                }
            );
        }

        // Privilege escalation
        if (this.config.blockPrivilegeEscalation) {
            this.rules.push(
                {
                    name: 'sudo',
                    pattern: /sudo\s+/i,
                    severity: 'high',
                    message: 'Privilege escalation: sudo command detected',
                    suggestion: 'Avoid sudo in scripts - run with appropriate permissions'
                },
                {
                    name: 'chmod_777',
                    pattern: /chmod\s+777\s+/i,
                    severity: 'high',
                    message: 'Insecure permissions: chmod 777 detected',
                    suggestion: 'Use more restrictive permissions: chmod 755 or chmod 644'
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

        // Unsafe network calls
        if (this.config.blockUnsafeNetworkCalls) {
            this.rules.push(
                {
                    name: 'http_not_https',
                    pattern: /["']http:\/\/(?!localhost|127\.0\.0\.1)/i,
                    severity: 'medium',
                    message: 'Insecure HTTP connection (use HTTPS)',
                    suggestion: 'Use HTTPS for secure connections'
                },
                {
                    name: 'eval_remote',
                    pattern: /eval\s*\(\s*(await\s+)?fetch\s*\(/i,
                    severity: 'critical',
                    message: 'Remote code execution: eval(fetch()) detected'
                }
            );
        }

        // Always-on critical safety rules
        this.rules.push(
            {
                name: 'fork_bomb',
                pattern: /:\s*\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/,
                severity: 'critical',
                message: 'Fork bomb detected - would crash system'
            },
            {
                name: 'dd_disk',
                pattern: /dd\s+if=.*\s+of=\/dev\/(sd[a-z]|nvme|hd[a-z])/i,
                severity: 'critical',
                message: 'Direct disk write operation (dd) - could corrupt disk'
            },
            {
                name: 'format_drive',
                pattern: /format\s+[a-z]:/i,
                severity: 'critical',
                message: 'Drive format command detected'
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
            // Skip if language doesn't match (when specified)
            if (rule.languages && !rule.languages.includes(language)) {
                continue;
            }

            // Skip if allowed once
            if (this.allowedOnce.has(rule.name)) {
                this.allowedOnce.delete(rule.name);
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
     * Set policy enabled/disabled
     */
    setPolicy(policy: string, enabled: boolean): void {
        const policyMap: Record<string, keyof PolicyConfig> = {
            'destructiveSQL': 'blockDestructiveSQL',
            'fileDeletes': 'blockFileDeletes',
            'secretExposure': 'blockSecretExposure',
            'privilegeEscalation': 'blockPrivilegeEscalation',
            'unsafeNetwork': 'blockUnsafeNetworkCalls'
        };

        const configKey = policyMap[policy];
        if (configKey) {
            this.config[configKey] = enabled;
            this.loadRules();
        }
    }

    /**
     * Get active policies
     */
    getActivePolicies(): { name: string; enabled: boolean; severity: string }[] {
        return [
            { name: 'Destructive SQL', enabled: this.config.blockDestructiveSQL, severity: 'critical' },
            { name: 'File Deletes', enabled: this.config.blockFileDeletes, severity: 'critical' },
            { name: 'Secret Exposure', enabled: this.config.blockSecretExposure, severity: 'critical' },
            { name: 'Privilege Escalation', enabled: this.config.blockPrivilegeEscalation, severity: 'high' },
            { name: 'Unsafe Network', enabled: this.config.blockUnsafeNetworkCalls, severity: 'medium' }
        ];
    }

    /**
     * Get total rule count
     */
    getRuleCount(): number {
        return this.rules.length;
    }
}
