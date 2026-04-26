// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Role-Based Access Control (RBAC) Manager
 * 
 * Manages permissions and access control for enterprise deployments
 * with granular role-based policies.
 */

import * as vscode from 'vscode';
import { EnterpriseAuthProvider } from './ssoProvider';

export interface Permission {
    id: string;
    name: string;
    description: string;
    resource: string;
    actions: ('create' | 'read' | 'update' | 'delete' | 'execute')[];
}

export interface Role {
    id: string;
    name: string;
    description: string;
    permissions: string[];
    inherits?: string[];
}

export interface AccessPolicy {
    id: string;
    name: string;
    roles: string[];
    resources: string[];
    conditions?: {
        timeOfDay?: { start: string; end: string };
        ipRanges?: string[];
        mfaRequired?: boolean;
    };
}

export class RBACManager {
    private _authProvider: EnterpriseAuthProvider;
    private _roles: Map<string, Role> = new Map();
    private _permissions: Map<string, Permission> = new Map();
    private _policies: Map<string, AccessPolicy> = new Map();

    constructor(authProvider: EnterpriseAuthProvider) {
        this._authProvider = authProvider;
        this._initializeDefaultRoles();
        this._initializeDefaultPermissions();
    }

    private _initializeDefaultRoles(): void {
        const roles: Role[] = [
            {
                id: 'viewer',
                name: 'Viewer',
                description: 'Can view policies and audit logs',
                permissions: ['policy.read', 'audit.read', 'metrics.read']
            },
            {
                id: 'developer',
                name: 'Developer',
                description: 'Can create and test agents',
                permissions: [
                    'policy.read',
                    'agent.create',
                    'agent.read',
                    'agent.execute',
                    'workflow.create',
                    'workflow.read',
                    'workflow.execute',
                    'audit.read'
                ],
                inherits: ['viewer']
            },
            {
                id: 'policy_admin',
                name: 'Policy Administrator',
                description: 'Can manage policies',
                permissions: [
                    'policy.create',
                    'policy.read',
                    'policy.update',
                    'policy.delete',
                    'policy.deploy'
                ],
                inherits: ['developer']
            },
            {
                id: 'security_officer',
                name: 'Security Officer',
                description: 'Full access to security features',
                permissions: [
                    'policy.create',
                    'policy.read',
                    'policy.update',
                    'policy.delete',
                    'policy.deploy',
                    'policy.approve',
                    'audit.read',
                    'audit.export',
                    'compliance.read',
                    'compliance.report'
                ],
                inherits: ['policy_admin']
            },
            {
                id: 'admin',
                name: 'Administrator',
                description: 'Full administrative access',
                permissions: ['*'],
                inherits: ['security_officer']
            }
        ];

        roles.forEach(role => this._roles.set(role.id, role));
    }

    private _initializeDefaultPermissions(): void {
        const permissions: Permission[] = [
            // Policy permissions
            { id: 'policy.create', name: 'Create Policy', description: 'Create new policies', resource: 'policy', actions: ['create'] },
            { id: 'policy.read', name: 'Read Policy', description: 'View policies', resource: 'policy', actions: ['read'] },
            { id: 'policy.update', name: 'Update Policy', description: 'Modify policies', resource: 'policy', actions: ['update'] },
            { id: 'policy.delete', name: 'Delete Policy', description: 'Remove policies', resource: 'policy', actions: ['delete'] },
            { id: 'policy.deploy', name: 'Deploy Policy', description: 'Deploy policies to production', resource: 'policy', actions: ['execute'] },
            { id: 'policy.approve', name: 'Approve Policy', description: 'Approve policy changes', resource: 'policy', actions: ['execute'] },

            // Agent permissions
            { id: 'agent.create', name: 'Create Agent', description: 'Create new agents', resource: 'agent', actions: ['create'] },
            { id: 'agent.read', name: 'Read Agent', description: 'View agents', resource: 'agent', actions: ['read'] },
            { id: 'agent.update', name: 'Update Agent', description: 'Modify agents', resource: 'agent', actions: ['update'] },
            { id: 'agent.delete', name: 'Delete Agent', description: 'Remove agents', resource: 'agent', actions: ['delete'] },
            { id: 'agent.execute', name: 'Execute Agent', description: 'Run agents', resource: 'agent', actions: ['execute'] },

            // Workflow permissions
            { id: 'workflow.create', name: 'Create Workflow', description: 'Create workflows', resource: 'workflow', actions: ['create'] },
            { id: 'workflow.read', name: 'Read Workflow', description: 'View workflows', resource: 'workflow', actions: ['read'] },
            { id: 'workflow.update', name: 'Update Workflow', description: 'Modify workflows', resource: 'workflow', actions: ['update'] },
            { id: 'workflow.delete', name: 'Delete Workflow', description: 'Remove workflows', resource: 'workflow', actions: ['delete'] },
            { id: 'workflow.execute', name: 'Execute Workflow', description: 'Run workflows', resource: 'workflow', actions: ['execute'] },

            // Audit permissions
            { id: 'audit.read', name: 'Read Audit Log', description: 'View audit logs', resource: 'audit', actions: ['read'] },
            { id: 'audit.export', name: 'Export Audit Log', description: 'Export audit logs', resource: 'audit', actions: ['read'] },

            // Metrics permissions
            { id: 'metrics.read', name: 'Read Metrics', description: 'View metrics', resource: 'metrics', actions: ['read'] },

            // Compliance permissions
            { id: 'compliance.read', name: 'Read Compliance', description: 'View compliance status', resource: 'compliance', actions: ['read'] },
            { id: 'compliance.report', name: 'Generate Compliance Report', description: 'Create compliance reports', resource: 'compliance', actions: ['execute'] }
        ];

        permissions.forEach(perm => this._permissions.set(perm.id, perm));
    }

    getRole(roleId: string): Role | undefined {
        return this._roles.get(roleId);
    }

    getAllRoles(): Role[] {
        return Array.from(this._roles.values());
    }

    getPermission(permissionId: string): Permission | undefined {
        return this._permissions.get(permissionId);
    }

    getAllPermissions(): Permission[] {
        return Array.from(this._permissions.values());
    }

    hasPermission(permissionId: string): boolean {
        const user = this._authProvider.currentUser;
        if (!user) return false;

        // Check all user roles
        for (const roleName of user.roles) {
            if (this._roleHasPermission(roleName, permissionId)) {
                return true;
            }
        }

        return false;
    }

    private _roleHasPermission(roleId: string, permissionId: string): boolean {
        const role = this._roles.get(roleId);
        if (!role) return false;

        // Check wildcard permission
        if (role.permissions.includes('*')) return true;

        // Check direct permission
        if (role.permissions.includes(permissionId)) return true;

        // Check inherited roles
        if (role.inherits) {
            for (const inheritedRole of role.inherits) {
                if (this._roleHasPermission(inheritedRole, permissionId)) {
                    return true;
                }
            }
        }

        return false;
    }

    requirePermission(permissionId: string): boolean {
        if (!this._authProvider.isAuthenticated) {
            vscode.window.showWarningMessage(
                'This action requires authentication.',
                'Sign In'
            ).then(selection => {
                if (selection === 'Sign In') {
                    this._authProvider.signIn();
                }
            });
            return false;
        }

        if (!this.hasPermission(permissionId)) {
            const permission = this._permissions.get(permissionId);
            vscode.window.showWarningMessage(
                `You don't have permission: ${permission?.name || permissionId}`
            );
            return false;
        }

        return true;
    }

    canAccess(resource: string, action: 'create' | 'read' | 'update' | 'delete' | 'execute'): boolean {
        const permissionId = `${resource}.${action === 'execute' ? 'execute' : action}`;
        return this.hasPermission(permissionId);
    }

    addCustomRole(role: Role): void {
        this._roles.set(role.id, role);
    }

    addCustomPermission(permission: Permission): void {
        this._permissions.set(permission.id, permission);
    }

    getUserPermissions(): Permission[] {
        const user = this._authProvider.currentUser;
        if (!user) return [];

        const permissionIds = new Set<string>();
        
        for (const roleName of user.roles) {
            this._collectRolePermissions(roleName, permissionIds);
        }

        return Array.from(permissionIds)
            .map(id => this._permissions.get(id))
            .filter((p): p is Permission => p !== undefined);
    }

    private _collectRolePermissions(roleId: string, collected: Set<string>): void {
        const role = this._roles.get(roleId);
        if (!role) return;

        if (role.permissions.includes('*')) {
            this._permissions.forEach((_, id) => collected.add(id));
            return;
        }

        role.permissions.forEach(p => collected.add(p));

        if (role.inherits) {
            role.inherits.forEach(inherited => this._collectRolePermissions(inherited, collected));
        }
    }
}

/**
 * Permission decorator for commands
 */
export function requiresPermission(rbac: RBACManager, permissionId: string) {
    return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
        const originalMethod = descriptor.value;
        
        descriptor.value = async function (...args: any[]) {
            if (rbac.requirePermission(permissionId)) {
                return originalMethod.apply(this, args);
            }
            return undefined;
        };
        
        return descriptor;
    };
}
