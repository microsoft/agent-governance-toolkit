// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Enterprise Authentication Module
 * 
 * Provides SSO integration (SAML, OAuth, OIDC) and authentication
 * management for enterprise deployments.
 */

import * as vscode from 'vscode';

export interface SSOProvider {
    type: 'saml' | 'oauth' | 'oidc';
    name: string;
    clientId?: string;
    tenantId?: string;
    authorizationUrl?: string;
    tokenUrl?: string;
    scopes?: string[];
}

export interface AuthenticatedUser {
    id: string;
    email: string;
    name: string;
    roles: string[];
    organization?: string;
    groups?: string[];
    token?: string;
    expiresAt?: Date;
}

export interface AuthState {
    isAuthenticated: boolean;
    user?: AuthenticatedUser;
    provider?: SSOProvider;
}

export class EnterpriseAuthProvider {
    private _state: AuthState = { isAuthenticated: false };
    private _onAuthStateChanged = new vscode.EventEmitter<AuthState>();
    readonly onAuthStateChanged = this._onAuthStateChanged.event;
    
    private _context: vscode.ExtensionContext;
    private _providers: Map<string, SSOProvider> = new Map();

    constructor(context: vscode.ExtensionContext) {
        this._context = context;
        this._loadState();
        this._registerProviders();
    }

    private async _loadState(): Promise<void> {
        const savedState = this._context.globalState.get<AuthState>('agent-os.authState');
        if (savedState) {
            this._state = savedState;
            // Check if token expired
            if (this._state.user?.expiresAt && new Date(this._state.user.expiresAt) < new Date()) {
                this._state = { isAuthenticated: false };
            }
        }
        // Restore token from SecretStorage
        if (this._state?.user) {
            const token = await this._context.secrets.get('agent-os.authToken');
            if (token) {
                this._state.user.token = token;
            }
        }
    }

    private _registerProviders(): void {
        // Azure AD / Entra ID
        this._providers.set('azure', {
            type: 'oidc',
            name: 'Microsoft Entra ID',
            clientId: '',
            authorizationUrl: 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize',
            tokenUrl: 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
            scopes: ['openid', 'profile', 'email']
        });

        // Okta
        this._providers.set('okta', {
            type: 'oidc',
            name: 'Okta',
            clientId: '',
            authorizationUrl: 'https://{domain}.okta.com/oauth2/v1/authorize',
            tokenUrl: 'https://{domain}.okta.com/oauth2/v1/token',
            scopes: ['openid', 'profile', 'email', 'groups']
        });

        // Google Workspace
        this._providers.set('google', {
            type: 'oauth',
            name: 'Google Workspace',
            clientId: '',
            authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
            tokenUrl: 'https://oauth2.googleapis.com/token',
            scopes: ['openid', 'email', 'profile']
        });

        // GitHub Enterprise
        this._providers.set('github', {
            type: 'oauth',
            name: 'GitHub',
            clientId: '',
            authorizationUrl: 'https://github.com/login/oauth/authorize',
            tokenUrl: 'https://github.com/login/oauth/access_token',
            scopes: ['read:user', 'user:email', 'read:org']
        });
    }

    get state(): AuthState {
        return this._state;
    }

    get isAuthenticated(): boolean {
        return this._state.isAuthenticated;
    }

    get currentUser(): AuthenticatedUser | undefined {
        return this._state.user;
    }

    async signIn(providerId?: string): Promise<AuthenticatedUser | undefined> {
        const config = vscode.workspace.getConfiguration('agentOS.enterprise');
        const configuredProvider = config.get<string>('sso.provider');
        
        const id = providerId || configuredProvider;
        if (!id) {
            const selected = await vscode.window.showQuickPick([
                { label: 'Microsoft Entra ID', id: 'azure', description: 'Azure AD / Microsoft 365' },
                { label: 'Okta', id: 'okta', description: 'Okta Identity' },
                { label: 'Google Workspace', id: 'google', description: 'Google authentication' },
                { label: 'GitHub', id: 'github', description: 'GitHub authentication' }
            ], {
                placeHolder: 'Select authentication provider'
            });
            
            if (!selected) return undefined;
            return this.signIn(selected.id);
        }

        const provider = this._providers.get(id);
        if (!provider) {
            vscode.window.showErrorMessage(`Unknown SSO provider: ${id}`);
            return undefined;
        }

        try {
            // Use VS Code authentication API
            const session = await vscode.authentication.getSession(
                id === 'github' ? 'github' : 'microsoft',
                provider.scopes || [],
                { createIfNone: true }
            );

            if (session) {
                const user: AuthenticatedUser = {
                    id: session.account.id,
                    email: session.account.label,
                    name: session.account.label,
                    roles: ['user'],
                    token: session.accessToken,
                    expiresAt: new Date(Date.now() + 3600000) // 1 hour
                };

                this._state = {
                    isAuthenticated: true,
                    user,
                    provider
                };

                await this._saveState();
                this._onAuthStateChanged.fire(this._state);

                vscode.window.showInformationMessage(`Signed in as ${user.name}`);
                return user;
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Authentication failed: ${error}`);
        }

        return undefined;
    }

    async signOut(): Promise<void> {
        this._state = { isAuthenticated: false };
        await this._saveState();
        this._onAuthStateChanged.fire(this._state);
        vscode.window.showInformationMessage('Signed out successfully');
    }

    private async _saveState(): Promise<void> {
        // Store token in SecretStorage, not globalState
        if (this._state?.user?.token) {
            await this._context.secrets.store('agent-os.authToken', this._state.user.token);
        }
        // Strip token from globalState persistence
        const safeState = this._state ? {
            ...this._state,
            user: this._state.user ? { ...this._state.user, token: undefined } : undefined,
        } : null;
        await this._context.globalState.update('agent-os.authState', safeState);
    }

    hasRole(role: string): boolean {
        return this._state.user?.roles.includes(role) || false;
    }

    hasAnyRole(roles: string[]): boolean {
        return roles.some(role => this.hasRole(role));
    }

    requireAuth(roles?: string[]): boolean {
        if (!this.isAuthenticated) {
            vscode.window.showWarningMessage(
                'This feature requires authentication.',
                'Sign In'
            ).then(selection => {
                if (selection === 'Sign In') {
                    this.signIn();
                }
            });
            return false;
        }

        if (roles && !this.hasAnyRole(roles)) {
            vscode.window.showWarningMessage(
                `This feature requires one of these roles: ${roles.join(', ')}`
            );
            return false;
        }

        return true;
    }

    dispose(): void {
        this._onAuthStateChanged.dispose();
    }
}
