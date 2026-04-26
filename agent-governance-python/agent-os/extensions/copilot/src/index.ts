// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent OS Copilot Extension
 * 
 * Main entry point for the GitHub Copilot Extension.
 * Provides safety verification for Copilot suggestions.
 * 
 * Features:
 * - Agent creation from natural language
 * - 50+ agent templates
 * - Policy-aware code suggestions
 * - CMVK multi-model verification
 * - Compliance checking (GDPR, HIPAA, SOC2, PCI DSS)
 * - GitHub Actions deployment
 */

import express, { Request, Response } from 'express';
import { CopilotExtension } from './copilotExtension';
import { PolicyEngine } from './policyEngine';
import { CMVKClient } from './cmvkClient';
import { AuditLogger } from './auditLogger';
import { TemplateGallery } from './templateGallery';
import { PolicyLibrary } from './policyLibrary';
import { logger } from './logger';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const app = express();

const DEFAULT_ALLOWED_ORIGINS = [
    'https://github.com',
    'https://api.github.com',
    'https://copilot.github.com'
];

const CORS_EXCLUDED_PATHS = new Set([
    '/',
    '/health',
    '/auth/callback',
    '/api/webhook'
]);

function normalizeOrigin(origin: string): string | null {
    try {
        const parsed = new URL(origin.trim());
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return null;
        }
        return parsed.origin;
    } catch {
        return null;
    }
}

function getAllowedOrigins(): Set<string> {
    const configured = process.env.ALLOWED_ORIGINS;
    const hasConfiguredAllowlist = typeof configured === 'string';
    const source = configured
        ? configured.split(',').map((v) => v.trim()).filter(Boolean)
        : DEFAULT_ALLOWED_ORIGINS;

    const normalized: string[] = [];
    for (const entry of source) {
        const value = normalizeOrigin(entry);
        if (!value) {
            logger.warn('Ignoring invalid CORS origin from ALLOWED_ORIGINS', { origin: entry });
            continue;
        }
        normalized.push(value);
    }

    if (normalized.length === 0) {
        if (hasConfiguredAllowlist) {
            throw new Error(
                'Invalid ALLOWED_ORIGINS configuration. Provide one or more valid origins, for example: https://github.com,https://copilot.github.com'
            );
        }
        logger.warn('No valid ALLOWED_ORIGINS provided, falling back to secure defaults');
        return new Set(DEFAULT_ALLOWED_ORIGINS);
    }

    return new Set(normalized);
}

const allowedOrigins = getAllowedOrigins();

function isCorsProtectedPath(path: string): boolean {
    return !CORS_EXCLUDED_PATHS.has(path);
}

// Raw body for webhook signature verification
app.use(express.json({
    verify: (req: any, res, buf) => {
        req.rawBody = buf;
    }
}));

// Initialize components
const policyEngine = new PolicyEngine();
const cmvkClient = new CMVKClient();
const auditLogger = new AuditLogger();
const extension = new CopilotExtension(policyEngine, cmvkClient, auditLogger);
const templateGallery = new TemplateGallery();
const policyLibrary = new PolicyLibrary();

// CORS origin allowlist (configurable via ALLOWED_ORIGINS).
app.use((req, res, next) => {
    const isProtectedPath = isCorsProtectedPath(req.path);
    const origin = req.header('Origin');
    const normalizedOrigin = origin ? normalizeOrigin(origin) : null;
    const isAllowedOrigin = normalizedOrigin !== null && allowedOrigins.has(normalizedOrigin);

    if (isAllowedOrigin && normalizedOrigin) {
        res.header('Access-Control-Allow-Origin', normalizedOrigin);
        res.header('Vary', 'Origin');
        res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-GitHub-Token, X-Hub-Signature-256');
    }

    if (req.method === 'OPTIONS') {
        if (!isProtectedPath) {
            return res.sendStatus(204);
        }
        if (!origin || !isAllowedOrigin) {
            logger.warn('Rejected CORS preflight request');
            return res.sendStatus(403);
        }
        return res.sendStatus(204);
    }

    if (!isProtectedPath) {
        return next();
    }

    if (!origin) {
        logger.warn('Rejected request due to missing CORS origin header', { path: req.path });
        return res.sendStatus(403);
    }

    if (!isAllowedOrigin) {
        logger.warn('Rejected request due to disallowed CORS origin', { path: req.path });
        return res.sendStatus(403);
    }

    next();
});

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
    res.json({
        status: 'healthy',
        version: '1.0.0',
        service: 'agent-os-copilot-extension',
        timestamp: new Date().toISOString()
    });
});

// Root endpoint - service info
app.get('/', (req: Request, res: Response) => {
    res.json({
        name: 'AgentOS Copilot Extension',
        version: '1.0.0',
        description: 'Build safe AI agents with natural language',
        documentation: 'https://github.com/microsoft/agent-governance-toolkit/tree/main/docstutorials/copilot-extension/',
        endpoints: {
            health: '/health',
            copilot: '/api/copilot',
            webhook: '/api/webhook',
            templates: '/api/templates',
            compliance: '/api/compliance'
        }
    });
});

/**
 * GitHub Copilot Extension endpoint
 * This is the main endpoint that GitHub Copilot calls
 * POST /api/copilot
 */
app.post('/api/copilot', async (req: Request, res: Response) => {
    try {
        const { messages, copilot_references, copilot_confirmations } = req.body;
        const githubToken = req.headers['x-github-token'] as string;
        
        logger.info('Copilot request received', { 
            messageCount: messages?.length,
            hasToken: !!githubToken
        });

        // Get the latest user message
        const userMessage = messages?.filter((m: any) => m.role === 'user').pop();
        if (!userMessage) {
            return res.json({
                choices: [{
                    message: {
                        role: 'assistant',
                        content: "I didn't receive a message. Try asking me something like `@agentos help` or `@agentos create an agent that monitors my API`."
                    }
                }]
            });
        }

        // Extract command from message
        const content = userMessage.content || '';
        
        // Handle the chat message
        const response = await extension.handleChatMessage(content, {
            user: { id: 'copilot-user' }
        });

        // Format response for Copilot
        res.json({
            choices: [{
                message: {
                    role: 'assistant',
                    content: response.message || JSON.stringify(response)
                }
            }]
        });
    } catch (error) {
        logger.error('Copilot endpoint error', { error });
        res.json({
            choices: [{
                message: {
                    role: 'assistant',
                    content: '❌ Sorry, I encountered an error processing your request. Please try again.'
                }
            }]
        });
    }
});

/**
 * GitHub Webhook endpoint
 * Handles installation and other GitHub events
 * POST /api/webhook
 */
app.post('/api/webhook', async (req: Request, res: Response) => {
    try {
        const signature = req.headers['x-hub-signature-256'] as string;
        const event = req.headers['x-github-event'] as string;
        
        // Verify webhook signature if secret is configured
        if (process.env.GITHUB_WEBHOOK_SECRET && signature) {
            const rawBody = (req as any).rawBody;
            const expectedSignature = 'sha256=' + crypto
                .createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET)
                .update(rawBody)
                .digest('hex');
            
            if (signature !== expectedSignature) {
                logger.warn('Invalid webhook signature');
                return res.status(401).json({ error: 'Invalid signature' });
            }
        }

        logger.info('Webhook received', { event, action: req.body.action });

        // Handle different webhook events
        switch (event) {
            case 'installation':
                if (req.body.action === 'created') {
                    logger.info('New installation', { 
                        installationId: req.body.installation?.id,
                        account: req.body.installation?.account?.login
                    });
                }
                break;
            
            case 'installation_repositories':
                logger.info('Repository access changed', {
                    action: req.body.action,
                    repos: req.body.repositories_added?.length || req.body.repositories_removed?.length
                });
                break;
            
            case 'ping':
                logger.info('Webhook ping received');
                break;
            
            default:
                logger.info('Unhandled webhook event', { event });
        }

        res.json({ received: true });
    } catch (error) {
        logger.error('Webhook error', { error });
        res.status(500).json({ error: 'Webhook processing failed' });
    }
});

/**
 * OAuth callback endpoint
 * GET /auth/callback
 */
app.get('/auth/callback', async (req: Request, res: Response) => {
    const { code, state } = req.query;
    
    if (!code) {
        return res.status(400).send('Missing authorization code');
    }

    // In production, exchange code for token and complete setup
    logger.info('OAuth callback received', { hasCode: !!code, hasState: !!state });
    
    res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'");
    res.send(`
        <html>
        <head><title>AgentOS Setup Complete</title></head>
        <body style="font-family: system-ui; padding: 2rem; text-align: center;">
            <h1>✅ AgentOS Installation Complete!</h1>
            <p>You can now use @agentos in GitHub Copilot Chat.</p>
            <p>Try: <code>@agentos help</code></p>
            <p><a href="https://github.com">Return to GitHub</a></p>
        </body>
        </html>
    `);
});

/**
 * Setup page
 * GET /setup
 */
app.get('/setup', (req: Request, res: Response) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'");
    res.send(`
        <html>
        <head>
            <title>AgentOS Setup</title>
            <style>
                body { font-family: system-ui; max-width: 600px; margin: 2rem auto; padding: 1rem; }
                h1 { color: #10b981; }
                .step { background: #f1f5f9; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
                code { background: #e2e8f0; padding: 0.25rem 0.5rem; border-radius: 4px; }
            </style>
        </head>
        <body>
            <h1>🤖 AgentOS Setup</h1>
            <p>Welcome! AgentOS helps you build safe AI agents with natural language.</p>
            
            <div class="step">
                <h3>Step 1: Start Using</h3>
                <p>Open GitHub Copilot Chat and type:</p>
                <code>@agentos help</code>
            </div>
            
            <div class="step">
                <h3>Step 2: Create Your First Agent</h3>
                <p>Describe what you want:</p>
                <code>@agentos create an agent that monitors my API endpoints</code>
            </div>
            
            <div class="step">
                <h3>Step 3: Explore Templates</h3>
                <p>Browse 50+ pre-built templates:</p>
                <code>@agentos templates</code>
            </div>
            
            <p><a href="https://github.com/microsoft/agent-governance-toolkit/tree/main/docstutorials/copilot-extension/">📚 Full Documentation</a></p>
        </body>
        </html>
    `);
});

/**
 * Audit endpoint - Get audit log
 * GET /api/audit
 */
app.get('/api/audit', (req: Request, res: Response) => {
    const limit = parseInt(req.query.limit as string) || 20;
    const logs = auditLogger.getRecent(limit);
    res.json({ logs });
});

/**
 * Policy endpoint - Get or update policies
 * GET/POST /api/policy
 */
app.get('/api/policy', (req: Request, res: Response) => {
    const policies = policyEngine.getActivePolicies();
    res.json({ policies });
});

app.post('/api/policy', async (req: Request, res: Response) => {
    try {
        const { policy, enabled } = req.body;
        policyEngine.setPolicy(policy, enabled);
        res.json({ success: true, policies: policyEngine.getActivePolicies() });
    } catch (error) {
        res.status(400).json({ error: 'Invalid policy configuration' });
    }
});

/**
 * Templates endpoint - List and search templates
 * GET /api/templates
 */
app.get('/api/templates', (req: Request, res: Response) => {
    const query = req.query.q as string;
    const category = req.query.category as string;
    const limit = parseInt(req.query.limit as string) || 20;
    
    const results = templateGallery.search(query, category as any, undefined, limit);
    res.json(results);
});

/**
 * Template by ID
 * GET /api/templates/:id
 */
app.get('/api/templates/:id', (req: Request, res: Response) => {
    const templateId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const template = templateGallery.getById(templateId);
    if (template) {
        res.json(template);
    } else {
        res.status(404).json({ error: 'Template not found' });
    }
});

/**
 * Compliance frameworks
 * GET /api/compliance
 */
app.get('/api/compliance', (req: Request, res: Response) => {
    const frameworks = policyLibrary.getFrameworks();
    res.json({ frameworks });
});

/**
 * Validate code against compliance framework
 * POST /api/compliance/validate
 */
app.post('/api/compliance/validate', (req: Request, res: Response) => {
    try {
        const { code, language, framework } = req.body;
        const policyId = `${framework}-standard`;
        const result = policyLibrary.validateAgainstPolicy(code, language, policyId);
        res.json(result);
    } catch (error) {
        res.status(400).json({ error: 'Validation failed' });
    }
});

/**
 * Health check with detailed status
 * GET /api/status
 */
app.get('/api/status', (req: Request, res: Response) => {
    const stats = auditLogger.getStats();
    res.json({
        status: 'healthy',
        version: '1.0.0',
        service: 'agent-os-copilot-extension',
        stats: {
            blockedToday: stats.blockedToday,
            reviewsToday: stats.cmvkReviewsToday,
            templatesAvailable: templateGallery.search().totalCount,
            activePolicies: policyEngine.getActivePolicies().filter(p => p.enabled).length
        }
    });
});

// Start server only if not in serverless environment
const PORT = process.env.PORT || 3000;

if (process.env.VERCEL !== '1') {
    app.listen(PORT, () => {
        logger.info(`Agent OS Copilot Extension running on port ${PORT}`);
        logger.info('Endpoints:');
        logger.info('  POST /api/copilot  - Copilot extension endpoint');
        logger.info('  POST /api/webhook  - GitHub webhook endpoint');
        logger.info('  GET  /api/audit    - Get audit log');
        logger.info('  GET  /api/policy   - Get active policies');
    });
}

// Export for Vercel serverless
export default app;
export { app };
