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

import express, { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { context, propagation, SpanStatusCode, trace } from '@opentelemetry/api';
import { CopilotExtension } from './copilotExtension';
import { PolicyEngine } from './policyEngine';
import { CMVKClient } from './cmvkClient';
import { AuditLogger } from './auditLogger';
import { TemplateGallery } from './templateGallery';
import { PolicyLibrary } from './policyLibrary';
import { logger } from './logger';
import {
    complianceValidationSchema,
    copilotRequestSchema,
    policyUpdateSchema,
    validateBody,
    webhookRequestSchema
} from './validation';
import { getTracer, initializeTelemetry, telemetryEnabled } from './telemetry';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const SERVICE_NAME = 'agent-os-copilot-extension';
const SERVICE_VERSION = '1.0.0';

interface TraceableRequest extends Request {
    rawBody?: Buffer;
    traceId?: string;
    spanId?: string;
}

function parsePositiveInteger(value: string | undefined, fallback: number): number {
    const parsed = Number.parseInt(value || '', 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
    if (!value) {
        return fallback;
    }

    const normalized = value.trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(normalized)) {
        return true;
    }
    if (['0', 'false', 'no', 'off'].includes(normalized)) {
        return false;
    }
    return fallback;
}

function verifyWebhookSignature(rawBody: Buffer | undefined, signature: string, secret: string): boolean {
    if (!rawBody || !signature.startsWith('sha256=')) {
        return false;
    }

    const expectedSignature = Buffer.from(
        'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex')
    );
    const providedSignature = Buffer.from(signature);

    return expectedSignature.length === providedSignature.length
        && crypto.timingSafeEqual(expectedSignature, providedSignature);
}

    function resolveTraceId(candidate: string): string {
        const emptyTraceId = '00000000000000000000000000000000';
        return candidate && candidate !== emptyTraceId
        ? candidate
        : crypto.randomBytes(16).toString('hex');
    }

export function createApp(): express.Express {
    initializeTelemetry();

    const app = express();
    const tracer = getTracer();
    const startedAt = Date.now();

    // Initialize components
    const policyEngine = new PolicyEngine();
    const cmvkClient = new CMVKClient();
    const auditLogger = new AuditLogger();
    const extension = new CopilotExtension(policyEngine, cmvkClient, auditLogger);
    const templateGallery = new TemplateGallery();
    const policyLibrary = new PolicyLibrary();

    app.disable('x-powered-by');

    // Raw body for webhook signature verification
    app.use(express.json({
        limit: process.env.REQUEST_BODY_LIMIT || '1mb',
        verify: (req: TraceableRequest, _res, buf) => {
            req.rawBody = Buffer.from(buf);
        }
    }));

    app.use((req: TraceableRequest, res: Response, next: NextFunction) => {
        const extractedContext = propagation.extract(context.active(), req.headers);

        context.with(extractedContext, () => {
            const span = tracer.startSpan(`${req.method} ${req.path}`);
            const spanContext = span.spanContext();
            const traceId = resolveTraceId(spanContext.traceId);
            req.traceId = traceId;
            req.spanId = spanContext.spanId;
            res.setHeader('X-Trace-Id', traceId);

            res.on('finish', () => {
                span.setAttributes({
                    'http.method': req.method,
                    'http.route': req.path,
                    'http.status_code': res.statusCode,
                    'agentos.trace_id': traceId
                });
                span.setStatus({
                    code: res.statusCode >= 500 ? SpanStatusCode.ERROR : SpanStatusCode.OK
                });
                span.end();
            });

            context.with(trace.setSpan(context.active(), span), next);
        });
    });

    // CORS for GitHub
    app.use((req, res, next) => {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-GitHub-Token, X-Hub-Signature-256, Traceparent');
        if (req.method === 'OPTIONS') {
            return res.sendStatus(200);
        }
        next();
    });

    const apiRateLimiter = rateLimit({
        windowMs: parsePositiveInteger(process.env.RATE_LIMIT_WINDOW_MS, 60_000),
        limit: parsePositiveInteger(process.env.RATE_LIMIT_MAX_REQUESTS, 100),
        standardHeaders: 'draft-8',
        legacyHeaders: false,
        skipSuccessfulRequests: parseBoolean(process.env.RATE_LIMIT_SKIP_SUCCESSFUL_REQUESTS, false),
        message: {
            error: 'Too many requests',
            details: 'Rate limit exceeded for AgentOS API endpoints. Please retry later.'
        },
        handler: (req: TraceableRequest, res: Response) => {
            logger.warn('Rate limit exceeded', {
                path: req.path,
                method: req.method,
                traceId: req.traceId,
                ip: req.ip
            });
            res.status(429).json({
                error: 'Too many requests',
                details: 'Rate limit exceeded for AgentOS API endpoints. Please retry later.'
            });
        }
    });

    app.use('/api', apiRateLimiter);

    // Health check endpoint
    app.get('/health', (req: TraceableRequest, res: Response) => {
        res.json({
            status: 'healthy',
            version: SERVICE_VERSION,
            service: SERVICE_NAME,
            timestamp: new Date().toISOString(),
            uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
            traceId: req.traceId,
            telemetry: telemetryEnabled()
        });
    });

// Root endpoint - service info
    app.get('/', (req: TraceableRequest, res: Response) => {
        res.json({
            name: 'AgentOS Copilot Extension',
            version: SERVICE_VERSION,
            description: 'Build safe AI agents with natural language',
            documentation: 'https://github.com/microsoft/agent-governance-toolkit/tree/main/docs/tutorials/copilot-extension/',
            traceId: req.traceId,
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
    app.post('/api/copilot', validateBody(copilotRequestSchema), async (req: TraceableRequest, res: Response) => {
    try {
        const { messages, copilot_references, copilot_confirmations } = req.body;
        const githubToken = req.headers['x-github-token'] as string;
        
        logger.info('Copilot request received', { 
            messageCount: messages?.length,
            hasToken: !!githubToken,
            traceId: req.traceId
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
        logger.error('Copilot endpoint error', { error, traceId: req.traceId });
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
    app.post('/api/webhook', validateBody(webhookRequestSchema), async (req: TraceableRequest, res: Response) => {
    try {
        const signature = req.headers['x-hub-signature-256'] as string;
        const event = req.headers['x-github-event'] as string;
        
        // Verify webhook signature if secret is configured
        if (process.env.GITHUB_WEBHOOK_SECRET && signature) {
            const rawBody = req.rawBody;
            if (!verifyWebhookSignature(rawBody, signature, process.env.GITHUB_WEBHOOK_SECRET)) {
                logger.warn('Invalid webhook signature', { traceId: req.traceId, event });
                return res.status(401).json({ error: 'Invalid signature' });
            }
        }

        logger.info('Webhook received', { event, action: req.body.action, traceId: req.traceId });

        // Handle different webhook events
        switch (event) {
            case 'installation':
                if (req.body.action === 'created') {
                    logger.info('New installation', { 
                        installationId: req.body.installation?.id,
                        account: req.body.installation?.account?.login,
                        traceId: req.traceId
                    });
                }
                break;
            
            case 'installation_repositories':
                logger.info('Repository access changed', {
                    action: req.body.action,
                    repos: req.body.repositories_added?.length || req.body.repositories_removed?.length,
                    traceId: req.traceId
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
        logger.error('Webhook error', { error, traceId: req.traceId });
        res.status(500).json({ error: 'Webhook processing failed' });
    }
    });

/**
 * OAuth callback endpoint
 * GET /auth/callback
 */
    app.get('/auth/callback', async (req: TraceableRequest, res: Response) => {
    const { code, state } = req.query;
    
    if (!code) {
        return res.status(400).send('Missing authorization code');
    }

    // In production, exchange code for token and complete setup
    logger.info('OAuth callback received', { hasCode: !!code, hasState: !!state, traceId: req.traceId });
    
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
    app.get('/setup', (_req: Request, res: Response) => {
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
    app.get('/api/policy', (_req: Request, res: Response) => {
        const policies = policyEngine.getActivePolicies();
        res.json({ policies });
    });

    app.post('/api/policy', validateBody(policyUpdateSchema), async (req: TraceableRequest, res: Response) => {
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
    app.get('/api/compliance', (_req: Request, res: Response) => {
        const frameworks = policyLibrary.getFrameworks();
        res.json({ frameworks });
    });

/**
 * Validate code against compliance framework
 * POST /api/compliance/validate
 */
    app.post('/api/compliance/validate', validateBody(complianceValidationSchema), (req: TraceableRequest, res: Response) => {
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
    app.get('/api/status', (req: TraceableRequest, res: Response) => {
        const stats = auditLogger.getStats();
        res.json({
            status: 'healthy',
            version: SERVICE_VERSION,
            service: SERVICE_NAME,
            traceId: req.traceId,
            uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
            telemetry: telemetryEnabled(),
            stats: {
                blockedToday: stats.blockedToday,
                reviewsToday: stats.cmvkReviewsToday,
                templatesAvailable: templateGallery.search().totalCount,
                activePolicies: policyEngine.getActivePolicies().filter(p => p.enabled).length
            }
        });
    });

    return app;
}

const app = createApp();

// Start server only if not in serverless environment
const PORT = process.env.PORT || 3000;

if (process.env.VERCEL !== '1' && process.env.NODE_ENV !== 'test') {
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
