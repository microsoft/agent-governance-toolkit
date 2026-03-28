// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Request validation helpers for HTTP endpoints.
 */

import { Request, Response, NextFunction, RequestHandler } from 'express';
import { z, ZodTypeAny } from 'zod';

const copilotMessageSchema = z.object({
    role: z.string().min(1, 'role is required'),
    content: z.string().min(1, 'content is required')
}).passthrough();

const repositorySchema = z.object({
    id: z.number().optional(),
    name: z.string().optional(),
    full_name: z.string().optional()
}).passthrough();

export const copilotRequestSchema = z.object({
    messages: z.array(copilotMessageSchema).min(1, 'messages must contain at least one message'),
    copilot_references: z.array(z.unknown()).optional(),
    copilot_confirmations: z.array(z.unknown()).optional()
}).passthrough();

export const webhookRequestSchema = z.object({
    action: z.string().optional(),
    installation: z.object({
        id: z.union([z.number(), z.string()]).optional(),
        account: z.object({
            login: z.string().optional()
        }).partial().optional()
    }).partial().optional(),
    repositories_added: z.array(repositorySchema).optional(),
    repositories_removed: z.array(repositorySchema).optional()
}).passthrough();

export const policyUpdateSchema = z.object({
    policy: z.enum([
        'destructiveSQL',
        'fileDeletes',
        'secretExposure',
        'privilegeEscalation',
        'unsafeNetwork'
    ]),
    enabled: z.boolean()
});

export const complianceValidationSchema = z.object({
    code: z.string().min(1, 'code is required'),
    language: z.string().min(1, 'language is required'),
    framework: z.enum([
        'gdpr',
        'hipaa',
        'soc2',
        'pci-dss',
        'iso27001',
        'ccpa'
    ])
});

function formatZodIssues(error: z.ZodError): Array<{ path: string; message: string }> {
    return error.issues.map((issue) => ({
        path: issue.path.join('.') || 'body',
        message: issue.message
    }));
}

export function validateBody<T extends ZodTypeAny>(schema: T): RequestHandler {
    return (req: Request, res: Response, next: NextFunction) => {
        const result = schema.safeParse(req.body);
        if (!result.success) {
            return res.status(400).json({
                error: 'Invalid request body',
                details: formatZodIssues(result.error)
            });
        }

        req.body = result.data;
        next();
    };
}