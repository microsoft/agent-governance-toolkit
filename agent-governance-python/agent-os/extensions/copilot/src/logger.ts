// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Logger for Agent OS Copilot Extension
 */

import winston from 'winston';

export const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'agent-os-copilot' },
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

// Add file transport in production
if (process.env.NODE_ENV === 'production') {
    logger.add(new winston.transports.File({ 
        filename: 'error.log', 
        level: 'error' 
    }));
    logger.add(new winston.transports.File({ 
        filename: 'combined.log' 
    }));
}
