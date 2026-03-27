// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Audit Summary Panel
 *
 * Compact audit event summary showing violation count,
 * total events, and relative time since last event.
 */

import React from 'react';
import type { AuditSummaryData } from '../types';
import { timeAgo } from '../timeUtils';

export function AuditSummary(
    { data }: { data: AuditSummaryData | null }
): React.ReactElement {
    if (!data) {
        return (
            <div className="flex items-center justify-center p-ml-sm">
                <span className="text-sm text-ml-text-muted">Awaiting audit data...</span>
            </div>
        );
    }

    const violationColor = data.violationsToday > 0
        ? 'text-ml-error'
        : 'text-ml-success';

    return (
        <div className="flex flex-col gap-ml-xs p-ml-sm">
            <div className="flex flex-col items-start">
                <span className={`text-2xl font-bold ${violationColor}`}>
                    {data.violationsToday}
                </span>
                <span className="text-xs text-ml-text-muted">violations</span>
            </div>
            <div className="flex items-center justify-between">
                <span className="text-xs text-ml-text-muted">
                    {data.totalToday} total today
                </span>
                {data.lastEventTime && (
                    <span className="text-xs text-ml-text-muted">
                        {timeAgo(data.lastEventTime)}
                    </span>
                )}
            </div>
            {data.lastEventAction && (
                <span className="text-xs text-ml-text-muted truncate">
                    {data.lastEventAction}
                </span>
            )}
        </div>
    );
}
