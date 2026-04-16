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
import { Tooltip } from '../../shared/Tooltip';
import { HELP } from '../../shared/helpContent';

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
                <Tooltip text={HELP.audit.violations}><span className="text-xs text-ml-text-muted">violations</span></Tooltip>
            </div>
            <div className="flex items-center justify-between">
                <Tooltip text={HELP.audit.totalToday}><span className="text-xs text-ml-text-muted">
                    {data.totalToday} total today
                </span></Tooltip>
                {data.lastEventTime && (
                    <Tooltip text={HELP.audit.lastEvent}><span className="text-xs text-ml-text-muted">
                        {timeAgo(data.lastEventTime)}
                    </span></Tooltip>
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
