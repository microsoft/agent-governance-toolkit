// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Memory Summary Panel
 *
 * Compact display of VFS directory/file counts
 * with up to 3 root paths shown in monospace.
 */

import React from 'react';
import type { MemorySummaryData } from '../types';
import { Tooltip } from '../../shared/Tooltip';
import { HELP } from '../../shared/helpContent';

const MAX_VISIBLE_PATHS = 3;

function PathList({ paths }: { paths: string[] }): React.ReactElement {
    const visible = paths.slice(0, MAX_VISIBLE_PATHS);
    const remaining = paths.length - MAX_VISIBLE_PATHS;

    return (
        <div className="mt-1">
            {visible.map((p) => (
                <div key={p} className="text-xs font-mono text-ml-text-muted truncate">{p}</div>
            ))}
            {remaining > 0 && (
                <div className="text-xs text-ml-text-muted">+{remaining} more</div>
            )}
        </div>
    );
}

export function MemorySummary(
    { data }: { data: MemorySummaryData | null }
): React.ReactElement {
    if (!data) {
        return (
            <div className="flex items-center justify-center p-ml-sm">
                <span className="text-sm text-ml-text-muted">Awaiting VFS data...</span>
            </div>
        );
    }

    return (
        <div className="p-ml-sm">
            <div className="flex items-center gap-ml-sm text-sm text-ml-text">
                <Tooltip text={HELP.memory.directories}><span><span className="font-bold">{data.directoryCount}</span> dirs</span></Tooltip>
                <Tooltip text={HELP.memory.files}><span><span className="font-bold">{data.fileCount}</span> files</span></Tooltip>
            </div>
            {data.rootPaths.length > 0 && <PathList paths={data.rootPaths} />}
        </div>
    );
}
