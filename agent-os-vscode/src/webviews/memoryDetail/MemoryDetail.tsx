// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Memory Browser Detail Panel
 *
 * Full-panel view of the Agent VFS (Virtual File System).
 * Displays directory/file counts and a tree of root paths.
 */

import React, { useState } from 'react';
import { DetailShell } from '../shared/DetailShell';
import { useExtensionMessage } from '../shared/useExtensionMessage';
import { getVSCodeAPI } from '../shared/vscode';
import type { MemoryDetailData, MemoryNode } from '../shared/types';

function TreeNode({ node, depth }: { node: MemoryNode; depth: number }): React.JSX.Element {
    const [expanded, setExpanded] = useState(depth < 2);
    const hasChildren = node.type === 'directory' && node.children && node.children.length > 0;
    const indent = depth * 16;

    return (
        <div>
            <div
                className={`flex items-center gap-1.5 py-0.5 px-ml-sm hover:bg-ml-surface-hover ${hasChildren ? 'cursor-pointer' : ''}`}
                style={{ paddingLeft: `${indent + 8}px` }}
                onClick={() => hasChildren && setExpanded(!expanded)}
                role={hasChildren ? 'button' : undefined}
                tabIndex={hasChildren ? 0 : undefined}
                onKeyDown={(e) => { if (hasChildren && (e.key === 'Enter' || e.key === ' ')) { setExpanded(!expanded); } }}
            >
                {node.type === 'directory' ? (
                    <span className="text-xs text-ml-text-muted w-3">{hasChildren ? (expanded ? '\u25BE' : '\u25B8') : ''}</span>
                ) : (
                    <span className="w-3" />
                )}
                <i className={`codicon codicon-${node.type === 'directory' ? 'folder' : 'file'} text-sm`} />
                <span className="text-sm font-mono text-ml-text">{node.name}</span>
            </div>
            {expanded && hasChildren && node.children!.map((child) => (
                <TreeNode key={child.path} node={child} depth={depth + 1} />
            ))}
        </div>
    );
}

function LoadingState(): React.JSX.Element {
    return (
        <div className="flex items-center justify-center h-64 text-ml-text-muted text-sm">
            Waiting for VFS data...
        </div>
    );
}

function MemoryContent({ data }: { data: MemoryDetailData }): React.JSX.Element {
    return (
        <div className="space-y-ml-md">
            <div className="grid grid-cols-3 gap-ml-sm">
                <div className="bg-ml-surface rounded-ml p-ml-sm">
                    <div className="text-xs text-ml-text-muted">Directories</div>
                    <div className="text-lg font-bold text-ml-text">{data.directoryCount}</div>
                </div>
                <div className="bg-ml-surface rounded-ml p-ml-sm">
                    <div className="text-xs text-ml-text-muted">Files</div>
                    <div className="text-lg font-bold text-ml-text">{data.fileCount}</div>
                </div>
                <div className="bg-ml-surface rounded-ml p-ml-sm">
                    <div className="text-xs text-ml-text-muted">Root Paths</div>
                    <div className="text-lg font-bold text-ml-text">{data.rootPaths.length}</div>
                </div>
            </div>

            <div className="bg-ml-surface rounded-ml">
                <div className="px-ml-sm py-1.5 border-b border-ml-border">
                    <h2 className="text-sm font-semibold text-ml-text-bright">Virtual File System</h2>
                </div>
                {data.tree.length === 0 ? (
                    <div className="p-ml-sm text-sm text-ml-text-muted">VFS is empty</div>
                ) : (
                    <div className="py-1">
                        {data.tree.map((node) => (
                            <TreeNode key={node.path} node={node} depth={0} />
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}

export function MemoryDetail({ data: propData }: { data?: MemoryDetailData }): React.JSX.Element {
    const msgData = useExtensionMessage<MemoryDetailData>('memoryDetailUpdate');
    const data = propData ?? msgData;

    const handleRefresh = () => getVSCodeAPI().postMessage({ type: 'refresh' });

    return (
        <DetailShell title="Memory Browser" timestamp={data?.fetchedAt ?? null} onRefresh={handleRefresh}>
            {data ? <MemoryContent data={data} /> : <LoadingState />}
        </DetailShell>
    );
}
