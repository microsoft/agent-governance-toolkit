// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Types, constants, and pure helper functions for the Governance Status Bar.
 *
 * Extracted from governanceStatusBar.ts to keep each file under 250 lines.
 */

/** Policy enforcement modes supported by the governance engine. */
type GovernanceMode = 'strict' | 'permissive' | 'audit-only';

/** Per-dimension SLO breakdown. */
interface SLOBreakdown {
    availability: number;
    latency: number;
    compliance: number;
}

/** Summary information for a registered agent. */
interface AgentInfo {
    did: string;
    trust: number;
}

/** Violation severity breakdown. */
interface ViolationBreakdown {
    errors: number;
    warnings: number;
    lastViolation?: Date;
}

/** Human-readable labels for each governance mode. */
const MODE_LABELS: Record<GovernanceMode, string> = {
    'strict': 'Strict',
    'permissive': 'Permissive',
    'audit-only': 'Audit-Only',
};

/** Descriptive tooltips for each governance mode. */
const MODE_DESCRIPTIONS: Record<GovernanceMode, string> = {
    'strict': 'All policy violations are blocked immediately.',
    'permissive': 'Policy violations are logged but not blocked.',
    'audit-only': 'Actions are recorded for audit; no enforcement applied.',
};

/**
 * Format a Date as a locale time string (HH:MM:SS).
 *
 * @param date - The date to format.
 * @returns Formatted time string.
 */
function formatTime(date: Date): string {
    return date.toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    });
}

/**
 * Truncate a DID string for compact display.
 *
 * Returns the full string when 24 characters or fewer, otherwise
 * keeps the first 16 and last 6 characters separated by an ellipsis.
 *
 * @param did - The agent DID to truncate.
 * @returns Truncated DID string.
 */
function truncateAgentDid(did: string): string {
    if (did.length <= 24) {
        return did;
    }
    return `${did.slice(0, 16)}...${did.slice(-6)}`;
}

/**
 * Build a tooltip string for the governance mode status bar item.
 *
 * @param mode - The active governance mode.
 * @param activePolicies - Number of loaded policy documents.
 * @param lastReload - Timestamp of the last policy reload.
 * @returns Multi-line tooltip string.
 */
function buildModeTooltip(
    mode: GovernanceMode,
    activePolicies: number,
    lastReload: Date,
): string {
    const lines = [
        `Governance Mode: ${MODE_LABELS[mode]}`,
        MODE_DESCRIPTIONS[mode],
        '',
        `Active policies: ${activePolicies}`,
        `Last reload: ${formatTime(lastReload)}`,
        '',
        'Click to configure policy',
    ];
    return lines.join('\n');
}

/**
 * Build a tooltip string for the violation counter status bar item.
 *
 * @param count - Total violation count for today.
 * @param breakdown - Severity breakdown with optional last violation time.
 * @returns Multi-line tooltip string.
 */
function buildViolationTooltip(
    count: number,
    breakdown: ViolationBreakdown,
): string {
    const lines = [
        `${count} violation${count === 1 ? '' : 's'} today`,
        '',
        `  Errors:   ${breakdown.errors}`,
        `  Warnings: ${breakdown.warnings}`,
    ];
    if (breakdown.lastViolation) {
        lines.push('');
        lines.push(`Last violation: ${formatTime(breakdown.lastViolation)}`);
    }
    lines.push('');
    lines.push('Click to view audit log');
    return lines.join('\n');
}

export {
    GovernanceMode,
    SLOBreakdown,
    AgentInfo,
    ViolationBreakdown,
    MODE_LABELS,
    MODE_DESCRIPTIONS,
    formatTime,
    truncateAgentDid,
    buildModeTooltip,
    buildViolationTooltip,
};
