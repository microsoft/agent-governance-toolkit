// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Hub Policy Tab
 *
 * Policy rules detail view with summary stats and collapsible
 * action groups. Displays within the Governance Hub panel.
 */

import React, { useState, useMemo } from 'react';
import type { PolicyDetailData, PolicyRuleDetail } from '../shared/types';
import { Tooltip } from '../shared/Tooltip';
import { HELP } from '../shared/helpContent';

type PolicyAction = PolicyRuleDetail['action'];

interface HubPolicyTabProps {
    data: PolicyDetailData | null;
}

/** Action display order by severity (most restrictive first). */
const ACTION_ORDER: PolicyAction[] = ['DENY', 'BLOCK', 'AUDIT', 'ALLOW'];

/** Map policy action to accent color class. */
function actionColorClass(action: PolicyAction): string {
    if (action === 'DENY') { return 'text-ml-error'; }
    if (action === 'BLOCK') { return 'text-ml-error'; }
    if (action === 'AUDIT') { return 'text-ml-warning'; }
    return 'text-ml-success';
}

/** Group rules by action type and return in severity order. */
function groupByAction(
    rules: PolicyRuleDetail[],
): { action: PolicyAction; rules: PolicyRuleDetail[] }[] {
    const grouped = new Map<PolicyAction, PolicyRuleDetail[]>();
    for (const rule of rules) {
        const list = grouped.get(rule.action) ?? [];
        list.push(rule);
        grouped.set(rule.action, list);
    }
    return ACTION_ORDER
        .filter((a) => grouped.has(a))
        .map((a) => ({ action: a, rules: grouped.get(a)! }));
}

/** Calculate violation rate as a percentage string. */
function violationRate(evaluations: number, violations: number): string {
    if (evaluations === 0) { return '0.0%'; }
    return `${((violations / evaluations) * 100).toFixed(1)}%`;
}

/** Summary statistics bar above the rule groups. */
function PolicySummary({ data }: { data: PolicyDetailData }): React.JSX.Element {
    const enabledCount = data.rules.filter((r) => r.enabled).length;
    const rate = violationRate(data.totalEvaluations, data.totalViolations);

    return (
        <div className="flex items-center gap-4 mb-ml-sm">
            <StatChip label="Total Rules" value={String(data.rules.length)} />
            <StatChip label="Enabled" value={String(enabledCount)} />
            <StatChip label="Violation Rate" value={rate} />
        </div>
    );
}

/** Small labeled stat display. */
function StatChip({ label, value }: { label: string; value: string }): React.JSX.Element {
    return (
        <div className="flex flex-col items-center px-3 py-1 rounded-ml bg-ml-surface">
            <span className="text-xs text-ml-text-muted">{label}</span>
            <span className="text-sm font-semibold text-ml-text-bright">{value}</span>
        </div>
    );
}

/** Tooltip text for each policy action type. */
const ACTION_TOOLTIPS: Record<PolicyAction, string> = {
    DENY: HELP.policy.deny,
    BLOCK: HELP.policy.block,
    AUDIT: HELP.policy.audit,
    ALLOW: HELP.policy.allow,
};

/** Collapsible section for a single action group. */
function ActionGroup(
    { action, rules }: { action: PolicyAction; rules: PolicyRuleDetail[] },
): React.JSX.Element {
    const [expanded, setExpanded] = useState(true);

    return (
        <div className="mb-ml-sm">
            <button
                type="button"
                className="flex items-center gap-2 w-full text-left py-1 cursor-pointer"
                onClick={() => setExpanded((prev) => !prev)}
                aria-expanded={expanded}
            >
                <i className={`codicon codicon-chevron-${expanded ? 'down' : 'right'} text-xs`} />
                <span className={`text-sm font-semibold ${actionColorClass(action)}`}>
                    {action}
                </span>
                <Tooltip text={ACTION_TOOLTIPS[action]} />
                <span className="text-xs text-ml-text-muted">({rules.length})</span>
            </button>
            {expanded && (
                <div className="ml-4 mt-1 flex flex-col gap-1">
                    {rules.map((rule) => (
                        <PolicyRuleRow key={rule.id} rule={rule} />
                    ))}
                </div>
            )}
        </div>
    );
}

/** Single policy rule display row. */
function PolicyRuleRow({ rule }: { rule: PolicyRuleDetail }): React.JSX.Element {
    return (
        <div className="flex items-center gap-3 px-2 py-1 rounded-ml hover:bg-ml-surface-hover text-xs">
            <span className="font-medium text-ml-text-bright w-36 truncate" title={rule.name}>
                {rule.name}
            </span>
            <code className="text-ml-text-muted flex-1 truncate" title={rule.pattern}>
                {rule.pattern}
            </code>
            <EnabledIndicator enabled={rule.enabled} />
            <span className="text-ml-text-muted w-16 text-right">
                {rule.evaluationsToday} eval
            </span>
            <span className={`w-16 text-right ${rule.violationsToday > 0 ? 'text-ml-error' : 'text-ml-text-muted'}`}>
                {rule.violationsToday} viol
            </span>
        </div>
    );
}

/** Display-only enabled/disabled indicator dot. */
function EnabledIndicator({ enabled }: { enabled: boolean }): React.JSX.Element {
    const color = enabled ? 'bg-ml-success' : 'bg-ml-text-muted';
    const label = enabled ? 'Enabled' : 'Disabled';
    return (
        <span
            className={`inline-block w-2 h-2 rounded-full ${color}`}
            title={label}
            aria-label={label}
        />
    );
}

/**
 * Policy rules tab for the Governance Hub.
 *
 * Shows summary stats and rules grouped by action type
 * in collapsible sections ordered by severity.
 */
export function HubPolicyTab({ data }: HubPolicyTabProps): React.JSX.Element {
    const groups = useMemo(() => {
        if (!data) { return []; }
        return groupByAction(data.rules);
    }, [data]);

    if (!data) {
        return <p className="text-sm text-ml-text-muted py-ml-md">Loading policy data...</p>;
    }

    return (
        <div className="flex flex-col gap-ml-sm">
            <h2 className="text-sm font-semibold text-ml-text-bright">Policy Rules</h2>
            <PolicySummary data={data} />
            {groups.map((g) => (
                <ActionGroup key={g.action} action={g.action} rules={g.rules} />
            ))}
            {groups.length === 0 && (
                <p className="text-xs text-ml-text-muted py-ml-sm">No policy rules configured.</p>
            )}
        </div>
    );
}
