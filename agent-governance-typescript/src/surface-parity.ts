// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import type {
  GovernanceSurface,
  Policy,
  PolicyAction,
  PolicyRule,
  SurfaceGap,
  SurfaceParityReport,
  SurfaceRuleMapping,
} from './types';

const KNOWN_SURFACES: GovernanceSurface[] = ['cli', 'ide', 'api'];

const SURFACE_CONDITION_PATTERNS: Array<{ pattern: RegExp; surface: GovernanceSurface }> = [
  { pattern: /\bsurface\s*==\s*['"]cli['"]/i, surface: 'cli' },
  { pattern: /\bsurface\s*==\s*['"]ide['"]/i, surface: 'ide' },
  { pattern: /\bsurface\s*==\s*['"]api['"]/i, surface: 'api' },
  { pattern: /\bcontext\.surface\s*==\s*['"]cli['"]/i, surface: 'cli' },
  { pattern: /\bcontext\.surface\s*==\s*['"]ide['"]/i, surface: 'ide' },
  { pattern: /\bcontext\.surface\s*==\s*['"]api['"]/i, surface: 'api' },
  { pattern: /\bsurface\s+in\s+\[.*?['"]cli['"].*?\]/i, surface: 'cli' },
  { pattern: /\bsurface\s+in\s+\[.*?['"]ide['"].*?\]/i, surface: 'ide' },
  { pattern: /\bsurface\s+in\s+\[.*?['"]api['"].*?\]/i, surface: 'api' },
];

/**
 * Detects governance parity gaps between enforcement surfaces (CLI, IDE, API).
 *
 * When organizations deploy governance policies, rules may be enforced
 * differently depending on the surface. This checker identifies rules
 * that only apply to some surfaces, highlighting enforcement gaps.
 */
export class SurfaceParityChecker {
  /**
   * Analyze a set of policies for surface parity gaps.
   */
  analyzePolicies(policies: Policy[]): SurfaceParityReport {
    const mappings: SurfaceRuleMapping[] = [];

    for (const policy of policies) {
      for (const rule of policy.rules) {
        if (rule.enabled === false) continue;

        const detected = this.detectSurfaces(rule);
        mappings.push({
          rule,
          policyName: policy.name,
          detectedSurfaces: detected,
          isUniversal: detected.length === 0,
        });
      }
    }

    const gaps = this.findGaps(mappings);
    const universalRules = mappings.filter((m) => m.isUniversal).length;
    const surfaceSpecificRules = mappings.length - universalRules;

    const surfaceCoverage = this.computeCoverage(mappings);
    const parityScore = this.computeParityScore(mappings, gaps);

    return {
      analyzedAt: new Date(),
      totalRules: mappings.length,
      universalRules,
      surfaceSpecificRules,
      gaps,
      mappings,
      surfaceCoverage,
      parityScore,
    };
  }

  /**
   * Detect which surfaces a rule targets.
   * Returns empty array for universal rules (no surface restriction).
   */
  detectSurfaces(rule: PolicyRule): GovernanceSurface[] {
    const surfaces = new Set<GovernanceSurface>();

    // Explicit surfaces field takes precedence
    if (rule.surfaces && rule.surfaces.length > 0) {
      return [...rule.surfaces];
    }

    // Parse condition string for surface references
    if (typeof rule.condition === 'string') {
      for (const { pattern, surface } of SURFACE_CONDITION_PATTERNS) {
        if (pattern.test(rule.condition)) {
          surfaces.add(surface);
        }
      }
    }

    // Check object-form conditions for surface keys
    if (rule.condition && typeof rule.condition === 'object') {
      const condObj = rule.condition as Record<string, unknown>;
      if (condObj.surface && typeof condObj.surface === 'string') {
        const val = condObj.surface.toLowerCase();
        if (KNOWN_SURFACES.includes(val as GovernanceSurface)) {
          surfaces.add(val as GovernanceSurface);
        }
      }
      if (condObj['context.surface'] && typeof condObj['context.surface'] === 'string') {
        const val = condObj['context.surface'].toLowerCase();
        if (KNOWN_SURFACES.includes(val as GovernanceSurface)) {
          surfaces.add(val as GovernanceSurface);
        }
      }
    }

    return [...surfaces];
  }

  /**
   * Find gaps by grouping surface-specific rules by their normalized semantics
   * and checking which surfaces are missing counterparts.
   */
  private findGaps(mappings: SurfaceRuleMapping[]): SurfaceGap[] {
    const gaps: SurfaceGap[] = [];
    const surfaceSpecific = mappings.filter((m) => !m.isUniversal);

    // Group by normalized key (action + non-surface conditions)
    const groups = new Map<string, SurfaceRuleMapping[]>();
    for (const mapping of surfaceSpecific) {
      const key = this.normalizeRuleKey(mapping.rule);
      const group = groups.get(key) ?? [];
      group.push(mapping);
      groups.set(key, group);
    }

    for (const [, group] of groups) {
      const coveredSurfaces = new Set<GovernanceSurface>();
      for (const m of group) {
        for (const s of m.detectedSurfaces) {
          coveredSurfaces.add(s);
        }
      }

      // Only flag gaps if rule exists for some surfaces but not all
      if (coveredSurfaces.size > 0 && coveredSurfaces.size < KNOWN_SURFACES.length) {
        const presentOn = [...coveredSurfaces];
        const missingFrom = KNOWN_SURFACES.filter((s) => !coveredSurfaces.has(s));
        const representative = group[0];
        const ruleAction = representative.rule.ruleAction;
        const severity = this.classifySeverity(ruleAction);

        gaps.push({
          ruleName: representative.rule.name ?? 'unnamed-rule',
          policyName: representative.policyName,
          presentOn,
          missingFrom,
          ruleAction,
          severity,
          recommendation: this.generateRecommendation(
            representative.rule.name ?? 'unnamed-rule',
            presentOn,
            missingFrom,
            ruleAction,
          ),
        });
      }
    }

    return gaps;
  }

  /**
   * Generate a normalized key for a rule based on its semantics
   * (action + non-surface conditions), so we can group rules that
   * do the same thing on different surfaces.
   */
  private normalizeRuleKey(rule: PolicyRule): string {
    const action = rule.ruleAction ?? rule.effect ?? 'unknown';
    const condStr = this.stripSurfaceFromCondition(rule);
    return `${action}::${condStr}`;
  }

  /**
   * Remove surface-related parts from a condition to get the
   * "semantic core" of a rule for comparison purposes.
   */
  private stripSurfaceFromCondition(rule: PolicyRule): string {
    if (typeof rule.condition === 'string') {
      let stripped = rule.condition;
      // Remove surface == 'x' clauses and surrounding connectives
      stripped = stripped.replace(/\bsurface\s*==\s*['"][^'"]*['"]/gi, '');
      stripped = stripped.replace(/\bcontext\.surface\s*==\s*['"][^'"]*['"]/gi, '');
      stripped = stripped.replace(/\bsurface\s+in\s+\[[^\]]*\]/gi, '');
      // Clean up dangling 'and'/'or'
      stripped = stripped.replace(/^\s*(and|or)\s+/i, '');
      stripped = stripped.replace(/\s+(and|or)\s*$/i, '');
      stripped = stripped.replace(/\s+(and|or)\s+(and|or)\s+/gi, ' and ');
      return stripped.trim() || (rule.name ?? '');
    }

    if (rule.condition && typeof rule.condition === 'object') {
      const condObj = { ...(rule.condition as Record<string, unknown>) };
      delete condObj.surface;
      delete condObj['context.surface'];
      return JSON.stringify(condObj);
    }

    return rule.name ?? rule.action ?? '';
  }

  private classifySeverity(action: PolicyAction | undefined): 'high' | 'medium' | 'low' {
    if (action === 'deny' || action === 'require_approval') return 'high';
    if (action === 'warn' || action === 'log') return 'medium';
    return 'low';
  }

  private generateRecommendation(
    ruleName: string,
    presentOn: GovernanceSurface[],
    missingFrom: GovernanceSurface[],
    action: PolicyAction | undefined,
  ): string {
    const present = presentOn.join(', ');
    const missing = missingFrom.join(', ');

    if (action === 'deny' || action === 'require_approval') {
      return (
        `Rule "${ruleName}" enforces ${action} on ${present} but not ${missing}. ` +
        `This creates a bypass path: users can avoid governance by switching surfaces.`
      );
    }

    return (
      `Rule "${ruleName}" applies on ${present} but not ${missing}. ` +
      `Consider extending coverage for consistent governance.`
    );
  }

  private computeCoverage(
    mappings: SurfaceRuleMapping[],
  ): Record<GovernanceSurface, number> {
    const coverage: Record<GovernanceSurface, number> = { cli: 0, ide: 0, api: 0, unknown: 0 };
    const universalCount = mappings.filter((m) => m.isUniversal).length;

    for (const surface of KNOWN_SURFACES) {
      const surfaceCount = mappings.filter(
        (m) => !m.isUniversal && m.detectedSurfaces.includes(surface),
      ).length;
      coverage[surface] = surfaceCount + universalCount;
    }

    return coverage;
  }

  /**
   * Compute a 0-100 parity score.
   * 100 = perfect parity (all rules are universal or all surfaces equally covered).
   * Deductions for each gap, weighted by severity.
   */
  private computeParityScore(
    mappings: SurfaceRuleMapping[],
    gaps: SurfaceGap[],
  ): number {
    if (mappings.length === 0) return 100;

    const severityWeights = { high: 15, medium: 8, low: 3 };
    let deductions = 0;
    for (const gap of gaps) {
      deductions += severityWeights[gap.severity] * gap.missingFrom.length;
    }

    return Math.max(0, Math.round(100 - deductions));
  }
}
