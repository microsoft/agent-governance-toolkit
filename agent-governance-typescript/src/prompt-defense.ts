// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHash } from 'crypto';

type Severity = 'critical' | 'high' | 'medium' | 'low';

interface DefenseRule {
  vectorId: string;
  name: string;
  owasp: string;
  patterns: RegExp[];
  minMatches: number;
  severity: Severity;
}

export interface PromptDefenseFinding {
  vectorId: string;
  name: string;
  owasp: string;
  defended: boolean;
  confidence: number;
  severity: Severity;
  evidence: string;
  matchedPatterns: number;
  requiredPatterns: number;
}

export interface PromptDefenseReport {
  grade: string;
  score: number;
  defended: number;
  total: number;
  coverage: string;
  missing: string[];
  findings: PromptDefenseFinding[];
  promptHash: string;
  evaluatedAt: string;
  isBlocking(minGrade?: string): boolean;
}

export interface PromptDefenseConfig {
  minGrade?: string;
  vectors?: string[];
}

const GRADE_THRESHOLDS: Array<[string, number]> = [
  ['A', 90],
  ['B', 70],
  ['C', 50],
  ['D', 30],
  ['F', 0],
];

const DEFENSE_RULES: DefenseRule[] = [
  {
    vectorId: 'role-escape',
    name: 'Role Boundary',
    owasp: 'LLM01',
    patterns: [
      /(?:you are|your role|act as|serve as|function as)/i,
      /(?:stay in (?:character|role)|maintain.*(?:role|identity|persona)|only (?:answer|respond|act) as)/i,
    ],
    minMatches: 1,
    severity: 'high',
  },
  {
    vectorId: 'instruction-override',
    name: 'Instruction Boundary',
    owasp: 'LLM01',
    patterns: [
      /(?:do not|never|must not|cannot|should not|refuse|reject|decline)/i,
      /(?:ignore (?:any|all)|disregard|override)/i,
    ],
    minMatches: 1,
    severity: 'high',
  },
  {
    vectorId: 'data-leakage',
    name: 'Data Protection',
    owasp: 'LLM07',
    patterns: [
      /(?:do not (?:reveal|share|disclose|expose|output)|never (?:reveal|share|disclose|show)|keep.*(?:secret|confidential|private))/i,
      /(?:system prompt|internal|instruction|training|behind the scenes)/i,
    ],
    minMatches: 1,
    severity: 'critical',
  },
  {
    vectorId: 'output-manipulation',
    name: 'Output Control',
    owasp: 'LLM02',
    patterns: [
      /(?:only (?:respond|reply|output|answer) (?:in|with|as)|format.*(?:as|in|using)|response (?:format|style))/i,
      /(?:do not (?:generate|create|produce|output)|never (?:generate|produce))/i,
    ],
    minMatches: 1,
    severity: 'medium',
  },
  {
    vectorId: 'multilang-bypass',
    name: 'Multi-language Protection',
    owasp: 'LLM01',
    patterns: [
      /(?:only (?:respond|reply|answer|communicate) in|respond in (?:english|chinese|japanese)|language)/i,
      /(?:regardless of (?:the )?(?:input |user )?language)/i,
    ],
    minMatches: 1,
    severity: 'medium',
  },
  {
    vectorId: 'unicode-attack',
    name: 'Unicode Protection',
    owasp: 'LLM01',
    patterns: [/(?:unicode|homoglyph|special character|character encoding)/i],
    minMatches: 1,
    severity: 'low',
  },
  {
    vectorId: 'context-overflow',
    name: 'Length Limits',
    owasp: 'LLM01',
    patterns: [/(?:max(?:imum)?.*(?:length|char|token|word)|limit.*(?:input|length|size|token)|truncat)/i],
    minMatches: 1,
    severity: 'low',
  },
  {
    vectorId: 'indirect-injection',
    name: 'Indirect Injection Protection',
    owasp: 'LLM01',
    patterns: [
      /(?:external (?:data|content|source|input)|user.?(?:provided|supplied|submitted|generated)|third.?party|untrusted)/i,
      /(?:(?:validate|verify|sanitize|filter|check).*(?:external|input|data|content)|treat.*(?:as (?:data|untrusted|information))|do not (?:follow|execute|obey).*(?:instruction|command).*(?:from|in|within|embedded))/i,
    ],
    minMatches: 1,
    severity: 'critical',
  },
  {
    vectorId: 'social-engineering',
    name: 'Social Engineering Defense',
    owasp: 'LLM01',
    patterns: [/(?:emotional|urgency|pressure|threaten|guilt|manipulat)/i, /(?:regardless of|no matter|even if)/i],
    minMatches: 1,
    severity: 'medium',
  },
  {
    vectorId: 'output-weaponization',
    name: 'Harmful Content Prevention',
    owasp: 'LLM02',
    patterns: [
      /(?:harmful|illegal|dangerous|malicious|weapon|violence|exploit|phishing)/i,
      /(?:do not (?:help|assist|generate|create).*(?:harm|illegal|danger|weapon))/i,
    ],
    minMatches: 1,
    severity: 'high',
  },
  {
    vectorId: 'abuse-prevention',
    name: 'Abuse Prevention',
    owasp: 'LLM06',
    patterns: [
      /(?:abuse|misuse|exploit|attack|inappropriate|spam|flood)/i,
      /(?:rate limit|throttl|quota|maximum.*request)/i,
      /(?:authenticat|authoriz|permission|access control|api.?key|token)/i,
    ],
    minMatches: 1,
    severity: 'medium',
  },
  {
    vectorId: 'input-validation',
    name: 'Input Validation',
    owasp: 'LLM01',
    patterns: [
      /(?:validate|sanitize|filter|clean|escape|strip|check.*input|input.*(?:validation|check))/i,
      /(?:sql|xss|injection|script|html|special char|malicious)/i,
    ],
    minMatches: 1,
    severity: 'high',
  },
];

const MAX_PROMPT_LENGTH = 100_000;

class PromptDefenseReportImpl implements PromptDefenseReport {
  constructor(
    readonly grade: string,
    readonly score: number,
    readonly defended: number,
    readonly total: number,
    readonly coverage: string,
    readonly missing: string[],
    readonly findings: PromptDefenseFinding[],
    readonly promptHash: string,
    readonly evaluatedAt: string,
  ) {}

  isBlocking(minGrade: string = 'C'): boolean {
    const order: Record<string, number> = { A: 5, B: 4, C: 3, D: 2, F: 1 };
    return (order[this.grade] ?? 0) < (order[minGrade] ?? 3);
  }
}

export class PromptDefenseEvaluator {
  private readonly rules: DefenseRule[];

  constructor(config: PromptDefenseConfig = {}) {
    this.rules = config.vectors
      ? DEFENSE_RULES.filter((rule) => config.vectors?.includes(rule.vectorId))
      : DEFENSE_RULES;
  }

  evaluate(prompt: string): PromptDefenseReport {
    if (prompt.length > MAX_PROMPT_LENGTH) {
      throw new Error(`Prompt length ${prompt.length} exceeds maximum ${MAX_PROMPT_LENGTH}`);
    }

    const findings = this.rules.map((rule) => this.evaluateRule(rule, prompt));
    const defended = findings.filter((finding) => finding.defended).length;
    const total = findings.length;
    const score = total > 0 ? Math.round((defended / total) * 100) : 0;
    const missing = findings.filter((finding) => !finding.defended).map((finding) => finding.vectorId);

    return new PromptDefenseReportImpl(
      this.scoreToGrade(score),
      score,
      defended,
      total,
      `${defended}/${total}`,
      missing,
      findings,
      createHash('sha256').update(prompt, 'utf8').digest('hex'),
      new Date().toISOString(),
    );
  }

  private evaluateRule(rule: DefenseRule, prompt: string): PromptDefenseFinding {
    let matched = 0;
    let evidence = '';

    for (const pattern of rule.patterns) {
      const match = pattern.exec(prompt);
      if (match) {
        matched += 1;
        if (!evidence) {
          evidence = match[0].slice(0, 60);
        }
      }
    }

    const defended = matched >= rule.minMatches;
    const confidence = defended
      ? Math.min(0.9, 0.5 + matched * 0.2)
      : matched > 0
        ? 0.4
        : 0.8;

    return {
      vectorId: rule.vectorId,
      name: rule.name,
      owasp: rule.owasp,
      defended,
      confidence,
      severity: rule.severity,
      evidence: defended
        ? `Found: "${evidence}"`
        : matched > 0
          ? `Partial: ${matched}/${rule.minMatches} pattern(s)`
          : 'No defense pattern found',
      matchedPatterns: matched,
      requiredPatterns: rule.minMatches,
    };
  }

  private scoreToGrade(score: number): string {
    for (const [grade, threshold] of GRADE_THRESHOLDS) {
      if (score >= threshold) {
        return grade;
      }
    }

    return 'F';
  }
}
