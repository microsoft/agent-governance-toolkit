// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/** Sensitivity levels for data classification, ordered by sensitivity (higher = more sensitive). */
export enum DataClassification {
  PUBLIC = 0,
  INTERNAL = 1,
  CONFIDENTIAL = 2,
  RESTRICTED = 3,
  TOP_SECRET = 4,
}

/** Label describing data sensitivity and handling requirements. */
export interface DataLabel {
  classification: DataClassification;
  categories: string[];
  owner: string;
  retentionDays: number;
  geography: string;
}

export function makeDataLabel(overrides: Partial<DataLabel> = {}): DataLabel {
  return {
    classification: DataClassification.PUBLIC,
    categories: [],
    owner: '',
    retentionDays: 90,
    geography: '',
    ...overrides,
  };
}

/** Attribute-Based Access Control policy for an agent. */
export interface ABACPolicy {
  agentId: string;
  allowedClassifications: DataClassification[];
  allowedCategories: string[];
  deniedCategories: string[];
  requiredGeography: string | null;
  maxClassification: DataClassification;
}

export function makeABACPolicy(overrides: Partial<ABACPolicy> & { agentId: string }): ABACPolicy {
  return {
    allowedClassifications: [],
    allowedCategories: [],
    deniedCategories: [],
    requiredGeography: null,
    maxClassification: DataClassification.PUBLIC,
    ...overrides,
  };
}

/** Result of evaluating an agent's data access request. */
export interface DataAccessDecision {
  allowed: boolean;
  reason: string;
  agentId: string;
  dataLabel: DataLabel;
  matchedPolicy: string | null;
  evaluatedAt: Date;
}

/** Evaluates agent data-access requests against ABAC policies. Deny takes precedence. */
export class DataAccessEvaluator {
  constructor(private readonly _policies: ABACPolicy[]) {}

  evaluate(agentId: string, dataLabel: DataLabel): DataAccessDecision {
    const agentPolicies = this._policies.filter((p) => p.agentId === agentId);
    if (agentPolicies.length === 0) {
      return {
        allowed: false,
        reason: 'No ABAC policy registered for agent',
        agentId,
        dataLabel,
        matchedPolicy: null,
        evaluatedAt: new Date(),
      };
    }

    for (const policy of agentPolicies) {
      const decision = evaluateSingle(agentId, dataLabel, policy);
      if (!decision.allowed) return decision;
    }

    return {
      allowed: true,
      reason: 'Access permitted by all applicable policies',
      agentId,
      dataLabel,
      matchedPolicy: agentPolicies[0].agentId,
      evaluatedAt: new Date(),
    };
  }
}

function evaluateSingle(
  agentId: string,
  dataLabel: DataLabel,
  policy: ABACPolicy,
): DataAccessDecision {
  const base = { agentId, dataLabel, matchedPolicy: policy.agentId, evaluatedAt: new Date() };

  if (dataLabel.classification > policy.maxClassification) {
    return {
      ...base,
      allowed: false,
      reason: `Classification ${DataClassification[dataLabel.classification]} exceeds max ${DataClassification[policy.maxClassification]}`,
    };
  }

  if (
    policy.allowedClassifications.length > 0 &&
    !policy.allowedClassifications.includes(dataLabel.classification)
  ) {
    return {
      ...base,
      allowed: false,
      reason: `Classification ${DataClassification[dataLabel.classification]} not in allowed list`,
    };
  }

  for (const cat of dataLabel.categories) {
    if (policy.deniedCategories.includes(cat)) {
      return { ...base, allowed: false, reason: `Category '${cat}' is explicitly denied` };
    }
  }

  if (policy.allowedCategories.length > 0) {
    for (const cat of dataLabel.categories) {
      if (!policy.allowedCategories.includes(cat)) {
        return { ...base, allowed: false, reason: `Category '${cat}' not in allowed categories` };
      }
    }
  }

  // When requiredGeography is set, an absent/empty geography label must also deny:
  // unlabeled data must not bypass the geography restriction.
  if (policy.requiredGeography && dataLabel.geography !== policy.requiredGeography) {
    return {
      ...base,
      allowed: false,
      reason: dataLabel.geography
        ? `Geography '${dataLabel.geography}' does not match required '${policy.requiredGeography}'`
        : `Geography label absent but policy requires '${policy.requiredGeography}'`,
    };
  }

  return { ...base, allowed: true, reason: 'Policy passed' };
}

// ---------------------------------------------------------------------------
// PII / PHI / PCI detection helpers
// ---------------------------------------------------------------------------

const _SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/;
const _EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
const _PHONE_RE = /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/;

const _MRN_RE = /\bMRN[-:\s]*\d{6,10}\b/i;
const _ICD_RE = /\b[A-Z]\d{2}(?:\.\d{1,4})?\b/;

const _CC_RE = /\b(?:\d[ -]*?){13,19}\b/;

export function detectPii(text: string): string[] {
  const findings: string[] = [];
  if (_SSN_RE.test(text)) findings.push('SSN');
  if (_EMAIL_RE.test(text)) findings.push('email');
  if (_PHONE_RE.test(text)) findings.push('phone');
  return findings;
}

export function detectPhi(text: string): string[] {
  const findings: string[] = [];
  if (_MRN_RE.test(text)) findings.push('MRN');
  if (_ICD_RE.test(text)) findings.push('ICD-code');
  return findings;
}

export function detectPci(text: string): string[] {
  const findings: string[] = [];
  if (_CC_RE.test(text)) findings.push('credit-card');
  return findings;
}

export function classifyText(text: string): DataLabel {
  const categories: string[] = [];
  let classification = DataClassification.PUBLIC;

  if (detectPii(text).length > 0) {
    categories.push('PII');
    classification = Math.max(classification, DataClassification.CONFIDENTIAL);
  }
  if (detectPhi(text).length > 0) {
    categories.push('PHI');
    classification = Math.max(classification, DataClassification.RESTRICTED);
  }
  if (detectPci(text).length > 0) {
    categories.push('PCI');
    classification = Math.max(classification, DataClassification.CONFIDENTIAL);
  }

  return makeDataLabel({ classification, categories });
}
