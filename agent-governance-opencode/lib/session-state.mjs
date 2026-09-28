// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const DEFAULT_MAX_SESSIONS = 1024;
const DEFAULT_MAX_PENDING_CALLS_PER_SESSION = 64;
const MAX_ATTRIBUTES = 128;
const MAX_RULES = 256;
const MAX_TRANSITIONS = 256;
const MAX_TOOL_NAMES = 64;
const MAX_ARGUMENT_KEYS = 32;
const MAX_REGEX_LENGTH = 2048;
const MAX_PENDING_ATTRIBUTE_REFERENCES_PER_SESSION = 256;
const MAX_RESTORED_QUARANTINED_SESSIONS = 10000;
const MAX_SESSION_ID_LENGTH = 256;
const MAX_CALL_ID_LENGTH = 256;
const DEFAULT_ARGUMENT_KEYS = ["filePath", "file_path", "path"];
const ATTRIBUTE_NAME_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const RULE_ID_PATTERN = /^[a-z][a-z0-9_-]{0,63}$/;
const DEFAULT_AGENT_ID = "opencode";

export function compileSessionStatePolicy(raw) {
  if (raw === undefined || raw === null) {
    return undefined;
  }
  if (!isRecord(raw)) {
    throw new Error("sessionState must be an object.");
  }

  const attributes = compileAttributeNames(raw.attributes, "sessionState.attributes");
  if (attributes.length === 0) {
    throw new Error("sessionState.attributes must include at least one monotonic attribute.");
  }
  const attributeSet = new Set(attributes);

  const transitions = compileTransitions(raw.transitions, attributeSet);
  const rules = compileRules(raw.rules, attributeSet);
  if (transitions.length === 0 || rules.length === 0) {
    throw new Error("sessionState requires at least one transition and one rule.");
  }

  return Object.freeze({
    attributes: Object.freeze(attributes),
    maxPendingCallsPerSession: compileInteger(
      raw.maxPendingCallsPerSession,
      DEFAULT_MAX_PENDING_CALLS_PER_SESSION,
      1,
      256,
      "sessionState.maxPendingCallsPerSession",
    ),
    maxSessions: compileInteger(
      raw.maxSessions,
      DEFAULT_MAX_SESSIONS,
      1,
      4096,
      "sessionState.maxSessions",
    ),
    rules: Object.freeze(rules),
    transitions: Object.freeze(transitions),
  });
}

export function restoreSessionStateFromAudit(policy, entries) {
  const allowedAttributes = new Set(policy.attributes);
  const sessions = new Map();
  const quarantinedSessionIds = new Set();
  const agentPrefix = `${DEFAULT_AGENT_ID}:`;

  for (const entry of entries) {
    if (
      typeof entry?.agentId !== "string" ||
      !entry.agentId.startsWith(agentPrefix) ||
      typeof entry.action !== "string"
    ) {
      continue;
    }

    const sessionId = entry.agentId.slice(agentPrefix.length);
    if (!isValidSessionId(sessionId)) {
      continue;
    }
    if (entry.action === "session.state.cleanup" && entry.decision === "allow") {
      sessions.delete(sessionId);
      quarantinedSessionIds.delete(sessionId);
      continue;
    }

    const match =
      /^session\.state\.(?:pending|set):([a-z][a-z0-9_]{0,63}(?:,[a-z][a-z0-9_]{0,63})*)$/.exec(
        entry.action,
      );
    const attributes = match?.[1]?.split(",");
    if (
      entry.decision !== "allow" ||
      !attributes?.length ||
      attributes.some((attribute) => !allowedAttributes.has(attribute))
    ) {
      continue;
    }

    if (quarantinedSessionIds.has(sessionId)) {
      continue;
    }

    let sessionAttributes = sessions.get(sessionId);
    if (!sessionAttributes) {
      if (sessions.size >= policy.maxSessions) {
        const oldestSessionId = sessions.keys().next().value;
        sessions.delete(oldestSessionId);
        quarantinedSessionIds.add(oldestSessionId);
        if (quarantinedSessionIds.size > MAX_RESTORED_QUARANTINED_SESSIONS) {
          throw new Error(
            `Restored session quarantine exceeds ${MAX_RESTORED_QUARANTINED_SESSIONS} sessions.`,
          );
        }
      }
      sessionAttributes = new Set();
    } else {
      sessions.delete(sessionId);
    }
    for (const attribute of attributes) {
      sessionAttributes.add(attribute);
    }
    sessions.set(sessionId, sessionAttributes);
  }

  return {
    quarantinedSessionIds: [...quarantinedSessionIds],
    sessions: [...sessions].map(([sessionId, attributes]) => ({
      attributes: [...attributes],
      sessionId,
    })),
  };
}

export function createSessionStateRuntime(
  policy,
  { restoredSessions = [], quarantinedSessionIds: restoredQuarantinedIds = [] } = {},
) {
  const sessions = new Map();
  const sessionQueues = new Map();
  const quarantinedSessionIds = new Set();
  const configuredAttributes = new Set(policy.attributes);

  if (
    !Array.isArray(restoredQuarantinedIds) ||
    restoredQuarantinedIds.length > MAX_RESTORED_QUARANTINED_SESSIONS
  ) {
    throw new Error(
      `Restored session quarantine must contain at most ${MAX_RESTORED_QUARANTINED_SESSIONS} session IDs.`,
    );
  }
  for (const sessionId of restoredQuarantinedIds) {
    if (!isValidSessionId(sessionId)) {
      throw new Error("The audit log contains an invalid quarantined session ID.");
    }
    quarantinedSessionIds.add(sessionId);
  }

  for (const restored of restoredSessions) {
    if (!isValidSessionId(restored?.sessionId)) {
      throw new Error("The audit log contains an invalid session-state session ID.");
    }
    if (quarantinedSessionIds.has(restored.sessionId)) {
      throw new Error("A session cannot be both restored and quarantined.");
    }

    const attributes = new Set(
      (Array.isArray(restored.attributes) ? restored.attributes : []).filter((attribute) =>
        configuredAttributes.has(attribute),
      ),
    );
    if (attributes.size === 0) {
      continue;
    }
    if (!sessions.has(restored.sessionId) && sessions.size >= policy.maxSessions) {
      throw new Error(
        `Restored session state exceeds sessionState.maxSessions (${policy.maxSessions}).`,
      );
    }

    const existing = sessions.get(restored.sessionId);
    if (existing) {
      for (const attribute of attributes) {
        existing.attributes.add(attribute);
      }
    } else {
      sessions.set(restored.sessionId, {
        attributes,
        pendingAttributeCount: 0,
        pendingCalls: new Map(),
        quarantinedReason: "",
      });
    }
  }

  function getEntry(sessionId, { create = false } = {}) {
    const id = requireSessionId(sessionId);
    if (quarantinedSessionIds.has(id)) {
      throw new Error(getQuarantinedSessionReason(id));
    }
    let entry = sessions.get(id);
    if (entry || !create) {
      return entry;
    }
    if (sessions.size >= policy.maxSessions) {
      throw new Error(
        `AGT session-state capacity reached (${policy.maxSessions} sessions); no active session state was evicted.`,
      );
    }

    entry = {
      attributes: new Set(),
      pendingAttributeCount: 0,
      pendingCalls: new Map(),
      quarantinedReason: "",
    };
    sessions.set(id, entry);
    return entry;
  }

  function withSessionLock(sessionId, operation) {
    const id = requireSessionId(sessionId);
    const previous = sessionQueues.get(id);
    let release;
    const queued = new Promise((resolve) => {
      release = resolve;
    });
    sessionQueues.set(id, queued);

    return (async () => {
      if (previous) {
        await previous;
      }
      try {
        return await operation();
      } finally {
        release();
        if (sessionQueues.get(id) === queued) {
          sessionQueues.delete(id);
        }
      }
    })();
  }

  function evaluateTool(sessionId, toolName) {
    const id = requireSessionId(sessionId);
    if (quarantinedSessionIds.has(id)) {
      return {
        decision: "deny",
        reason: getQuarantinedSessionReason(id),
      };
    }
    const entry = sessions.get(id);
    if (!entry) {
      return undefined;
    }
    if (entry.quarantinedReason) {
      return {
        decision: "deny",
        reason: entry.quarantinedReason,
      };
    }

    const activeAttributes = collectActiveAttributes(entry);
    let reviewMatch;
    for (const rule of policy.rules) {
      if (
        matchesToolName(rule.tools, toolName) &&
        rule.requires.every((attribute) => activeAttributes.has(attribute))
      ) {
        const result = {
          decision: rule.effect,
          reason: rule.reason,
        };
        if (result.decision === "deny") {
          return result;
        }
        reviewMatch ??= result;
      }
    }
    return reviewMatch;
  }

  function stageToolCall(sessionId, callId, toolName, args) {
    const id = requireSessionId(sessionId);
    if (quarantinedSessionIds.has(id)) {
      throw new Error(getQuarantinedSessionReason(id));
    }
    let entry = sessions.get(id);
    if (entry?.quarantinedReason) {
      throw new Error(entry.quarantinedReason);
    }

    const attributes = new Set();
    for (const transition of policy.transitions) {
      if (
        matchesToolName([transition.tool], toolName) &&
        matchesTransitionArguments(transition, args) &&
        !entry?.attributes.has(transition.attribute)
      ) {
        attributes.add(transition.attribute);
      }
    }
    if (attributes.size === 0) {
      return [];
    }
    const normalizedCallId = requireCallId(callId);
    if (!entry) {
      entry = getEntry(id, { create: true });
    }

    if (entry.pendingCalls.has(normalizedCallId)) {
      throw new Error("AGT could not stage session state for a duplicate OpenCode tool call ID.");
    }
    if (entry.pendingCalls.size >= policy.maxPendingCallsPerSession) {
      throw new Error(
        `AGT session-state pending-call limit reached (${policy.maxPendingCallsPerSession}); the tool call was denied.`,
      );
    }
    if (
      entry.pendingAttributeCount + attributes.size >
      MAX_PENDING_ATTRIBUTE_REFERENCES_PER_SESSION
    ) {
      throw new Error(
        `AGT session-state pending-attribute limit reached (${MAX_PENDING_ATTRIBUTE_REFERENCES_PER_SESSION}); the tool call was denied.`,
      );
    }

    const stagedAttributes = [...attributes].sort();
    entry.pendingCalls.set(normalizedCallId, new Set(stagedAttributes));
    entry.pendingAttributeCount += stagedAttributes.length;
    return stagedAttributes;
  }

  function completeToolCall(sessionId, callId) {
    if (quarantinedSessionIds.has(requireSessionId(sessionId))) {
      return [];
    }
    const entry = getEntry(sessionId);
    if (!entry) {
      return [];
    }

    const normalizedCallId = tryNormalizeCallId(callId);
    if (!normalizedCallId) {
      return [];
    }
    const pending = entry.pendingCalls.get(normalizedCallId);
    if (!pending) {
      return [];
    }

    entry.pendingCalls.delete(normalizedCallId);
    entry.pendingAttributeCount -= pending.size;
    const changed = [];
    for (const attribute of pending) {
      if (!entry.attributes.has(attribute)) {
        entry.attributes.add(attribute);
        changed.push(attribute);
      }
    }
    return changed.sort();
  }

  function finalizePendingCalls(sessionId) {
    if (quarantinedSessionIds.has(requireSessionId(sessionId))) {
      return [];
    }
    const entry = getEntry(sessionId);
    if (!entry || entry.pendingCalls.size === 0) {
      return [];
    }

    const changed = new Set();
    for (const attributes of entry.pendingCalls.values()) {
      for (const attribute of attributes) {
        if (!entry.attributes.has(attribute)) {
          entry.attributes.add(attribute);
          changed.add(attribute);
        }
      }
    }
    entry.pendingCalls.clear();
    entry.pendingAttributeCount = 0;
    return [...changed].sort();
  }

  function quarantineSession(sessionId, reason) {
    const entry = getEntry(sessionId, { create: true });
    entry.quarantinedReason =
      String(reason ?? "AGT session state could not be verified.")
        .trim()
        .slice(0, 512) || "AGT session state could not be verified.";
  }

  function removeSession(sessionId) {
    const id = requireSessionId(sessionId);
    if (quarantinedSessionIds.delete(id)) {
      return { hadState: true };
    }
    const entry = sessions.get(id);
    if (!entry) {
      return undefined;
    }

    const hadState = entry.attributes.size > 0 || entry.pendingCalls.size > 0;
    sessions.delete(id);
    return { hadState };
  }

  function snapshot(sessionId) {
    const id = requireSessionId(sessionId);
    if (quarantinedSessionIds.has(id)) {
      return Object.freeze({
        attributes: Object.freeze([]),
        pendingAttributes: Object.freeze([]),
        quarantined: true,
      });
    }
    const entry = getEntry(sessionId);
    if (!entry) {
      return undefined;
    }
    const pendingAttributes = collectPendingAttributes(entry);
    return Object.freeze({
      attributes: Object.freeze([...entry.attributes].sort()),
      pendingAttributes: Object.freeze([...pendingAttributes].sort()),
      quarantined: Boolean(entry.quarantinedReason),
    });
  }

  function status() {
    return Object.freeze({
      maxPendingCallsPerSession: policy.maxPendingCallsPerSession,
      maxPendingAttributesPerSession: MAX_PENDING_ATTRIBUTE_REFERENCES_PER_SESSION,
      maxSessions: policy.maxSessions,
      quarantinedSessions: quarantinedSessionIds.size,
      trackedSessions: sessions.size,
    });
  }

  return Object.freeze({
    completeToolCall,
    evaluateTool,
    finalizePendingCalls,
    quarantineSession,
    removeSession,
    snapshot,
    stageToolCall,
    status,
    withSessionLock,
  });
}

export function isValidSessionId(value) {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= MAX_SESSION_ID_LENGTH
  );
}

function compileAttributeNames(value, label) {
  if (!Array.isArray(value) || value.length > MAX_ATTRIBUTES) {
    throw new Error(`${label} must be an array with at most ${MAX_ATTRIBUTES} names.`);
  }

  const seen = new Set();
  return value.map((name, index) => {
    if (typeof name !== "string" || !ATTRIBUTE_NAME_PATTERN.test(name)) {
      throw new Error(
        `${label}[${index}] must match ${ATTRIBUTE_NAME_PATTERN.source}.`,
      );
    }
    if (seen.has(name)) {
      throw new Error(`${label} contains duplicate attribute '${name}'.`);
    }
    seen.add(name);
    return name;
  });
}

function compileTransitions(value, attributes) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value) || value.length > MAX_TRANSITIONS) {
    throw new Error(`sessionState.transitions must be an array with at most ${MAX_TRANSITIONS} entries.`);
  }

  const ids = new Set();
  return value.map((transition, index) => {
    if (!isRecord(transition)) {
      throw new Error(`sessionState.transitions[${index}] must be an object.`);
    }

    const id = compileRuleId(transition.id, `sessionState.transitions[${index}].id`);
    ensureUniqueId(ids, id, "sessionState.transitions");
    const tool = compileToolName(transition.tool, `sessionState.transitions[${index}].tool`);
    const attribute = transition.attribute;
    if (typeof attribute !== "string" || !attributes.has(attribute)) {
      throw new Error(
        `sessionState.transitions[${index}].attribute must name a declared attribute.`,
      );
    }

    const pathPatterns =
      transition.pathPatterns === undefined
        ? []
        : compilePatterns(
            transition.pathPatterns,
            `sessionState.transitions[${index}].pathPatterns`,
          );
    const argumentKeys =
      pathPatterns.length === 0
        ? []
        : compileArgumentKeys(
            transition.argumentKeys,
            `sessionState.transitions[${index}].argumentKeys`,
          );

    return Object.freeze({
      argumentKeys: Object.freeze(argumentKeys),
      attribute,
      id,
      pathPatterns: Object.freeze(pathPatterns),
      tool,
    });
  });
}

function compileRules(value, attributes) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value) || value.length > MAX_RULES) {
    throw new Error(`sessionState.rules must be an array with at most ${MAX_RULES} entries.`);
  }

  const ids = new Set();
  return value.map((rule, index) => {
    if (!isRecord(rule)) {
      throw new Error(`sessionState.rules[${index}] must be an object.`);
    }

    const id = compileRuleId(rule.id, `sessionState.rules[${index}].id`);
    ensureUniqueId(ids, id, "sessionState.rules");
    const tools = compileToolNames(rule.tools, `sessionState.rules[${index}].tools`);
    const requires = compileAttributeNames(rule.requires, `sessionState.rules[${index}].requires`);
    if (requires.length === 0) {
      throw new Error(`sessionState.rules[${index}].requires must not be empty.`);
    }
    for (const attribute of requires) {
      if (!attributes.has(attribute)) {
        throw new Error(
          `sessionState.rules[${index}].requires references undeclared attribute '${attribute}'.`,
        );
      }
    }

    const effect = String(rule.effect ?? "").trim().toLowerCase();
    if (effect !== "deny" && effect !== "review") {
      throw new Error(
        `sessionState.rules[${index}].effect must be either "deny" or "review".`,
      );
    }
    const reason = String(rule.reason ?? "").trim();
    if (!reason) {
      throw new Error(`sessionState.rules[${index}].reason must not be empty.`);
    }

    return Object.freeze({
      effect,
      id,
      reason,
      requires: Object.freeze(requires),
      tools: Object.freeze(tools),
    });
  });
}

function compilePatterns(value, label) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 128) {
    throw new Error(`${label} must be an array of 1-128 regex pattern objects.`);
  }

  return value.map((pattern, index) => {
    if (!isRecord(pattern)) {
      throw new Error(`${label}[${index}] must be a regex pattern object.`);
    }
    if (
      typeof pattern.source !== "string" ||
      !pattern.source.trim() ||
      pattern.source.length > MAX_REGEX_LENGTH
    ) {
      throw new Error(
        `${label}[${index}].source must be a non-empty string of at most ${MAX_REGEX_LENGTH} characters.`,
      );
    }
    const flags = pattern.flags === undefined ? "" : pattern.flags;
    if (
      typeof flags !== "string" ||
      [...flags].some((flag) => flag !== "i" && flag !== "u")
    ) {
      throw new Error(`${label}[${index}].flags may contain only "i" and "u".`);
    }

    let regex;
    try {
      regex = new RegExp(pattern.source, flags);
    } catch (error) {
      throw new Error(
        `${label}[${index}] contains an invalid regular expression: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }

    return Object.freeze({ regex, source: pattern.source, flags });
  });
}

function compileArgumentKeys(value, label) {
  if (value === undefined || value === null) {
    return DEFAULT_ARGUMENT_KEYS.map((key) => key.toLowerCase());
  }
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_ARGUMENT_KEYS) {
    throw new Error(`${label} must be an array with 1-${MAX_ARGUMENT_KEYS} argument keys.`);
  }

  const keys = new Set();
  for (const [index, key] of value.entries()) {
    if (typeof key !== "string" || !/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(key)) {
      throw new Error(`${label}[${index}] must be a valid top-level argument key.`);
    }
    keys.add(key.toLowerCase());
  }
  return [...keys];
}

function compileToolNames(value, label) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_TOOL_NAMES) {
    throw new Error(`${label} must be an array with 1-${MAX_TOOL_NAMES} tool names.`);
  }

  const names = new Set();
  for (const [index, tool] of value.entries()) {
    const name = compileToolName(tool, `${label}[${index}]`);
    names.add(name.toLowerCase());
  }
  return [...names];
}

function compileToolName(value, label) {
  if (typeof value !== "string" || !value.trim() || value.length > 128) {
    throw new Error(`${label} must be a non-empty tool name of at most 128 characters.`);
  }
  return value.trim();
}

function compileRuleId(value, label) {
  if (typeof value !== "string" || !RULE_ID_PATTERN.test(value)) {
    throw new Error(`${label} must match ${RULE_ID_PATTERN.source}.`);
  }
  return value;
}

function ensureUniqueId(ids, id, label) {
  if (ids.has(id)) {
    throw new Error(`${label} contains duplicate id '${id}'.`);
  }
  ids.add(id);
}

function compileInteger(value, fallback, minimum, maximum, label) {
  if (value === undefined || value === null) {
    return fallback;
  }
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum}.`);
  }
  return value;
}

function matchesTransitionArguments(transition, args) {
  if (transition.pathPatterns.length === 0) {
    return true;
  }
  if (!isRecord(args)) {
    return false;
  }

  for (const [key, value] of Object.entries(args)) {
    if (typeof value !== "string" || !transition.argumentKeys.includes(key.toLowerCase())) {
      continue;
    }
    const normalizedPath = value.trim().replace(/\\/g, "/");
    if (
      normalizedPath &&
      transition.pathPatterns.some((pattern) => pattern.regex.test(normalizedPath))
    ) {
      return true;
    }
  }
  return false;
}

function matchesToolName(expectedTools, actualTool) {
  const normalized = String(actualTool ?? "").toLowerCase();
  return expectedTools.some((tool) => tool === "*" || tool.toLowerCase() === normalized);
}

function collectActiveAttributes(entry) {
  const attributes = new Set(entry.attributes);
  for (const pending of entry.pendingCalls.values()) {
    for (const attribute of pending) {
      attributes.add(attribute);
    }
  }
  return attributes;
}

function collectPendingAttributes(entry) {
  const attributes = new Set();
  for (const pending of entry.pendingCalls.values()) {
    for (const attribute of pending) {
      attributes.add(attribute);
    }
  }
  return attributes;
}

function requireSessionId(sessionId) {
  if (!isValidSessionId(sessionId)) {
    throw new Error(
      `AGT session-scoped policy requires a non-empty OpenCode session ID no longer than ${MAX_SESSION_ID_LENGTH} characters.`,
    );
  }
  return sessionId;
}

function getQuarantinedSessionReason(sessionId) {
  return `AGT session state for '${sessionId}' was not restored because the configured session capacity was exceeded. Delete this OpenCode session to release its quarantine.`;
}

function requireCallId(callId) {
  const normalized = tryNormalizeCallId(callId);
  if (!normalized) {
    throw new Error(
      `AGT could not stage session state without a non-empty OpenCode tool call ID no longer than ${MAX_CALL_ID_LENGTH} characters.`,
    );
  }
  return normalized;
}

function tryNormalizeCallId(callId) {
  return typeof callId === "string" &&
    callId.trim().length > 0 &&
    callId.length <= MAX_CALL_ID_LENGTH
    ? callId
    : "";
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
