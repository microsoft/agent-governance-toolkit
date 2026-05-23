// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

export function flattenText(value) {
  if (value === undefined || value === null) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value.map(flattenText).join("\n");
  }
  if (typeof value === "object") {
    return Object.values(value).map(flattenText).join("\n");
  }
  return "";
}

export function summarizeText(text, maxLength = 4000) {
  const normalized = flattenText(text).replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLength) {
    return normalized;
  }
  return `${normalized.slice(0, maxLength)}...`;
}

export function summarizeTextWindows(text, maxLength = 12000) {
  const normalized = flattenText(text).replace(/\s+/g, " ").trim();
  if (!normalized) {
    return [];
  }
  if (normalized.length <= maxLength) {
    return [normalized];
  }

  const windowSize = Math.max(Math.floor(maxLength / 4), 1000);
  const midStart = Math.max(Math.floor(normalized.length / 2) - Math.floor(windowSize / 2), 0);
  const tailStart = Math.max(normalized.length - windowSize, 0);

  return dedupeStrings([
    `${normalized.slice(0, windowSize)}...`,
    `...${normalized.slice(midStart, midStart + windowSize)}...`,
    `...${normalized.slice(tailStart)}`,
  ]);
}

export function safeJsonStringify(value, space = 0) {
  try {
    return JSON.stringify(value, null, space);
  } catch {
    return "[unserializable]";
  }
}

function dedupeStrings(values) {
  return [...new Set(values.filter(Boolean))];
}
