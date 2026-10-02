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

export function safeJsonStringify(value, space = 0) {
  try {
    return JSON.stringify(value, null, space);
  } catch {
    return "[unserializable]";
  }
}
