// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Data sensitivity ladder for accumulated context governance.
 *
 * Ported from the Python reference (`agent_os/policies/data_classification.py`)
 * for issue #3084, so the TypeScript SDK can accumulate and evaluate workflow
 * context with the same sensitivity semantics as the Python, .NET and Rust SDKs.
 */

/**
 * Ordered sensitivity levels. The numeric value is the ordering: aggregation
 * keeps the maximum, and a higher level always outranks a lower one.
 */
export enum DataClassification {
  Public = 0,
  Internal = 1,
  Confidential = 2,
  Restricted = 3,
  TopSecret = 4,
}

const DEFINED_CLASSIFICATIONS: readonly DataClassification[] = [
  DataClassification.Public,
  DataClassification.Internal,
  DataClassification.Confidential,
  DataClassification.Restricted,
  DataClassification.TopSecret,
];

/**
 * Whether `value` is one of the five defined levels.
 *
 * A TypeScript numeric enum is open at runtime: `const x: DataClassification = 99`
 * compiles, and `NaN`/`undefined` pass through comparisons. Left unchecked they
 * poison `Math.max`, so an envelope could report a lower sensitivity than the data
 * it actually holds and a restricted export would go through.
 */
export function isDataClassification(value: unknown): value is DataClassification {
  return (
    typeof value === 'number' &&
    DEFINED_CLASSIFICATIONS.some((defined) => defined === value)
  );
}

/** Returns `value` if it is a defined level, throws otherwise. */
export function requireDataClassification(
  value: DataClassification,
  parameterName: string,
): DataClassification {
  if (!isDataClassification(value)) {
    throw new RangeError(
      `${parameterName} must be a defined DataClassification value, received ${String(value)}.`,
    );
  }
  return value;
}

/** The higher of two defined levels. */
export function maximumClassification(
  left: DataClassification,
  right: DataClassification,
): DataClassification {
  return Math.max(
    requireDataClassification(left, 'left'),
    requireDataClassification(right, 'right'),
  ) as DataClassification;
}
