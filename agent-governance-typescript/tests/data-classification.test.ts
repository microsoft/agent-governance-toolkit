// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import {
  DataClassification,
  isDataClassification,
  maximumClassification,
  requireDataClassification,
} from '../src/data-classification';

describe('DataClassification', () => {
  it('orders the levels most public first', () => {
    expect(DataClassification.Public).toBeLessThan(DataClassification.Internal);
    expect(DataClassification.Internal).toBeLessThan(DataClassification.Confidential);
    expect(DataClassification.Confidential).toBeLessThan(DataClassification.Restricted);
    expect(DataClassification.Restricted).toBeLessThan(DataClassification.TopSecret);
  });

  describe('isDataClassification()', () => {
    it('accepts every defined level', () => {
      for (const level of [
        DataClassification.Public,
        DataClassification.Internal,
        DataClassification.Confidential,
        DataClassification.Restricted,
        DataClassification.TopSecret,
      ]) {
        expect(isDataClassification(level)).toBe(true);
      }
    });

    it('rejects numbers outside the ladder', () => {
      expect(isDataClassification(-1)).toBe(false);
      expect(isDataClassification(5)).toBe(false);
      expect(isDataClassification(1.5)).toBe(false);
      expect(isDataClassification(Infinity)).toBe(false);
    });

    it('rejects NaN and the loose values a lookup can produce', () => {
      expect(isDataClassification(NaN)).toBe(false);
      expect(isDataClassification(undefined)).toBe(false);
      expect(isDataClassification(null)).toBe(false);
      expect(isDataClassification('2')).toBe(false);
    });
  });

  describe('requireDataClassification()', () => {
    it('returns defined values unchanged', () => {
      expect(requireDataClassification(DataClassification.Restricted, 'x')).toBe(
        DataClassification.Restricted,
      );
    });

    it('throws a RangeError naming the offending parameter', () => {
      expect(() => requireDataClassification(7 as DataClassification, 'newSensitivity')).toThrow(
        RangeError,
      );
      expect(() => requireDataClassification(7 as DataClassification, 'newSensitivity')).toThrow(
        /newSensitivity/,
      );
      expect(() => requireDataClassification(undefined as never, 'aggregateSensitivity')).toThrow(
        /aggregateSensitivity/,
      );
    });
  });

  describe('maximumClassification()', () => {
    it('returns the higher of two levels', () => {
      expect(maximumClassification(DataClassification.Public, DataClassification.Restricted)).toBe(
        DataClassification.Restricted,
      );
      expect(maximumClassification(DataClassification.TopSecret, DataClassification.Internal)).toBe(
        DataClassification.TopSecret,
      );
    });

    it('refuses to fold an undefined level, which would poison the max', () => {
      expect(() =>
        maximumClassification(DataClassification.Restricted, NaN as DataClassification),
      ).toThrow(RangeError);
      expect(() =>
        maximumClassification(undefined as never, DataClassification.Restricted),
      ).toThrow(RangeError);
    });
  });
});
