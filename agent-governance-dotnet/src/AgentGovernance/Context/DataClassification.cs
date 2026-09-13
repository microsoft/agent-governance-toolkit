// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentGovernance.Context;

/// <summary>
/// Ordered sensitivity levels for accumulated governance context.
/// </summary>
public enum DataClassification
{
    /// <summary>Public data.</summary>
    Public = 0,

    /// <summary>Internal data.</summary>
    Internal = 1,

    /// <summary>Confidential data.</summary>
    Confidential = 2,

    /// <summary>Restricted data.</summary>
    Restricted = 3,

    /// <summary>Top-secret data.</summary>
    TopSecret = 4
}

internal static class DataClassificationGuard
{
    internal static DataClassification Defined(
        DataClassification classification,
        string parameterName)
    {
        if (!Enum.IsDefined(classification))
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                classification,
                "Classification must be a defined DataClassification value.");
        }

        return classification;
    }

    internal static DataClassification Maximum(
        DataClassification left,
        DataClassification right) =>
        (DataClassification)Math.Max(
            (int)Defined(left, nameof(left)),
            (int)Defined(right, nameof(right)));
}
