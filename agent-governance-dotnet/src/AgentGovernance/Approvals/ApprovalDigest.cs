// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AgentGovernance.Approvals;

/// <summary>
/// Produces deterministic RFC 8785-style JSON and SHA-256 digests for approval records.
/// Object members are ordered by UTF-16 code unit using ordinal string ordering.
/// </summary>
public static class ApprovalDigest
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Indented = false,
        SkipValidation = false
    };

    /// <summary>Returns the deterministic UTF-8 JSON representation of a value.</summary>
    /// <param name="value">A JSON-serializable value.</param>
    /// <returns>The canonical UTF-8 bytes.</returns>
    /// <exception cref="ApprovalProtocolException">The value cannot be represented safely.</exception>
    public static byte[] Canonicalize(object? value)
    {
        try
        {
            var element = value is JsonElement jsonElement
                ? jsonElement.Clone()
                : JsonSerializer.SerializeToElement(value, SerializerOptions);

            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer, WriterOptions))
            {
                WriteElement(writer, element);
            }

            return buffer.ToArray();
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException or ArgumentException)
        {
            throw new ApprovalProtocolException("Value cannot be canonicalized as JSON.", exception);
        }
    }

    /// <summary>Returns a lowercase <c>sha256:</c>-prefixed digest of a canonical value.</summary>
    /// <param name="value">A JSON-serializable value.</param>
    public static string Sha256(object? value)
    {
        var digest = SHA256.HashData(Canonicalize(value));
        return $"sha256:{Convert.ToHexString(digest).ToLowerInvariant()}";
    }

    private static void WriteElement(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                WriteObject(writer, element);
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteElement(writer, item);
                }

                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;
            case JsonValueKind.Number:
                WriteNumber(writer, element);
                break;
            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;
            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;
            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;
            default:
                throw new ApprovalProtocolException($"Unsupported JSON value kind '{element.ValueKind}'.");
        }
    }

    private static void WriteObject(Utf8JsonWriter writer, JsonElement element)
    {
        var properties = element.EnumerateObject().ToList();
        if (properties.Select(property => property.Name).Distinct(StringComparer.Ordinal).Count() != properties.Count)
        {
            throw new ApprovalProtocolException("Canonical JSON objects cannot contain duplicate property names.");
        }

        properties.Sort((left, right) => StringComparer.Ordinal.Compare(left.Name, right.Name));
        writer.WriteStartObject();
        foreach (var property in properties)
        {
            writer.WritePropertyName(property.Name);
            WriteElement(writer, property.Value);
        }

        writer.WriteEndObject();
    }

    private static void WriteNumber(Utf8JsonWriter writer, JsonElement element)
    {
        if (element.TryGetInt64(out var signed))
        {
            writer.WriteNumberValue(signed);
            return;
        }

        if (element.TryGetUInt64(out var unsigned))
        {
            writer.WriteNumberValue(unsigned);
            return;
        }

        if (element.TryGetDecimal(out var decimalValue))
        {
            if (decimalValue == decimal.Truncate(decimalValue) &&
                decimalValue >= long.MinValue &&
                decimalValue <= long.MaxValue)
            {
                writer.WriteNumberValue(decimal.ToInt64(decimalValue));
            }
            else
            {
                writer.WriteNumberValue(decimalValue);
            }

            return;
        }

        var doubleValue = element.GetDouble();
        if (!double.IsFinite(doubleValue))
        {
            throw new ApprovalProtocolException("NaN and Infinity cannot be canonicalized.");
        }

        writer.WriteNumberValue(doubleValue == 0d ? 0d : doubleValue);
    }
}
