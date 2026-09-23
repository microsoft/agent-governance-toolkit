// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Buffers;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AgentGovernance.Audit;

/// <summary>
/// Skill metadata explicitly supplied from framework-owned state.
/// </summary>
public sealed class TrustedSkillMetadataSource
{
    private TrustedSkillMetadataSource(string? skillName, string? skillOrigin)
    {
        SkillName = Normalize(skillName);
        SkillOrigin = Normalize(skillOrigin);
    }

    /// <summary>
    /// The framework-owned skill name, when available.
    /// </summary>
    public string? SkillName { get; }

    /// <summary>
    /// The framework-owned skill origin, when available.
    /// </summary>
    public string? SkillOrigin { get; }

    /// <summary>
    /// Creates a trusted source after trimming empty values.
    /// </summary>
    public static TrustedSkillMetadataSource? Create(string? skillName = null, string? skillOrigin = null)
    {
        var source = new TrustedSkillMetadataSource(skillName, skillOrigin);
        return source.SkillName is null && source.SkillOrigin is null ? null : source;
    }

    private static string? Normalize(string? value)
    {
        var normalized = value?.Trim();
        return string.IsNullOrEmpty(normalized) ? null : normalized;
    }
}

/// <summary>
/// Normalized skill provenance and hashes attached to a governance audit event.
/// </summary>
public sealed class SkillAuditMetadata
{
    internal SkillAuditMetadata(
        string? skillName,
        string? skillOrigin,
        string? provenanceSourceTrust,
        string? contextHashBefore,
        string? contextHashAfter)
    {
        SkillName = skillName;
        SkillOrigin = skillOrigin;
        ProvenanceSourceTrust = provenanceSourceTrust;
        ContextHashBefore = contextHashBefore;
        ContextHashAfter = contextHashAfter;
    }

    /// <summary>
    /// The trusted skill name, when available.
    /// </summary>
    public string? SkillName { get; }

    /// <summary>
    /// The trusted skill origin, when available.
    /// </summary>
    public string? SkillOrigin { get; }

    /// <summary>
    /// Trust marker set only when framework-owned skill metadata is present.
    /// </summary>
    public string? ProvenanceSourceTrust { get; }

    /// <summary>
    /// SHA-256 hash of the context before the governed operation.
    /// </summary>
    public string? ContextHashBefore { get; }

    /// <summary>
    /// SHA-256 hash of the context after the governed operation.
    /// </summary>
    public string? ContextHashAfter { get; }

    internal Dictionary<string, object> ToAuditData()
    {
        var data = new Dictionary<string, object>();
        Add(data, "skill_name", SkillName);
        Add(data, "skill_origin", SkillOrigin);
        Add(data, "provenance_source_trust", ProvenanceSourceTrust);
        Add(data, "context_hash_before", ContextHashBefore);
        Add(data, "context_hash_after", ContextHashAfter);
        return data;
    }

    private static void Add(Dictionary<string, object> data, string key, string? value)
    {
        if (value is not null)
        {
            data[key] = value;
        }
    }
}

/// <summary>
/// Builds privacy-preserving skill audit metadata from trusted sources and context snapshots.
/// </summary>
public static class SkillAuditMetadataBuilder
{
    /// <summary>
    /// Builds audit metadata. Skill fields are taken only from
    /// <paramref name="trustedSource"/>; context values are hashed but never parsed for skill data.
    /// </summary>
    public static SkillAuditMetadata? Build(
        TrustedSkillMetadataSource? trustedSource,
        object? contextBefore = null,
        object? contextAfter = null)
    {
        var skillName = trustedSource?.SkillName;
        var skillOrigin = trustedSource?.SkillOrigin;
        var contextHashBefore = HashContext(contextBefore);
        var contextHashAfter = HashContext(contextAfter);

        if (skillName is null && skillOrigin is null &&
            contextHashBefore is null && contextHashAfter is null)
        {
            return null;
        }

        var provenanceSourceTrust = skillName is not null || skillOrigin is not null
            ? "trusted"
            : null;

        return new SkillAuditMetadata(
            skillName,
            skillOrigin,
            provenanceSourceTrust,
            contextHashBefore,
            contextHashAfter);
    }

    /// <summary>
    /// Returns a deterministic SHA-256 hash, or no hash when the context cannot be
    /// represented as canonical JSON.
    /// </summary>
    public static string? HashContext(object? context)
    {
        if (context is null)
        {
            return null;
        }

        JsonElement value;
        try
        {
            value = JsonSerializer.SerializeToElement(context, context.GetType());
        }
        catch (Exception exception) when (
            exception is JsonException or NotSupportedException or InvalidOperationException)
        {
            return null;
        }

        if (value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
        }

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(
                   buffer,
                   new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            WriteCanonicalJson(writer, value);
            writer.Flush();
        }

        return Convert.ToHexString(SHA256.HashData(buffer.WrittenSpan)).ToLowerInvariant();
    }

    private static void WriteCanonicalJson(Utf8JsonWriter writer, JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in value.EnumerateObject().OrderBy(
                             property => property.Name,
                             StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteCanonicalJson(writer, property.Value);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in value.EnumerateArray())
                {
                    WriteCanonicalJson(writer, item);
                }
                writer.WriteEndArray();
                break;
            default:
                value.WriteTo(writer);
                break;
        }
    }
}
