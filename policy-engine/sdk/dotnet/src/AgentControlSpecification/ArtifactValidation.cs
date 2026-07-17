// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using AgentControlSpecification.Interop;

namespace AgentControlSpecification;

public sealed record ValidationDiagnostic(
    [property: JsonPropertyName("component")] string Component,
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("path")] string? Path = null,
    [property: JsonPropertyName("line")] ulong? Line = null,
    [property: JsonPropertyName("column")] ulong? Column = null,
    [property: JsonPropertyName("snippet")] string? Snippet = null);

public sealed record ArtifactValidationResult(
    [property: JsonPropertyName("valid")] bool Valid,
    [property: JsonPropertyName("diagnostics")] IReadOnlyList<ValidationDiagnostic> Diagnostics);

public static class ArtifactValidator
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static ArtifactValidationResult Validate(
        string manifest,
        IReadOnlyDictionary<string, string>? regoModules = null,
        string? opaPath = null)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        NativeEnvironment.SyncOpaEnvironment();
        var modulesJson = JsonSerializer.Serialize(
            regoModules ?? new Dictionary<string, string>(),
            JsonOptions);
        var result = NativeMethods.AcsValidateArtifacts(manifest, modulesJson, opaPath, out var err);
        if (result == IntPtr.Zero)
        {
            throw new InvalidOperationException(ReadAndFreeError(err) ?? "ACS artifact validation failed.");
        }
        try
        {
            var json = Marshal.PtrToStringUTF8(result)
                ?? throw new InvalidOperationException("ACS validation returned a null or non-UTF8 result.");
            return JsonSerializer.Deserialize<ArtifactValidationResult>(json, JsonOptions)
                ?? throw new InvalidOperationException("ACS validation returned an empty result.");
        }
        finally
        {
            NativeMethods.AcsFreeString(result);
        }
    }

    private static string? ReadAndFreeError(IntPtr error)
    {
        if (error == IntPtr.Zero)
        {
            return null;
        }
        try
        {
            return Marshal.PtrToStringUTF8(error);
        }
        finally
        {
            NativeMethods.AcsFreeString(error);
        }
    }
}
