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
        if (manifest.IndexOf('\0') >= 0)
        {
            return InvalidInput(
                "manifest",
                "manifest_parse_error",
                "Manifest input contains an embedded null character.");
        }
        var modules = regoModules ?? new Dictionary<string, string>();
        if (modules.Count > 0 && opaPath?.IndexOf('\0') >= 0)
        {
            return InvalidInput(
                "rego",
                "opa_execution_error",
                "OPA path contains an embedded null character.",
                "opa");
        }
        NativeEnvironment.SyncOpaEnvironment();
        var modulesJson = JsonSerializer.Serialize(modules, JsonOptions);
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

    private static ArtifactValidationResult InvalidInput(
        string component,
        string code,
        string message,
        string? source = null)
    {
        return new ArtifactValidationResult(
            false,
            [new ValidationDiagnostic(component, code, message, source ?? component)]);
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
