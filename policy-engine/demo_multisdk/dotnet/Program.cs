// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using AgentControlSpecification;

const string ManifestPath = "/home/liamcrumm/port/agt-acs/policy-engine/demo_multisdk/manifest.yaml";

var control = AgentControl.FromPath(ManifestPath);

Console.WriteLine("DOTNET SDK");

var allowRun = await control.RunAsync<string, string>(
    "hello there",
    (input, _) => ValueTask.FromResult($"answer: {input}"));
Console.WriteLine($"ALLOW run {allowRun.Value}");

try
{
    await control.RunAsync<string, string>(
        "do BLOCKME please",
        (_, _) => ValueTask.FromResult("unexpected"));
}
catch (AgentControlBlockedException ex)
{
    Console.WriteLine($"DENY run {ex.Result.Verdict.Reason}");
}

var transformRun = await control.RunAsync<string, string>(
    "here is my SECRET value",
    (input, _) => ValueTask.FromResult(input));
Console.WriteLine($"XFORM run {transformRun.Value}");

var allowTool = await control.RunToolAsync<Dictionary<string, object?>, Dictionary<string, object?>>(
    "echo_tool",
    new Dictionary<string, object?> { ["text"] = "ping" },
    (args, _) => ValueTask.FromResult(new Dictionary<string, object?> { ["result"] = args["text"] }));
Console.WriteLine($"ALLOW tool {FormatValue(allowTool.Value)}");

try
{
    await control.RunToolAsync<Dictionary<string, object?>, string>(
        "danger_tool",
        new Dictionary<string, object?> { ["text"] = "anything" },
        (_, _) => ValueTask.FromResult("unexpected"));
}
catch (AgentControlBlockedException ex)
{
    Console.WriteLine($"DENY tool {ex.Result.Verdict.Reason}");
}

var transformTool = await control.RunToolAsync<Dictionary<string, object?>, object?>(
    "payments_tool",
    new Dictionary<string, object?> { ["text"] = "receipt" },
    (_, _) => ValueTask.FromResult<object?>(new Dictionary<string, object?> { ["result"] = "SECRET receipt" }));
Console.WriteLine($"XFORM tool {FormatValue(transformTool.Value)}");

var transformModel = await control.RunModelAsync<Dictionary<string, object?>, string>(
    new Dictionary<string, object?> { ["prompt"] = "say hello" },
    (_, _) => ValueTask.FromResult("model saw SECRET token"));
Console.WriteLine($"XFORM model {transformModel.Value}");

static string FormatValue(object? value) => value switch
{
    null => "null",
    string text => text,
    JsonElement element when element.ValueKind == JsonValueKind.String => element.GetString() ?? string.Empty,
    JsonElement element => element.GetRawText(),
    _ => JsonSerializer.Serialize(value),
};
