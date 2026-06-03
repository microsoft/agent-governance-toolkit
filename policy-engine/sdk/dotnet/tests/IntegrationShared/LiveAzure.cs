using Azure;
using Azure.AI.OpenAI;

internal static class LiveAzure
{
    public static string PolicyPath => SmokePolicy.Path;

    public static AzureOpenAIClient CreateClient()
    {
        LoadEnv();
        return new AzureOpenAIClient(new Uri(Required("AZURE_OPENAI_ENDPOINT")), new AzureKeyCredential(Required("AZURE_OPENAI_API_KEY")));
    }

    public static string Deployment
    {
        get { LoadEnv(); return Required("AZURE_OPENAI_DEPLOYMENT"); }
    }

    private static void LoadEnv()
    {
        var envPath = Path.Combine(SmokePolicy.RepoRoot(), ".env");
        if (!File.Exists(envPath))
        {
            return;
        }

        foreach (var line in File.ReadAllLines(envPath))
        {
            var index = line.IndexOf('=');
            if (index <= 0) continue;
            Environment.SetEnvironmentVariable(line[..index], line[(index + 1)..]);
        }
    }

    private static string Required(string name) =>
        Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : throw new InvalidOperationException($"Missing {name}.");
}
