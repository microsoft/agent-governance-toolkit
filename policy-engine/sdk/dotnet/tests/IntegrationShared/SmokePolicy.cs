internal static class SmokePolicy
{
    public static string Path =>
        Environment.GetEnvironmentVariable("ACS_SMOKE_POLICY") is { Length: > 0 } configured
            ? configured
            : System.IO.Path.Combine(RepoRoot(), "tests", "fixtures", "smoke", "manifest.yaml");

    public static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null &&
               !File.Exists(System.IO.Path.Combine(dir.FullName, "tests", "fixtures", "smoke", "manifest.yaml")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName
            ?? throw new InvalidOperationException(
                "Could not locate repo root containing tests/fixtures/smoke/manifest.yaml.");
    }
}
