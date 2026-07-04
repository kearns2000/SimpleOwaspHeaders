namespace SimpleOwaspHeaders.Policies;

public enum ClearSiteDataDirective
{
    Cache,
    Cookies,
    Storage,
    ExecutionContexts,
    Wildcard
}

public sealed class ClearSiteDataValueOptions
{
    public IReadOnlyList<ClearSiteDataDirective> Directives { get; init; } = [];

    public string BuildValue()
    {
        if (Directives.Count == 0)
        {
            throw new InvalidOperationException("Clear-Site-Data requires at least one directive.");
        }

        if (Directives.Contains(ClearSiteDataDirective.Wildcard))
        {
            return "\"*\"";
        }

        var parts = Directives
            .Distinct()
            .Select(d => d switch
            {
                ClearSiteDataDirective.Cache => "\"cache\"",
                ClearSiteDataDirective.Cookies => "\"cookies\"",
                ClearSiteDataDirective.Storage => "\"storage\"",
                ClearSiteDataDirective.ExecutionContexts => "\"executionContexts\"",
                _ => throw new InvalidOperationException($"Unknown directive: {d}")
            });

        return string.Join(',', parts);
    }
}

public sealed class ClearSiteDataPathOptions
{
    public ClearSiteDataValueOptions? Default { get; init; }

    public IReadOnlyDictionary<string, ClearSiteDataValueOptions> PathOverrides { get; init; }
        = new Dictionary<string, ClearSiteDataValueOptions>();

    public string? ResolveForPath(string requestPath)
    {
        if (string.IsNullOrEmpty(requestPath))
        {
            return Default?.BuildValue();
        }

        var sorted = PathOverrides
            .OrderByDescending(p => p.Key.Length)
            .ToList();

        foreach (var (pathPrefix, config) in sorted)
        {
            if (requestPath.StartsWith(pathPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return config.BuildValue();
            }
        }

        return Default?.BuildValue();
    }
}
