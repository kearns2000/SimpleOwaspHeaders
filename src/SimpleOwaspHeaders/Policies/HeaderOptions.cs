namespace SimpleOwaspHeaders.Policies;

public sealed class HstsOptions
{
    public int MaxAge { get; init; } = 31_536_000;
    public bool IncludeSubDomains { get; init; } = true;

    public string BuildValue()
    {
        var value = $"max-age={MaxAge}";
        if (IncludeSubDomains)
        {
            value += ";includeSubDomains";
        }

        return value;
    }
}

public sealed class CacheControlOptions
{
    public bool NoStore { get; init; } = true;
    public int MaxAge { get; init; }
    public bool NoCache { get; init; }
    public bool Private { get; init; }
    public bool MustRevalidate { get; init; }

    public string BuildValue()
    {
        if (NoCache)
        {
            return "no-cache";
        }

        if (Private)
        {
            return "private";
        }

        if (MustRevalidate)
        {
            return "must-revalidate";
        }

        var value = $"max-age={MaxAge}";
        if (NoStore)
        {
            value += ",no-store";
        }

        return value;
    }
}

public sealed class ContentSecurityPolicyOptions
{
    public IReadOnlyList<string> BaseUri { get; init; } = [];
    public IReadOnlyList<string> DefaultSources { get; init; } = [];
    public IReadOnlyList<string> ScriptSources { get; init; } = [];
    public IReadOnlyList<string> ObjectSources { get; init; } = [];
    public IReadOnlyList<string> StyleSources { get; init; } = [];
    public IReadOnlyList<string> ImageSources { get; init; } = [];
    public IReadOnlyList<string> MediaSources { get; init; } = [];
    public IReadOnlyList<string> FrameSources { get; init; } = [];
    public IReadOnlyList<string> ChildSources { get; init; } = [];
    public IReadOnlyList<string> FrameAncestors { get; init; } = [];
    public IReadOnlyList<string> FontSources { get; init; } = [];
    public IReadOnlyList<string> ConnectSources { get; init; } = [];
    public IReadOnlyList<string> ManifestSources { get; init; } = [];
    public IReadOnlyList<string> FormActions { get; init; } = [];
    public bool BlockAllMixedContent { get; init; }
    public bool UpgradeInsecureRequests { get; init; }
    public string? ReportUri { get; init; }
    public string? ReportTo { get; init; }
    public Func<HttpContext, string?>? NonceProvider { get; init; }

    public string BuildValue(HttpContext? context = null)
    {
        var parts = new List<string>();

        AppendDirective(parts, "base-uri", BaseUri);
        AppendDirective(parts, "default-src", DefaultSources);
        AppendDirective(parts, "script-src", ResolveScriptSources(context));
        AppendDirective(parts, "object-src", ObjectSources);
        AppendDirective(parts, "style-src", StyleSources);
        AppendDirective(parts, "img-src", ImageSources);
        AppendDirective(parts, "media-src", MediaSources);
        AppendDirective(parts, "frame-src", FrameSources);
        AppendDirective(parts, "child-src", ChildSources);
        AppendDirective(parts, "frame-ancestors", FrameAncestors);
        AppendDirective(parts, "font-src", FontSources);
        AppendDirective(parts, "connect-src", ConnectSources);
        AppendDirective(parts, "manifest-src", ManifestSources);
        AppendDirective(parts, "form-action", FormActions);

        if (BlockAllMixedContent)
        {
            parts.Add("block-all-mixed-content");
        }

        if (UpgradeInsecureRequests)
        {
            parts.Add("upgrade-insecure-requests");
        }

        if (!string.IsNullOrWhiteSpace(ReportUri))
        {
            parts.Add($"report-uri {ReportUri}");
        }

        if (!string.IsNullOrWhiteSpace(ReportTo))
        {
            parts.Add($"report-to {ReportTo}");
        }

        return parts.Count == 0 ? string.Empty : string.Join(';', parts) + ";";
    }

    internal static ContentSecurityPolicyOptions? Merge(
        ContentSecurityPolicyOptions? basePolicy,
        ContentSecurityPolicyOptions? overridePolicy)
    {
        if (overridePolicy is null)
        {
            return basePolicy;
        }

        if (basePolicy is null)
        {
            return overridePolicy;
        }

        return new ContentSecurityPolicyOptions
        {
            BaseUri = PickSources(overridePolicy.BaseUri, basePolicy.BaseUri),
            DefaultSources = PickSources(overridePolicy.DefaultSources, basePolicy.DefaultSources),
            ScriptSources = PickSources(overridePolicy.ScriptSources, basePolicy.ScriptSources),
            ObjectSources = PickSources(overridePolicy.ObjectSources, basePolicy.ObjectSources),
            StyleSources = PickSources(overridePolicy.StyleSources, basePolicy.StyleSources),
            ImageSources = PickSources(overridePolicy.ImageSources, basePolicy.ImageSources),
            MediaSources = PickSources(overridePolicy.MediaSources, basePolicy.MediaSources),
            FrameSources = PickSources(overridePolicy.FrameSources, basePolicy.FrameSources),
            ChildSources = PickSources(overridePolicy.ChildSources, basePolicy.ChildSources),
            FrameAncestors = PickSources(overridePolicy.FrameAncestors, basePolicy.FrameAncestors),
            FontSources = PickSources(overridePolicy.FontSources, basePolicy.FontSources),
            ConnectSources = PickSources(overridePolicy.ConnectSources, basePolicy.ConnectSources),
            ManifestSources = PickSources(overridePolicy.ManifestSources, basePolicy.ManifestSources),
            FormActions = PickSources(overridePolicy.FormActions, basePolicy.FormActions),
            BlockAllMixedContent = overridePolicy.BlockAllMixedContent || basePolicy.BlockAllMixedContent,
            UpgradeInsecureRequests = overridePolicy.UpgradeInsecureRequests || basePolicy.UpgradeInsecureRequests,
            ReportUri = overridePolicy.ReportUri ?? basePolicy.ReportUri,
            ReportTo = overridePolicy.ReportTo ?? basePolicy.ReportTo,
            NonceProvider = overridePolicy.NonceProvider ?? basePolicy.NonceProvider
        };
    }

    private static IReadOnlyList<string> PickSources(
        IReadOnlyList<string> overrideSources,
        IReadOnlyList<string> baseSources) =>
        overrideSources.Count > 0 ? overrideSources : baseSources;

    private IReadOnlyList<string> ResolveScriptSources(HttpContext? context)
    {
        if (NonceProvider is null || context is null)
        {
            return ScriptSources;
        }

        var nonce = NonceProvider(context);
        if (string.IsNullOrWhiteSpace(nonce))
        {
            return ScriptSources;
        }

        var sources = ScriptSources.ToList();
        sources.Add(FormatNonceSource(nonce));
        return sources;
    }

    private static string FormatNonceSource(string nonce)
    {
        if (nonce.Any(static c => char.IsWhiteSpace(c) || c == '\''))
        {
            throw new InvalidOperationException(
                "CSP nonce values must not contain whitespace or single quotes.");
        }

        return $"'nonce-{nonce}'";
    }

    private static void AppendDirective(List<string> parts, string name, IReadOnlyList<string> sources)
    {
        if (sources.Count == 0)
        {
            return;
        }

        parts.Add($"{name} {string.Join(' ', sources.Select(FormatSource))}");
    }

    internal static string FormatSource(string source)
    {
        if (source is "'self'" or "'none'" or "'unsafe-inline'" or "'unsafe-eval'" or "'unsafe-hashes'" or "'strict-dynamic'")
        {
            return source;
        }

        if (source.StartsWith('\'') && source.EndsWith('\''))
        {
            return source;
        }

        if (source.StartsWith("'nonce-", StringComparison.Ordinal))
        {
            return source;
        }

        if (source is "data:" or "blob:" or "https:" or "http:")
        {
            return source;
        }

        if (source.Contains("://", StringComparison.Ordinal))
        {
            return source;
        }

        return $"'{source}'";
    }
}
