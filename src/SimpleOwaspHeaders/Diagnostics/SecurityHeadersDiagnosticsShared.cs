using System.Collections.Frozen;
using SimpleOwaspHeaders.Matching;
using SimpleOwaspHeaders.Options;
using SimpleOwaspHeaders.Policies;

namespace SimpleOwaspHeaders.Diagnostics;

internal static class SecurityHeadersDiagnosticsShared
{
    public static string NormalizePath(string? path)
    {
        var normalizedPath = string.IsNullOrWhiteSpace(path) ? "/" : path;
        if (!normalizedPath.StartsWith('/'))
        {
            normalizedPath = "/" + normalizedPath;
        }

        return normalizedPath;
    }

    public static IReadOnlyDictionary<string, string> BuildHeadersForPath(
        SecurityHeaderPolicyResolver resolver,
        string path)
    {
        var resolution = resolver.ResolveDetailsForPath(path);
        return BuildHeadersFromResolution(resolution, path);
    }

    public static IReadOnlyDictionary<string, string> BuildHeadersFromResolution(
        PolicyResolutionDetails resolution,
        string path)
    {
        if (resolution.IsIgnored)
        {
            return FrozenDictionary<string, string>.Empty;
        }

        var headers = resolution.EffectivePolicy.BuildHeaders()
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);

        var clearSiteData = resolution.EffectivePolicy.ClearSiteData?.ResolveForPath(path);
        if (!string.IsNullOrEmpty(clearSiteData))
        {
            headers["Clear-Site-Data"] = clearSiteData;
        }

        return headers;
    }

    public static IReadOnlyList<AppliedHeaderInfo> BuildHeaderInfos(
        PolicyResolutionDetails resolution,
        string path)
    {
        if (resolution.IsIgnored)
        {
            return [];
        }

        return BuildHeadersFromResolution(resolution, path)
            .Select(pair => CreateHeaderInfo(pair.Key, pair.Value, resolution.EffectivePolicy))
            .OrderBy(info => info.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static AppliedHeaderInfo CreateHeaderInfo(
        string name,
        string value,
        SecurityHeaderPolicy policy)
    {
        IReadOnlyList<CspDirectiveInfo>? cspDirectives = null;

        if (name.Equals("Content-Security-Policy", StringComparison.OrdinalIgnoreCase))
        {
            cspDirectives = ContentSecurityPolicyDiagnostics.Describe(policy.ContentSecurityPolicy);
        }
        else if (name.Equals("Content-Security-Policy-Report-Only", StringComparison.OrdinalIgnoreCase))
        {
            cspDirectives = ContentSecurityPolicyDiagnostics.Describe(policy.ContentSecurityPolicyReportOnly);
        }

        return new AppliedHeaderInfo
        {
            Name = name,
            Value = value,
            SecurityInfo = HeaderSecurityGuide.Get(name),
            CspDirectives = cspDirectives
        };
    }

    public static IReadOnlyList<PathPreviewLink> BuildPathPreviews(SimpleOwaspHeadersOptions options)
    {
        var links = new List<PathPreviewLink>
        {
            new() { Path = "/", Label = "Default policy ( / )" }
        };

        foreach (var pathPolicy in options.PathPolicies)
        {
            if (string.IsNullOrWhiteSpace(pathPolicy.Pattern))
            {
                continue;
            }

            links.Add(new PathPreviewLink
            {
                Path = GetSamplePath(pathPolicy),
                Label = DescribePathPolicy(pathPolicy)
            });
        }

        foreach (var ignored in options.IgnoredPaths)
        {
            if (string.IsNullOrWhiteSpace(ignored))
            {
                continue;
            }

            links.Add(new PathPreviewLink
            {
                Path = ignored,
                Label = $"Ignored {ignored}"
            });
        }

        return links;
    }

    public static string GetSamplePath(PathSecurityHeaderPolicy pathPolicy) =>
        pathPolicy.MatchKind == PathMatchKind.Prefix
            ? pathPolicy.Pattern
            : SamplePathForRegex(pathPolicy.Pattern);

    public static string DescribePathPolicy(PathSecurityHeaderPolicy pathPolicy) =>
        pathPolicy.MatchKind switch
        {
            PathMatchKind.Prefix when !string.IsNullOrWhiteSpace(pathPolicy.NamedPolicy) =>
                $"Prefix {pathPolicy.Pattern} → {pathPolicy.NamedPolicy}",
            PathMatchKind.Prefix => $"Prefix {pathPolicy.Pattern}",
            PathMatchKind.Regex when !string.IsNullOrWhiteSpace(pathPolicy.NamedPolicy) =>
                $"Regex {pathPolicy.Pattern} → {pathPolicy.NamedPolicy}",
            PathMatchKind.Regex => $"Regex {pathPolicy.Pattern}",
            _ => pathPolicy.Pattern
        };

    public static string SamplePathForRegex(string pattern)
    {
        if (pattern.StartsWith('^'))
        {
            var trimmed = pattern.TrimStart('^').TrimEnd('$');
            var withoutOptional = trimmed
                .Replace(".*", "/sample", StringComparison.Ordinal)
                .Replace("\\d+", "1", StringComparison.Ordinal)
                .Replace("\\.", ".", StringComparison.Ordinal);

            return withoutOptional.StartsWith('/') ? withoutOptional : "/" + withoutOptional;
        }

        return "/";
    }

    public static IReadOnlyDictionary<string, string> BuildHeadersFromPolicy(
        SecurityHeaderPolicy policy,
        string path = "/")
    {
        var headers = policy.BuildHeaders()
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);

        var clearSiteData = policy.ClearSiteData?.ResolveForPath(path);
        if (!string.IsNullOrEmpty(clearSiteData))
        {
            headers["Clear-Site-Data"] = clearSiteData;
        }

        return headers;
    }
}
