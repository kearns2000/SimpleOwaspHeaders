using SimpleOwaspHeaders.Matching;
using SimpleOwaspHeaders.Options;

namespace SimpleOwaspHeaders.Diagnostics;

public sealed class SecurityHeadersReport
{
    public required string RequestPath { get; init; }

    public required string DefaultPreset { get; init; }

    public required PolicyResolutionDetails Resolution { get; init; }

    public required IReadOnlyList<AppliedHeaderInfo> Headers { get; init; }

    public required IReadOnlyList<PathPreviewLink> PathPreviews { get; init; }
}

public sealed class AppliedHeaderInfo
{
    public required string Name { get; init; }

    public required string Value { get; init; }

    public required HeaderSecurityInfo SecurityInfo { get; init; }

    public IReadOnlyList<CspDirectiveInfo>? CspDirectives { get; init; }
}

public sealed class PathPreviewLink
{
    public required string Path { get; init; }

    public required string Label { get; init; }
}

internal static class SecurityHeadersReportBuilder
{
    public static SecurityHeadersReport Build(
        SimpleOwaspHeadersOptions options,
        SecurityHeaderPolicyResolver resolver,
        string requestPath)
    {
        var normalizedPath = SecurityHeadersDiagnosticsShared.NormalizePath(requestPath);
        var resolution = resolver.ResolveDetailsForPath(normalizedPath);

        return new SecurityHeadersReport
        {
            RequestPath = normalizedPath,
            DefaultPreset = options.DefaultPreset,
            Resolution = resolution,
            Headers = SecurityHeadersDiagnosticsShared.BuildHeaderInfos(resolution, normalizedPath),
            PathPreviews = SecurityHeadersDiagnosticsShared.BuildPathPreviews(options)
        };
    }
}
