using SimpleOwaspHeaders.Policies;

namespace SimpleOwaspHeaders.Diagnostics;

public sealed record CspDirectiveInfo(
    string Directive,
    string Value,
    string Summary);

internal static class ContentSecurityPolicyDiagnostics
{
    public static IReadOnlyList<CspDirectiveInfo> Describe(ContentSecurityPolicyOptions? policy)
    {
        if (policy is null)
        {
            return [];
        }

        var directives = new List<CspDirectiveInfo>();
        Add(directives, "default-src", policy.DefaultSources, "Fallback when other fetch directives are not set.");
        Add(directives, "script-src", policy.ScriptSources, "Allowed sources for JavaScript.");
        Add(directives, "object-src", policy.ObjectSources, "Allowed sources for plugins and embedded objects.");
        Add(directives, "style-src", policy.StyleSources, "Allowed sources for CSS.");
        Add(directives, "img-src", policy.ImageSources, "Allowed sources for images.");
        Add(directives, "media-src", policy.MediaSources, "Allowed sources for audio and video.");
        Add(directives, "frame-src", policy.FrameSources, "Allowed sources for nested frames.");
        Add(directives, "child-src", policy.ChildSources, "Allowed sources for workers and nested browsing contexts.");
        Add(directives, "frame-ancestors", policy.FrameAncestors, "Pages that may embed this resource.");
        Add(directives, "font-src", policy.FontSources, "Allowed sources for fonts.");
        Add(directives, "connect-src", policy.ConnectSources, "Allowed fetch/XHR/WebSocket endpoints.");
        Add(directives, "manifest-src", policy.ManifestSources, "Allowed sources for web app manifests.");
        Add(directives, "form-action", policy.FormActions, "Allowed targets for form submissions.");
        Add(directives, "base-uri", policy.BaseUri, "Allowed URLs for the document base element.");

        if (policy.BlockAllMixedContent)
        {
            directives.Add(new CspDirectiveInfo("block-all-mixed-content", "enabled", "Blocks HTTP subresources on HTTPS pages."));
        }

        if (policy.UpgradeInsecureRequests)
        {
            directives.Add(new CspDirectiveInfo("upgrade-insecure-requests", "enabled", "Rewrites HTTP resource URLs to HTTPS."));
        }

        if (!string.IsNullOrWhiteSpace(policy.ReportUri))
        {
            directives.Add(new CspDirectiveInfo("report-uri", policy.ReportUri, "Legacy CSP violation reporting endpoint."));
        }

        if (!string.IsNullOrWhiteSpace(policy.ReportTo))
        {
            directives.Add(new CspDirectiveInfo("report-to", policy.ReportTo, "Named endpoint for CSP violation reports."));
        }

        if (policy.NonceProvider is not null)
        {
            directives.Add(new CspDirectiveInfo("script-src nonce", "per-request", "A nonce is appended to script-src at runtime."));
        }

        return directives;
    }

    private static void Add(
        List<CspDirectiveInfo> directives,
        string name,
        IReadOnlyList<string> sources,
        string summary)
    {
        if (sources.Count == 0)
        {
            return;
        }

        directives.Add(new CspDirectiveInfo(
            name,
            string.Join(' ', sources),
            summary));
    }
}
