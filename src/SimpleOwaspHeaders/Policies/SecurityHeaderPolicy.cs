using System.Collections.Frozen;
using SimpleOwaspHeaders.Headers;

namespace SimpleOwaspHeaders.Policies;

/// <summary>
/// Immutable security header policy.
/// </summary>
public sealed class SecurityHeaderPolicy
{
    public static SecurityHeaderPolicy OwaspRecommended { get; } = SecurityHeaderPolicyBuilder
        .Create()
        .WithHsts()
        .WithXFrameOptions(FrameOptions.Deny)
        .WithXContentTypeOptions()
        .WithContentSecurityPolicy(csp => csp
            .ScriptSources("'self'")
            .ObjectSources("'self'")
            .BlockAllMixedContent()
            .UpgradeInsecureRequests())
        .WithPermittedCrossDomainPolicies("none")
        .WithReferrerPolicy(ReferrerPolicyValue.NoReferrer)
        .WithCacheControl()
        .WithXXssProtectionDisabled()
        .WithCrossOriginResourcePolicy(CrossOriginResourcePolicyValue.SameOrigin)
        .WithCrossOriginOpenerPolicy(CrossOriginOpenerPolicyValue.SameOrigin)
        .WithCrossOriginEmbedderPolicy(CrossOriginEmbedderPolicyValue.RequireCorp)
        .Build();

    public HstsOptions? Hsts { get; init; }
    public FrameOptions? XFrameOptions { get; init; }
    public bool XContentTypeOptions { get; init; }
    public ContentSecurityPolicyOptions? ContentSecurityPolicy { get; init; }
    public ContentSecurityPolicyOptions? ContentSecurityPolicyReportOnly { get; init; }
    public string? PermittedCrossDomainPolicies { get; init; }
    public ReferrerPolicyValue? ReferrerPolicy { get; init; }
    public CacheControlOptions? CacheControl { get; init; }
    public bool XXssProtectionDisabled { get; init; }
    public CrossOriginResourcePolicyValue? CrossOriginResourcePolicy { get; init; }
    public CrossOriginOpenerPolicyValue? CrossOriginOpenerPolicy { get; init; }
    public CrossOriginEmbedderPolicyValue? CrossOriginEmbedderPolicy { get; init; }
    public ClearSiteDataPathOptions? ClearSiteData { get; init; }
    public ReportingEndpointsOptions? ReportingEndpoints { get; init; }
    public PermissionPolicyOptions? PermissionPolicy { get; init; }

    public FrozenDictionary<string, string> BuildHeaders(HttpContext? context = null)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (Hsts is not null)
        {
            headers[HeaderNames.StrictTransportSecurity] = Hsts.BuildValue();
        }

        if (XFrameOptions is not null)
        {
            headers[HeaderNames.XFrameOptions] = XFrameOptions switch
            {
                Policies.FrameOptions.Deny => "deny",
                Policies.FrameOptions.SameOrigin => "sameorigin",
                _ => "deny"
            };
        }

        if (XContentTypeOptions)
        {
            headers[HeaderNames.XContentTypeOptions] = "nosniff";
        }

        if (ContentSecurityPolicy is not null)
        {
            var value = ContentSecurityPolicy.BuildValue(context);
            if (!string.IsNullOrEmpty(value))
            {
                headers[HeaderNames.ContentSecurityPolicy] = value;
            }
        }

        if (ContentSecurityPolicyReportOnly is not null)
        {
            var value = ContentSecurityPolicyReportOnly.BuildValue(context);
            if (!string.IsNullOrEmpty(value))
            {
                headers[HeaderNames.ContentSecurityPolicyReportOnly] = value;
            }
        }

        if (!string.IsNullOrWhiteSpace(PermittedCrossDomainPolicies))
        {
            headers[HeaderNames.PermittedCrossDomainPolicies] = PermittedCrossDomainPolicies;
        }

        if (ReferrerPolicy is not null)
        {
            headers[HeaderNames.ReferrerPolicy] = FormatReferrerPolicy(ReferrerPolicy.Value);
        }

        if (CacheControl is not null)
        {
            headers[HeaderNames.CacheControl] = CacheControl.BuildValue();
        }

        if (XXssProtectionDisabled)
        {
            headers[HeaderNames.XXssProtection] = "0";
        }

        if (CrossOriginResourcePolicy is not null)
        {
            headers[HeaderNames.CrossOriginResourcePolicy] = CrossOriginResourcePolicy switch
            {
                CrossOriginResourcePolicyValue.SameOrigin => "same-origin",
                CrossOriginResourcePolicyValue.SameSite => "same-site",
                CrossOriginResourcePolicyValue.CrossOrigin => "cross-origin",
                _ => "same-origin"
            };
        }

        if (CrossOriginOpenerPolicy is not null)
        {
            headers[HeaderNames.CrossOriginOpenerPolicy] = CrossOriginOpenerPolicy switch
            {
                CrossOriginOpenerPolicyValue.SameOrigin => "same-origin",
                CrossOriginOpenerPolicyValue.SameOriginAllowPopups => "same-origin-allow-popups",
                CrossOriginOpenerPolicyValue.UnsafeNone => "unsafe-none",
                _ => "same-origin"
            };
        }

        if (CrossOriginEmbedderPolicy is not null)
        {
            if (CrossOriginEmbedderPolicy == CrossOriginEmbedderPolicyValue.RequireCorp &&
                CrossOriginResourcePolicy is null)
            {
                throw new InvalidOperationException(
                    "Cross-Origin-Embedder-Policy require-corp requires Cross-Origin-Resource-Policy to be enabled.");
            }

            headers[HeaderNames.CrossOriginEmbedderPolicy] = CrossOriginEmbedderPolicy switch
            {
                CrossOriginEmbedderPolicyValue.RequireCorp => "require-corp",
                CrossOriginEmbedderPolicyValue.UnsafeNone => "unsafe-none",
                _ => "require-corp"
            };
        }

        if (ReportingEndpoints is not null)
        {
            var value = ReportingEndpoints.BuildValue();
            if (!string.IsNullOrEmpty(value))
            {
                headers[HeaderNames.ReportingEndpoints] = value;
            }
        }

        if (PermissionPolicy is not null)
        {
            var value = PermissionPolicy.BuildValue();
            if (!string.IsNullOrEmpty(value))
            {
                headers[HeaderNames.PermissionsPolicy] = value;
            }
        }

        return headers.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Merges <paramref name="overridePolicy"/> onto this policy.
    /// CSP directives merge individually; other reference-type properties replace the base when non-null.
    /// Boolean flags are OR-combined.
    /// </summary>
    public SecurityHeaderPolicy Merge(SecurityHeaderPolicy overridePolicy)
    {
        ArgumentNullException.ThrowIfNull(overridePolicy);

        return new SecurityHeaderPolicy
        {
            Hsts = overridePolicy.Hsts ?? Hsts,
            XFrameOptions = overridePolicy.XFrameOptions ?? XFrameOptions,
            XContentTypeOptions = overridePolicy.XContentTypeOptions || XContentTypeOptions,
            ContentSecurityPolicy = ContentSecurityPolicyOptions.Merge(ContentSecurityPolicy, overridePolicy.ContentSecurityPolicy),
            ContentSecurityPolicyReportOnly = ContentSecurityPolicyOptions.Merge(
                ContentSecurityPolicyReportOnly,
                overridePolicy.ContentSecurityPolicyReportOnly),
            PermittedCrossDomainPolicies = overridePolicy.PermittedCrossDomainPolicies ?? PermittedCrossDomainPolicies,
            ReferrerPolicy = overridePolicy.ReferrerPolicy ?? ReferrerPolicy,
            CacheControl = overridePolicy.CacheControl ?? CacheControl,
            XXssProtectionDisabled = overridePolicy.XXssProtectionDisabled || XXssProtectionDisabled,
            CrossOriginResourcePolicy = overridePolicy.CrossOriginResourcePolicy ?? CrossOriginResourcePolicy,
            CrossOriginOpenerPolicy = overridePolicy.CrossOriginOpenerPolicy ?? CrossOriginOpenerPolicy,
            CrossOriginEmbedderPolicy = overridePolicy.CrossOriginEmbedderPolicy ?? CrossOriginEmbedderPolicy,
            ClearSiteData = overridePolicy.ClearSiteData ?? ClearSiteData,
            ReportingEndpoints = overridePolicy.ReportingEndpoints ?? ReportingEndpoints,
            PermissionPolicy = overridePolicy.PermissionPolicy ?? PermissionPolicy
        };
    }

    private static string FormatReferrerPolicy(ReferrerPolicyValue value) => value switch
    {
        ReferrerPolicyValue.NoReferrer => "no-referrer",
        ReferrerPolicyValue.NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
        ReferrerPolicyValue.Origin => "origin",
        ReferrerPolicyValue.OriginWhenCrossOrigin => "origin-when-cross-origin",
        ReferrerPolicyValue.SameOrigin => "same-origin",
        ReferrerPolicyValue.StrictOrigin => "strict-origin",
        ReferrerPolicyValue.StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
        ReferrerPolicyValue.UnsafeUrl => "unsafe-url",
        _ => "no-referrer"
    };
}
