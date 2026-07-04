namespace SimpleOwaspHeaders.Policies;

/// <summary>
/// Built-in policy presets for common application shapes.
/// </summary>
public static class SecurityHeaderPresets
{
    public static SecurityHeaderPolicy OwaspRecommended => SecurityHeaderPolicy.OwaspRecommended;

    public static SecurityHeaderPolicy Strict => SecurityHeaderPolicyBuilder.Create()
        .WithHsts(maxAge: 63_072_000, includeSubDomains: true)
        .WithXFrameOptions(FrameOptions.Deny)
        .WithXContentTypeOptions()
        .WithContentSecurityPolicy(csp => csp
            .DefaultSources("'none'")
            .ScriptSources("'self'")
            .StyleSources("'self'")
            .ImageSources("'self'")
            .ConnectSources("'self'")
            .FrameAncestors("'none'")
            .BlockAllMixedContent()
            .UpgradeInsecureRequests())
        .WithPermittedCrossDomainPolicies("none")
        .WithReferrerPolicy(ReferrerPolicyValue.StrictOriginWhenCrossOrigin)
        .WithCacheControl()
        .WithXXssProtectionDisabled()
        .WithCrossOriginResourcePolicy(CrossOriginResourcePolicyValue.SameOrigin)
        .WithCrossOriginOpenerPolicy(CrossOriginOpenerPolicyValue.SameOrigin)
        .WithCrossOriginEmbedderPolicy(CrossOriginEmbedderPolicyValue.RequireCorp)
        .Build();

    public static SecurityHeaderPolicy ApiOnly => SecurityHeaderPolicyBuilder.Create()
        .WithHsts()
        .WithXContentTypeOptions()
        .WithContentSecurityPolicy(csp => csp.DefaultSources("'none'"))
        .WithReferrerPolicy(ReferrerPolicyValue.NoReferrer)
        .WithCacheControl(noStore: true)
        .WithCrossOriginResourcePolicy(CrossOriginResourcePolicyValue.CrossOrigin)
        .Build();

    public static SecurityHeaderPolicy SpaWithCdn(string cdnOrigin) => SecurityHeaderPolicyBuilder.Create()
        .WithHsts()
        .WithXFrameOptions(FrameOptions.SameOrigin)
        .WithXContentTypeOptions()
        .WithContentSecurityPolicy(csp => csp
            .ScriptSources("'self'", cdnOrigin)
            .StyleSources("'self'", "'unsafe-inline'", cdnOrigin)
            .ImageSources("'self'", "data:", cdnOrigin)
            .FontSources("'self'", cdnOrigin)
            .ConnectSources("'self'")
            .ObjectSources("'none'")
            .UpgradeInsecureRequests())
        .WithReferrerPolicy(ReferrerPolicyValue.StrictOriginWhenCrossOrigin)
        .WithCacheControl(maxAge: 0, noStore: false)
        .WithCrossOriginResourcePolicy(CrossOriginResourcePolicyValue.SameOrigin)
        .Build();

    public static SecurityHeaderPolicy? Resolve(string? presetName) => presetName?.ToLowerInvariant() switch
    {
        null or "" or "owasprecommended" or "owasp" or "default" => OwaspRecommended,
        "strict" => Strict,
        "apionly" or "api" => ApiOnly,
        _ => null
    };

    public static SecurityHeaderPolicy ResolveOrDefault(string? presetName) =>
        Resolve(presetName) ?? OwaspRecommended;
}
