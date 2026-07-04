using SimpleOwaspHeaders.Policies;

namespace SimpleOwaspHeaders.Tests;

public class SecurityHeaderPolicyTests
{
    [Fact]
    public void OwaspRecommended_includes_expected_headers()
    {
        var headers = SecurityHeaderPolicy.OwaspRecommended.BuildHeaders();

        Assert.True(headers.ContainsKey("Strict-Transport-Security"));
        Assert.True(headers.ContainsKey("X-Frame-Options"));
        Assert.Equal("deny", headers["X-Frame-Options"]);
        Assert.Contains("script-src 'self'", headers["Content-Security-Policy"]);
        Assert.True(headers.ContainsKey("Cross-Origin-Embedder-Policy"));
    }

    [Fact]
    public void ContentSecurityPolicy_supports_data_scheme()
    {
        var policy = SecurityHeaderPolicyBuilder.Create()
            .WithContentSecurityPolicy(csp => csp.ImageSources("'self'", "data:"))
            .Build();

        Assert.Contains("img-src 'self' data:", policy.BuildHeaders()["Content-Security-Policy"]);
    }

    [Fact]
    public void Merge_overrides_csp_directives_individually()
    {
        var merged = SecurityHeaderPolicy.OwaspRecommended.Merge(
            SecurityHeaderPolicyBuilder.Create()
                .WithContentSecurityPolicy(csp => csp.ScriptSources("'none'"))
                .Build()).BuildHeaders();

        Assert.Contains("script-src 'none'", merged["Content-Security-Policy"]);
        Assert.Contains("object-src 'self'", merged["Content-Security-Policy"]);
        Assert.Contains("block-all-mixed-content", merged["Content-Security-Policy"]);
        Assert.Equal("deny", merged["X-Frame-Options"]);
    }

    [Fact]
    public void ContentSecurityPolicy_merge_preserves_unset_directives()
    {
        var baseCsp = new ContentSecurityPolicyOptions
        {
            ScriptSources = ["'self'"],
            ObjectSources = ["'self'"],
            UpgradeInsecureRequests = true
        };

        var overrideCsp = new ContentSecurityPolicyOptions
        {
            ScriptSources = ["'none'"]
        };

        var merged = ContentSecurityPolicyOptions.Merge(baseCsp, overrideCsp)!;

        Assert.Equal(["'none'"], merged.ScriptSources);
        Assert.Equal(["'self'"], merged.ObjectSources);
        Assert.True(merged.UpgradeInsecureRequests);
    }

    [Fact]
    public void CoepRequireCorp_without_corp_throws()
    {
        var policy = SecurityHeaderPolicyBuilder.Create()
            .WithCrossOriginEmbedderPolicy(CrossOriginEmbedderPolicyValue.RequireCorp)
            .Build();

        Assert.Throws<InvalidOperationException>(() => policy.BuildHeaders());
    }

    [Fact]
    public void ReportOnly_uses_separate_header()
    {
        var policy = SecurityHeaderPolicyBuilder.Create()
            .WithContentSecurityPolicyReportOnly(csp => csp.ScriptSources("'self'"))
            .Build();

        var headers = policy.BuildHeaders();
        Assert.False(headers.ContainsKey("Content-Security-Policy"));
        Assert.Contains("script-src 'self'", headers["Content-Security-Policy-Report-Only"]);
    }

    [Fact]
    public void PermissionPolicy_builds_value()
    {
        var policy = SecurityHeaderPolicyBuilder.Create()
            .WithPermissionPolicy(pp => pp.Disable("geolocation").Disable("camera"))
            .Build();

        var value = policy.BuildHeaders()["Permissions-Policy"];
        Assert.Contains("geolocation=()", value);
        Assert.Contains("camera=()", value);
    }

    [Fact]
    public void Presets_resolve_by_name()
    {
        Assert.NotNull(SecurityHeaderPresets.Resolve("Strict"));
        Assert.NotNull(SecurityHeaderPresets.Resolve("api"));
    }
}
