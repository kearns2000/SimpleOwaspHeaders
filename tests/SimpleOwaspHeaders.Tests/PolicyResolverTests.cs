using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using SimpleOwaspHeaders.Matching;
using SimpleOwaspHeaders.Metadata;
using SimpleOwaspHeaders.Options;

namespace SimpleOwaspHeaders.Tests;

public class PolicyResolverTests
{
    [Fact]
    public void Resolve_uses_endpoint_named_policy_over_path_policy()
    {
        var options = new SimpleOwaspHeadersOptions();
        options.AddNamedPolicy("LockedDown", policy => policy
            .WithContentSecurityPolicy(csp => csp.DefaultSources("'none'")));
        options.ForPath("/endpoint", policy => policy
            .WithContentSecurityPolicy(csp => csp.ScriptSources("'unsafe-inline'")));

        var resolver = new SecurityHeaderPolicyResolver(Microsoft.Extensions.Options.Options.Create(options));

        var context = new DefaultHttpContext();
        context.Request.Path = "/endpoint";
        context.SetEndpoint(new Endpoint(
            _ => Task.CompletedTask,
            new EndpointMetadataCollection(new SecureHeadersAttribute("LockedDown")),
            "locked-down"));

        var policy = resolver.Resolve(context);
        Assert.Contains("default-src 'none'", policy.BuildHeaders()["Content-Security-Policy"]);
    }

    [Fact]
    public void Resolve_uses_regex_path_policy()
    {
        var options = new SimpleOwaspHeadersOptions();
        options.ForPathRegex(@"^/api/v\d+/public", policy => policy
            .WithContentSecurityPolicy(csp => csp.DefaultSources("'none'")));

        var resolver = new SecurityHeaderPolicyResolver(Microsoft.Extensions.Options.Options.Create(options));

        var context = new DefaultHttpContext { Request = { Path = "/api/v2/public/info" } };
        var policy = resolver.Resolve(context);

        Assert.Contains("default-src 'none'", policy.BuildHeaders()["Content-Security-Policy"]);
    }

    [Fact]
    public void Resolve_regex_path_policy_times_out_on_catastrophic_backtracking()
    {
        var options = new SimpleOwaspHeadersOptions();
        options.ForPathRegex(@"^(a+)+$", policy => policy
            .WithContentSecurityPolicy(csp => csp.DefaultSources("'none'")));

        var resolver = new SecurityHeaderPolicyResolver(Microsoft.Extensions.Options.Options.Create(options));

        var context = new DefaultHttpContext { Request = { Path = "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaX" } };
        var policy = resolver.Resolve(context);

        Assert.DoesNotContain("default-src 'none'", policy.BuildHeaders().GetValueOrDefault("Content-Security-Policy") ?? string.Empty);
    }
}
