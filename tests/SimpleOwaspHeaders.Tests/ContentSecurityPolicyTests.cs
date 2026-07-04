using Microsoft.AspNetCore.Http;
using SimpleOwaspHeaders.Policies;

namespace SimpleOwaspHeaders.Tests;

public class ContentSecurityPolicyTests
{
    [Fact]
    public void BuildHeaders_includes_sanitized_nonce()
    {
        var policy = SecurityHeaderPolicyBuilder.Create()
            .WithContentSecurityPolicy(csp => csp
                .ScriptSources("'self'")
                .WithNonce(_ => "abc123"))
            .Build();

        var headers = policy.BuildHeaders(new DefaultHttpContext());
        Assert.Contains("script-src 'self' 'nonce-abc123'", headers["Content-Security-Policy"]);
    }

    [Fact]
    public void BuildHeaders_rejects_nonce_with_quotes()
    {
        var policy = SecurityHeaderPolicyBuilder.Create()
            .WithContentSecurityPolicy(csp => csp
                .ScriptSources("'self'")
                .WithNonce(_ => "bad'nonce"))
            .Build();

        var context = new DefaultHttpContext();
        Assert.Throws<InvalidOperationException>(() => policy.BuildHeaders(context));
    }
}
