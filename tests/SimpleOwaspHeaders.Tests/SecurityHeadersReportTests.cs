using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SimpleOwaspHeaders;
using SimpleOwaspHeaders.Diagnostics;
using SimpleOwaspHeaders.Matching;
using SimpleOwaspHeaders.Policies;

namespace SimpleOwaspHeaders.Tests;

public class SecurityHeadersReportTests
{
    [Fact]
    public void ResolveDetailsForPath_includes_path_prefix_override()
    {
        var options = new Options.SimpleOwaspHeadersOptions();
        options.ForPath("/admin", policy => policy
            .WithContentSecurityPolicy(csp => csp.ScriptSources("'none'")));

        var resolver = new SecurityHeaderPolicyResolver(Microsoft.Extensions.Options.Options.Create(options));
        var details = resolver.ResolveDetailsForPath("/admin/dashboard");

        Assert.Equal(2, details.Steps.Count);
        Assert.Equal("Default policy", details.Steps[0].Source);
        Assert.Contains("Path prefix \"/admin\"", details.Steps[1].Source);
        Assert.Contains("script-src 'none'", details.EffectivePolicy.BuildHeaders()["Content-Security-Policy"]);
    }

    [Fact]
    public void ResolveDetailsForPath_marks_ignored_paths()
    {
        var options = new Options.SimpleOwaspHeadersOptions();
        options.IgnorePath("/health");

        var resolver = new SecurityHeaderPolicyResolver(Microsoft.Extensions.Options.Options.Create(options));
        var details = resolver.ResolveDetailsForPath("/health");

        Assert.True(details.IsIgnored);
        Assert.Empty(details.Steps);
    }

    [Fact]
    public void HtmlRenderer_includes_header_name_and_csp_directive_breakdown()
    {
        var options = new Options.SimpleOwaspHeadersOptions();
        var resolver = new SecurityHeaderPolicyResolver(Microsoft.Extensions.Options.Options.Create(options));
        var report = SecurityHeadersReportBuilder.Build(options, resolver, "/");

        var html = SecurityHeadersHtmlRenderer.Render(report);

        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("Strict-Transport-Security", html);
        Assert.Contains("Development diagnostics only", html);
        Assert.Contains("CSP directive", html);
        Assert.Contains("script-src", html);
        Assert.DoesNotContain("<script>", html);
    }

    [Fact]
    public async Task Report_endpoint_returns_html_when_enabled()
    {
        var host = await CreateDiagnosticsHost(options =>
        {
            options.ForPath("/admin", policy => policy
                .WithContentSecurityPolicy(csp => csp.ScriptSources("'none'")));
        });

        using (host)
        {
            var client = host.GetTestClient();
            var response = await client.GetAsync("/_simple-owasp-headers/report?path=/admin");

            Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("text/html; charset=utf-8", response.Content.Headers.ContentType?.ToString());
            var body = await response.Content.ReadAsStringAsync();
            Assert.Contains("Path prefix", body);
            Assert.Contains("/admin", body);
            Assert.Contains("script-src", body);
            Assert.Contains("none", body);
        }
    }

    [Fact]
    public async Task Diagnostics_json_includes_resolution_chain()
    {
        var host = await CreateDiagnosticsHost(options =>
        {
            options.ForPath("/admin", policy => policy
                .WithContentSecurityPolicy(csp => csp.ScriptSources("'none'")));
        });

        using (host)
        {
            var client = host.GetTestClient();
            var response = await client.GetAsync("/_simple-owasp-headers");
            var json = await response.Content.ReadAsStringAsync();

            Assert.Contains("resolution", json, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Strict-Transport-Security", json, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task Report_endpoint_not_mapped_when_disabled()
    {
        var host = await CreateDiagnosticsHost(_ => { }, enableDiagnostics: false);

        using (host)
        {
            var client = host.GetTestClient();
            var response = await client.GetAsync("/_simple-owasp-headers/report");
            Assert.Equal(System.Net.HttpStatusCode.NotFound, response.StatusCode);
        }
    }

    [Fact]
    public void MatrixBuilder_includes_default_and_path_scenarios()
    {
        var options = new Options.SimpleOwaspHeadersOptions();
        options.ForPath("/admin", policy => policy
            .WithContentSecurityPolicy(csp => csp.ScriptSources("'none'")));
        options.IgnorePath("/health");

        var resolver = new SecurityHeaderPolicyResolver(Microsoft.Extensions.Options.Options.Create(options));
        var matrix = SecurityHeadersMatrixBuilder.Build(options, resolver);

        Assert.True(matrix.Scenarios.Count >= 3);
        Assert.Contains(matrix.Scenarios, scenario => scenario.SamplePath == "/");
        Assert.Contains(matrix.Scenarios, scenario => scenario.SamplePath == "/admin" && !scenario.IsIgnored);
        Assert.Contains(matrix.Scenarios, scenario => scenario.SamplePath == "/health" && scenario.IsIgnored);
        Assert.Contains(matrix.HeaderComparisons, row => row.HeaderName == "Content-Security-Policy" && row.DiffersFromDefault);
    }

    [Fact]
    public void MatrixBuilder_includes_named_policy_summary()
    {
        var options = new Options.SimpleOwaspHeadersOptions();
        options.AddNamedPolicy("Admin", policy => policy
            .WithContentSecurityPolicy(csp => csp.ScriptSources("'none'")));
        options.ForPath("/admin", "Admin");

        var resolver = new SecurityHeaderPolicyResolver(Microsoft.Extensions.Options.Options.Create(options));
        var matrix = SecurityHeadersMatrixBuilder.Build(options, resolver);

        var named = Assert.Single(matrix.NamedPolicies);
        Assert.Equal("Admin", named.Name);
        Assert.Contains("Prefix /admin", named.ReferencedBy.Single());
        Assert.Contains("script-src", named.MergedHeaders["Content-Security-Policy"]);
    }

    [Fact]
    public async Task Matrix_endpoint_returns_html_and_json()
    {
        var host = await CreateDiagnosticsHost(options =>
        {
            options.ForPath("/admin", policy => policy
                .WithContentSecurityPolicy(csp => csp.ScriptSources("'none'")));
        });

        using (host)
        {
            var client = host.GetTestClient();

            var htmlResponse = await client.GetAsync("/_simple-owasp-headers/matrix");
            var html = await htmlResponse.Content.ReadAsStringAsync();
            Assert.Equal("text/html; charset=utf-8", htmlResponse.Content.Headers.ContentType?.ToString());
            Assert.Contains("Configuration matrix", html);
            Assert.Contains("Header comparison", html);

            var jsonResponse = await client.GetAsync("/_simple-owasp-headers/matrix?format=json");
            var json = await jsonResponse.Content.ReadAsStringAsync();
            Assert.Contains("comparisons", json, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("scenarios", json, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task Diagnostics_endpoints_not_mapped_in_production()
    {
        var host = await CreateDiagnosticsHost(_ => { }, environmentName: "Production");

        using (host)
        {
            var client = host.GetTestClient();
            var response = await client.GetAsync("/_simple-owasp-headers/matrix");
            Assert.Equal(StatusCodes.Status404NotFound, (int)response.StatusCode);
        }
    }

    private static async Task<IHost> CreateDiagnosticsHost(
        Action<Options.SimpleOwaspHeadersOptions> configure,
        bool enableDiagnostics = true,
        string environmentName = "Development")
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.UseEnvironment(environmentName);
                webBuilder.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSimpleOwaspHeaders(options =>
                    {
                        configure(options);
                        options.EnableDiagnosticsEndpoint = enableDiagnostics;
                    });
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseSimpleOwaspHeaders();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/admin", () => Results.Text("admin"));
                        endpoints.MapSimpleOwaspHeadersDiagnostics();
                    });
                });
            })
            .Build();

        await host.StartAsync();
        return host;
    }
}
