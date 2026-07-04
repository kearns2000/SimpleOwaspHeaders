using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SimpleOwaspHeaders;
using SimpleOwaspHeaders.Metadata;
using SimpleOwaspHeaders.Policies;

namespace SimpleOwaspHeaders.Tests;

public class MiddlewareIntegrationTests
{
    [Fact]
    public async Task Default_policy_adds_security_headers()
    {
        var host = await CreateHost(_ => { });
        using (host)
        {
            var client = host.GetTestClient();
            var response = await client.GetAsync("/");

            Assert.True(response.Headers.Contains("Strict-Transport-Security"));
            Assert.True(response.Headers.Contains("Content-Security-Policy"));
            Assert.Equal("deny", response.Headers.GetValues("X-Frame-Options").Single());
        }
    }

    [Fact]
    public async Task Path_policy_overrides_csp()
    {
        var host = await CreateHost(options =>
        {
            options.ForPath("/admin", policy => policy
                .WithContentSecurityPolicy(csp => csp.ScriptSources("'none'")));
        });

        using (host)
        {
            var client = host.GetTestClient();
            var adminResponse = await client.GetAsync("/admin");
            var rootResponse = await client.GetAsync("/");

            Assert.Contains("script-src 'none'", adminResponse.Headers.GetValues("Content-Security-Policy").Single());
            Assert.Contains("script-src 'self'", rootResponse.Headers.GetValues("Content-Security-Policy").Single());
        }
    }

    [Fact]
    public async Task Named_path_reference_applies_named_policy()
    {
        var host = await CreateHost(options =>
        {
            options.AddNamedPolicy("LockedDown", policy => policy
                .WithContentSecurityPolicy(csp => csp.DefaultSources("'none'")));
            options.ForPath("/locked", "LockedDown");
        });

        using (host)
        {
            var client = host.GetTestClient();
            var response = await client.GetAsync("/locked");
            Assert.Contains("default-src 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
        }
    }

    [Fact]
    public async Task Ignored_path_skips_headers()
    {
        var host = await CreateHost(options => options.IgnorePath("/skip"));
        using (host)
        {
            var client = host.GetTestClient();
            var response = await client.GetAsync("/skip");
            Assert.False(response.Headers.Contains("Strict-Transport-Security"));
        }
    }

    [Fact]
    public async Task ClearSiteData_applied_for_matching_path()
    {
        var host = await CreateHost(options =>
        {
            options.DefaultPolicy = SecurityHeaderPolicyBuilder.Create()
                .WithClearSiteData(csd => csd.ForPath("/logout",
                    ClearSiteDataDirective.Cookies,
                    ClearSiteDataDirective.Storage))
                .Build();
        });

        using (host)
        {
            var client = host.GetTestClient();
            var response = await client.GetAsync("/logout");
            Assert.Contains("\"cookies\"", response.Headers.GetValues("Clear-Site-Data").Single());
        }
    }

    [Fact]
    public void Invalid_coep_configuration_fails_at_startup()
    {
        Assert.ThrowsAny<Exception>(() =>
        {
            var host = new HostBuilder()
                .ConfigureWebHost(webBuilder =>
                {
                    webBuilder.UseTestServer();
                    webBuilder.ConfigureServices(services =>
                    {
                        services.AddSimpleOwaspHeaders(options =>
                        {
                            options.DefaultPolicy = SecurityHeaderPolicyBuilder.Create()
                                .WithCrossOriginEmbedderPolicy(CrossOriginEmbedderPolicyValue.RequireCorp)
                                .Build();
                        });
                    });
                    webBuilder.Configure(_ => { });
                })
                .Build();

            host.Start();
        });
    }

    private static Task<IHost> CreateHost(
        Action<Options.SimpleOwaspHeadersOptions> configure,
        Action<IApplicationBuilder>? extra = null) =>
        CreateHostInternal(configure, extra);

    private static async Task<IHost> CreateHostInternal(
        Action<Options.SimpleOwaspHeadersOptions> configure,
        Action<IApplicationBuilder>? extra)
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSimpleOwaspHeaders(configure);
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseSimpleOwaspHeaders();
                    extra?.Invoke(app);
                    if (extra is null)
                    {
                        app.Run(async context =>
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync("ok");
                        });
                    }
                });
            })
            .Build();

        await host.StartAsync();
        return host;
    }
}
