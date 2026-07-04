using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SimpleOwaspHeaders.Cookies;

namespace SimpleOwaspHeaders.Tests;

public class SecureCookiesTests
{
    [Fact]
    public async Task Adds_httponly_and_secure_to_set_cookie()
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services => services.AddSecureCookies());
                webBuilder.Configure(app =>
                {
                    app.UseSecureCookies();
                    app.Run(context =>
                    {
                        context.Response.Cookies.Append("session", "abc123");
                        return Task.CompletedTask;
                    });
                });
            })
            .Build();

        await host.StartAsync();
        using (host)
        {
            var client = host.GetTestClient();
            var response = await client.GetAsync("/");

            var cookie = response.Headers.GetValues("Set-Cookie").Single();
            Assert.Contains("HttpOnly", cookie, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("SameSite=Strict", cookie, StringComparison.OrdinalIgnoreCase);
        }
    }
}
