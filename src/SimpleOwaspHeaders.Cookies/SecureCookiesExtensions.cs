using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using SimpleOwaspHeaders.Cookies.Middleware;

namespace SimpleOwaspHeaders.Cookies;

public static class SecureCookiesExtensions
{
    public static IServiceCollection AddSecureCookies(
        this IServiceCollection services,
        Action<SecureCookieOptions>? configure = null)
    {
        if (configure is not null)
        {
            services.Configure(configure);
        }
        else
        {
            services.AddOptions<SecureCookieOptions>();
        }

        return services;
    }

    public static IApplicationBuilder UseSecureCookies(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<SecureCookiesMiddleware>();
    }
}
