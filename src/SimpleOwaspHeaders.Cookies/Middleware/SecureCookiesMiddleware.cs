using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace SimpleOwaspHeaders.Cookies.Middleware;

public sealed class SecureCookiesMiddleware(
    RequestDelegate next,
    IOptions<SecureCookieOptions> options)
{
    private const string SetCookieHeader = "Set-Cookie";
    private readonly SecureCookieOptions _options = options.Value;

    public async Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            if (!context.Response.Headers.TryGetValue(SetCookieHeader, out var cookies))
            {
                return Task.CompletedTask;
            }

            var updated = new List<string>(cookies.Count);
            foreach (var cookie in cookies)
            {
                if (string.IsNullOrEmpty(cookie))
                {
                    continue;
                }

                updated.Add(HardenCookie(cookie, context.Request.IsHttps));
            }

            context.Response.Headers.SetCookie = new StringValues([.. updated]);
            return Task.CompletedTask;
        });

        await next(context);
    }

    private string HardenCookie(string cookie, bool isHttps)
    {
        var result = cookie;

        if (_options.HttpOnly && !ContainsDirective(result, "httponly"))
        {
            result += "; HttpOnly";
        }

        if (_options.Secure && isHttps && !ContainsDirective(result, "secure"))
        {
            result += "; Secure";
        }

        if (!ContainsDirective(result, "samesite"))
        {
            result += $"; SameSite={MapSameSite(_options.SameSite)}";
        }

        return result;
    }

    private static bool ContainsDirective(string cookie, string directive) =>
        cookie.Contains(directive, StringComparison.OrdinalIgnoreCase);

    private static string MapSameSite(SameSiteMode mode) => mode switch
    {
        SameSiteMode.Strict => "Strict",
        SameSiteMode.Lax => "Lax",
        SameSiteMode.None => "None",
        _ => "Strict"
    };
}
