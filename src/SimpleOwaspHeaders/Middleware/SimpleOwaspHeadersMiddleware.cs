using SimpleOwaspHeaders.Headers;
using SimpleOwaspHeaders.Extensions;
using SimpleOwaspHeaders.Matching;
using SimpleOwaspHeaders.Options;

namespace SimpleOwaspHeaders.Middleware;

public sealed partial class SimpleOwaspHeadersMiddleware(
    RequestDelegate next,
    IOptions<SimpleOwaspHeadersOptions> options,
    SecurityHeaderPolicyResolver policyResolver,
    ILogger<SimpleOwaspHeadersMiddleware> logger)
{
    private readonly SimpleOwaspHeadersOptions _options = options.Value;

    public async Task InvokeAsync(HttpContext context)
    {
        if (ShouldIgnore(context.Request.Path))
        {
            await next(context);
            return;
        }

        var policy = policyResolver.Resolve(context);
        var headers = policy.BuildHeaders(context);

        foreach (var (name, value) in headers)
        {
            context.TryAddSecurityHeader(name, value);
        }

        var clearSiteData = policy.ClearSiteData?.ResolveForPath(context.Request.Path.Value ?? string.Empty);
        if (!string.IsNullOrEmpty(clearSiteData))
        {
            context.TryAddSecurityHeader(HeaderNames.ClearSiteData, clearSiteData);
        }

        LogHeadersApplied(headers.Count, context.Request.Path.Value);

        await next(context);
    }

    private bool ShouldIgnore(PathString path)
    {
        if (_options.IgnoredPaths.Count == 0 || !path.HasValue)
        {
            return false;
        }

        var value = path.Value!;
        return _options.IgnoredPaths.Any(
            ignored => value.Equals(ignored, StringComparison.OrdinalIgnoreCase));
    }

    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Debug,
        Message = "Applied {HeaderCount} security headers for {RequestPath}")]
    private partial void LogHeadersApplied(int headerCount, string? requestPath);
}
