using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SimpleOwaspHeaders.Configuration;
using SimpleOwaspHeaders.Diagnostics;
using SimpleOwaspHeaders.Matching;
using SimpleOwaspHeaders.Middleware;
using SimpleOwaspHeaders.Options;
using SimpleOwaspHeaders.Policies;
using SimpleOwaspHeaders.Validation;

namespace SimpleOwaspHeaders;

public static class SimpleOwaspHeadersServiceCollectionExtensions
{
    public static IServiceCollection AddSimpleOwaspHeaders(this IServiceCollection services) =>
        services.AddSimpleOwaspHeaders(_ => { });

    public static IServiceCollection AddSimpleOwaspHeaders(
        this IServiceCollection services,
        Action<SimpleOwaspHeadersOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<SimpleOwaspHeadersOptions>()
            .Configure(options =>
            {
                options.DefaultPolicyConfiguredInCode = true;
                configure(options);
            })
            .ValidateOnStart();

        RegisterCore(services);
        return services;
    }

    public static IServiceCollection AddSimpleOwaspHeaders(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<SimpleOwaspHeadersOptions>()
            .Bind(configuration)
            .ValidateOnStart();

        RegisterCore(services);
        return services;
    }

    private static void RegisterCore(IServiceCollection services)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<SimpleOwaspHeadersOptions>, SimpleOwaspHeadersOptionsValidator>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPostConfigureOptions<SimpleOwaspHeadersOptions>, SimpleOwaspHeadersOptionsPostConfigure>());

        services.AddSingleton<SecurityHeaderPolicyResolver>();
        services.AddHostedService<SecurityHeadersStartupExportService>();
    }
}

public static class SimpleOwaspHeadersApplicationBuilderExtensions
{
    public static IApplicationBuilder UseSimpleOwaspHeaders(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<SimpleOwaspHeadersMiddleware>();
    }
}

public static class SimpleOwaspHeadersEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps development diagnostics routes when enabled in options and the host
    /// environment is Development:
    /// GET /_simple-owasp-headers (JSON), GET /_simple-owasp-headers/report (HTML),
    /// GET /_simple-owasp-headers/matrix (HTML configuration matrix).
    /// </summary>
    public static IEndpointRouteBuilder MapSimpleOwaspHeadersDiagnostics(this IEndpointRouteBuilder endpoints)
    {
        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<SimpleOwaspHeadersOptions>>().Value;
        if (!options.EnableDiagnosticsEndpoint)
        {
            return endpoints;
        }

        var environment = endpoints.ServiceProvider.GetService<IHostEnvironment>();
        if (environment is not null && !environment.IsDevelopment())
        {
            return endpoints;
        }

        var resolver = endpoints.ServiceProvider.GetRequiredService<SecurityHeaderPolicyResolver>();

        endpoints.MapGet("/_simple-owasp-headers", (HttpContext context) =>
        {
            if (WantsHtml(context))
            {
                var previewPath = context.Request.Query["path"].ToString();
                if (string.IsNullOrWhiteSpace(previewPath))
                {
                    previewPath = "/";
                }

                var report = SecurityHeadersReportBuilder.Build(options, resolver, previewPath);
                return Results.Content(SecurityHeadersHtmlRenderer.Render(report), "text/html; charset=utf-8");
            }

            var resolution = resolver.ResolveDetails(context);
            return Results.Json(BuildDiagnosticsPayload(context, options, resolution));
        });

        endpoints.MapGet("/_simple-owasp-headers/report", (HttpContext context) =>
        {
            var previewPath = context.Request.Query["path"].ToString();
            if (string.IsNullOrWhiteSpace(previewPath))
            {
                previewPath = "/";
            }

            var report = SecurityHeadersReportBuilder.Build(options, resolver, previewPath);
            return Results.Content(SecurityHeadersHtmlRenderer.Render(report), "text/html; charset=utf-8");
        });

        endpoints.MapGet("/_simple-owasp-headers/matrix", (HttpContext context) =>
        {
            var matrix = SecurityHeadersMatrixBuilder.Build(options, resolver);
            if (WantsJson(context))
            {
                return Results.Json(SecurityHeadersMatrixSerializer.CreatePayload(matrix));
            }

            return Results.Content(SecurityHeadersHtmlRenderer.RenderMatrix(matrix), "text/html; charset=utf-8");
        });

        return endpoints;
    }

    private static bool WantsJson(HttpContext context)
    {
        var format = context.Request.Query["format"].ToString();
        return format.Equals("json", StringComparison.OrdinalIgnoreCase);
    }

    private static bool WantsHtml(HttpContext context)
    {
        var format = context.Request.Query["format"].ToString();
        return format.Equals("html", StringComparison.OrdinalIgnoreCase);
    }

    private static object BuildDiagnosticsPayload(
        HttpContext context,
        SimpleOwaspHeadersOptions options,
        PolicyResolutionDetails resolution)
    {
        var path = context.Request.Path.Value ?? "/";
        var headers = resolution.IsIgnored
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : resolution.EffectivePolicy.BuildHeaders(context)
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);

        if (!resolution.IsIgnored)
        {
            var clearSiteData = resolution.EffectivePolicy.ClearSiteData?.ResolveForPath(path);
            if (!string.IsNullOrEmpty(clearSiteData))
            {
                headers["Clear-Site-Data"] = clearSiteData;
            }
        }

        return new
        {
            path,
            preset = options.DefaultPreset,
            ignored = resolution.IsIgnored,
            resolution = resolution.Steps.Select(step => step.Source),
            headers
        };
    }
}

public static class SimpleOwaspHeadersOptionsExtensions
{
    public static SimpleOwaspHeadersOptions UsePreset(this SimpleOwaspHeadersOptions options, string presetName)
    {
        options.DefaultPreset = presetName;
        options.DefaultPolicy = SecurityHeaderPresets.ResolveOrDefault(presetName);
        options.DefaultPolicyConfiguredInCode = true;
        return options;
    }

    public static SimpleOwaspHeadersOptions AddNamedPolicy(
        this SimpleOwaspHeadersOptions options,
        string name,
        Action<SecurityHeaderPolicyBuilder> configure)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = SecurityHeaderPolicyBuilder.Create();
        configure(builder);
        options.NamedPolicies[name] = builder.Build();
        return options;
    }

    public static SimpleOwaspHeadersOptions ForPath(
        this SimpleOwaspHeadersOptions options,
        string pathPrefix,
        Action<SecurityHeaderPolicyBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(pathPrefix);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = SecurityHeaderPolicyBuilder.Create();
        configure(builder);

        options.PathPolicies.Add(new PathSecurityHeaderPolicy
        {
            Pattern = pathPrefix,
            MatchKind = PathMatchKind.Prefix,
            Policy = builder.Build()
        });

        return options;
    }

    public static SimpleOwaspHeadersOptions ForPathRegex(
        this SimpleOwaspHeadersOptions options,
        string pattern,
        Action<SecurityHeaderPolicyBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(pattern);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = SecurityHeaderPolicyBuilder.Create();
        configure(builder);

        options.PathPolicies.Add(new PathSecurityHeaderPolicy
        {
            Pattern = pattern,
            MatchKind = PathMatchKind.Regex,
            Policy = builder.Build()
        });

        return options;
    }

    public static SimpleOwaspHeadersOptions ForPath(
        this SimpleOwaspHeadersOptions options,
        string pathPrefix,
        string namedPolicy)
    {
        options.PathPolicies.Add(new PathSecurityHeaderPolicy
        {
            Pattern = pathPrefix,
            MatchKind = PathMatchKind.Prefix,
            NamedPolicy = namedPolicy
        });

        return options;
    }

    public static SimpleOwaspHeadersOptions IgnorePath(this SimpleOwaspHeadersOptions options, string path)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        options.IgnoredPaths.Add(path);
        return options;
    }
}
