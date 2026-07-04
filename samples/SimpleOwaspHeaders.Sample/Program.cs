using SimpleOwaspHeaders;
using SimpleOwaspHeaders.Cookies;
using SimpleOwaspHeaders.Metadata;
using SimpleOwaspHeaders.Policies;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSimpleOwaspHeaders(builder.Configuration.GetSection("SimpleOwaspHeaders"));
builder.Services.Configure<SimpleOwaspHeaders.Options.SimpleOwaspHeadersOptions>(options =>
{
    options.AddNamedPolicy("Admin", policy => policy
        .WithContentSecurityPolicy(csp => csp
            .ScriptSources("'self'")
            .ObjectSources("'none'")
            .ImageSources("'self'", "data:")
            .BlockAllMixedContent()
            .UpgradeInsecureRequests()));

    options.ForPath("/admin", "Admin");

    options.ForPathRegex(@"^/api/public/.*", policy => policy
        .WithContentSecurityPolicy(csp => csp.DefaultSources("'none'")));

    options.WithClearSiteDataOnLogout();
});

builder.Services.AddSecureCookies();

var app = builder.Build();

app.UseSecureCookies();
app.UseSimpleOwaspHeaders();

app.MapGet("/", () => Results.Text("Default OWASP security headers.", "text/plain"));
app.MapGet("/admin", [SecureHeaders("Admin")] () => Results.Text("Admin named policy via endpoint metadata.", "text/plain"));
app.MapGet("/api/public/info", () => Results.Text("Regex path policy.", "text/plain"));
app.MapGet("/logout", () => Results.Text("Clear-Site-Data applied on logout path.", "text/plain"));
app.MapSimpleOwaspHeadersDiagnostics();

await app.RunOrExportSecurityReportAsync();

public static class SampleOptionsExtensions
{
    public static SimpleOwaspHeaders.Options.SimpleOwaspHeadersOptions WithClearSiteDataOnLogout(
        this SimpleOwaspHeaders.Options.SimpleOwaspHeadersOptions options)
    {
        var logoutPolicy = SecurityHeaderPolicyBuilder.Create()
            .WithClearSiteData(csd => csd.ForPath("/logout",
                SimpleOwaspHeaders.Policies.ClearSiteDataDirective.Cache,
                SimpleOwaspHeaders.Policies.ClearSiteDataDirective.Cookies,
                SimpleOwaspHeaders.Policies.ClearSiteDataDirective.Storage))
            .Build();

        options.DefaultPolicy = options.DefaultPolicy.Merge(logoutPolicy);
        return options;
    }
}
