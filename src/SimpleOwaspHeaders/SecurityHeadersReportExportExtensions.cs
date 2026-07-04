using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;
using SimpleOwaspHeaders.Diagnostics;

namespace SimpleOwaspHeaders;

public static class SecurityHeadersReportExportExtensions
{
    /// <summary>
    /// Exports the configuration matrix and exits when
    /// <c>--export-security-report</c> or <c>SIMPLE_OWASP_HEADERS_REPORT_PATH</c> is set;
    /// otherwise runs the application normally.
    /// </summary>
    public static async Task RunOrExportSecurityReportAsync(
        this WebApplication app,
        string[]? args = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(app);

        if (SecurityHeadersReportExporter.TryExport(app.Services, ResolveExportArgs(args), out _))
        {
            return;
        }

        await app.RunAsync(cancellationToken);
    }

    /// <summary>
    /// Exports the configuration matrix and exits when configured; otherwise runs the host normally.
    /// </summary>
    public static async Task RunOrExportSecurityReportAsync(
        this IHost host,
        string[]? args = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(host);

        if (SecurityHeadersReportExporter.TryExport(host.Services, ResolveExportArgs(args), out _))
        {
            return;
        }

        await host.RunAsync(cancellationToken);
    }

    /// <summary>
    /// Writes the configuration matrix to disk using the resolved service configuration.
    /// </summary>
    public static void ExportSecurityHeadersReport(
        this WebApplication app,
        SecurityHeadersReportExportRequest request)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(request);
        SecurityHeadersReportExporter.Export(app.Services, request);
    }

    /// <summary>
    /// Writes the configuration matrix to disk using the resolved service configuration.
    /// </summary>
    public static void ExportSecurityHeadersReport(
        this IHost host,
        SecurityHeadersReportExportRequest request)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(request);
        SecurityHeadersReportExporter.Export(host.Services, request);
    }

    private static string[] ResolveExportArgs(string[]? args) =>
        args is { Length: > 0 } ? args : [.. Environment.GetCommandLineArgs().Skip(1)];
}
