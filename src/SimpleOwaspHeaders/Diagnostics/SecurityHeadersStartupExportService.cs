using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SimpleOwaspHeaders.Diagnostics;

/// <summary>
/// Exports the security headers report during host startup when export flags or environment
/// variables are set, then stops the application. Enables MSBuild export without requiring
/// <c>RunOrExportSecurityReportAsync()</c>.
/// </summary>
internal sealed class SecurityHeadersStartupExportService : IHostedService
{
    private readonly IServiceProvider _services;
    private readonly IHostApplicationLifetime _lifetime;

    public SecurityHeadersStartupExportService(
        IServiceProvider services,
        IHostApplicationLifetime lifetime)
    {
        _services = services;
        _lifetime = lifetime;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var args = Environment.GetCommandLineArgs().Skip(1).ToArray();
        if (!SecurityHeadersReportExporter.TryExport(_services, args, out var exitCode))
        {
            return Task.CompletedTask;
        }

        Environment.ExitCode = exitCode;
        _lifetime.StopApplication();
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
