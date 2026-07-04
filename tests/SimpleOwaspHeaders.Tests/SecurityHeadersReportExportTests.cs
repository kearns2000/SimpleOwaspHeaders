using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SimpleOwaspHeaders;
using SimpleOwaspHeaders.Diagnostics;
using SimpleOwaspHeaders.Policies;

namespace SimpleOwaspHeaders.Tests;

public class SecurityHeadersReportExportTests
{
    [Theory]
    [InlineData(new[] { "--export-security-report", "./report.html" }, "./report.html")]
    [InlineData(new[] { "--export-security-report=./report.html" }, "./report.html")]
    [InlineData(new[] { "--generate-security-report", "./report.html" }, "./report.html")]
    [InlineData(new[] { "--generate-security-report=./report.html" }, "./report.html")]
    public void TryParseRequest_parses_cli_flags(string[] args, string expectedPath)
    {
        Environment.SetEnvironmentVariable(SecurityHeadersReportExporter.ReportPathEnvironmentVariable, null);

        var parsed = SecurityHeadersReportExporter.TryParseRequest(args, out var request);

        Assert.True(parsed);
        Assert.Equal(Path.GetFullPath(expectedPath), Path.GetFullPath(request.OutputPath));
    }

    [Fact]
    public void TryParseRequest_uses_environment_variable()
    {
        var outputPath = Path.Combine(Path.GetTempPath(), "ssh-env-report.html");
        Environment.SetEnvironmentVariable(SecurityHeadersReportExporter.ReportPathEnvironmentVariable, outputPath);

        try
        {
            var parsed = SecurityHeadersReportExporter.TryParseRequest([], out var request);

            Assert.True(parsed);
            Assert.Equal(Path.GetFullPath(outputPath), Path.GetFullPath(request.OutputPath));
        }
        finally
        {
            Environment.SetEnvironmentVariable(SecurityHeadersReportExporter.ReportPathEnvironmentVariable, null);
        }
    }

    [Fact]
    public void TryParseRequest_parses_format_flag()
    {
        Environment.SetEnvironmentVariable(SecurityHeadersReportExporter.ReportPathEnvironmentVariable, null);

        var parsed = SecurityHeadersReportExporter.TryParseRequest(
            ["--export-security-report=./report.html", "--export-security-report-format=json"],
            out var request);

        Assert.True(parsed);
        Assert.Equal(SecurityHeadersReportExportFormat.Json, request.Format);
    }

    [Fact]
    public void Export_writes_html_and_json_files()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ssh-export-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var htmlPath = Path.Combine(directory, "report.html");

        try
        {
            using var host = CreateConfiguredHost();
            SecurityHeadersReportExporter.Export(host.Services, new SecurityHeadersReportExportRequest
            {
                OutputPath = htmlPath,
                Format = SecurityHeadersReportExportFormat.Both
            });

            var jsonPath = Path.ChangeExtension(htmlPath, ".json");
            Assert.True(File.Exists(htmlPath));
            Assert.True(File.Exists(jsonPath));

            var html = File.ReadAllText(htmlPath);
            var json = File.ReadAllText(jsonPath);

            Assert.Contains("Configuration matrix", html);
            Assert.Contains("comparisons", json, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public async Task RunOrExportSecurityReportAsync_exports_without_starting_server()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ssh-export-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var htmlPath = Path.Combine(directory, "report.html");

        try
        {
            var host = await CreateWebHostAsync();
            using (host)
            {
                await host.RunOrExportSecurityReportAsync(
                    ["--export-security-report", htmlPath, "--export-security-report-format=html"]);
            }

            Assert.True(File.Exists(htmlPath));
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    private static IHost CreateConfiguredHost()
    {
        return new HostBuilder()
            .ConfigureServices(services =>
            {
                services.AddSimpleOwaspHeaders(options =>
                {
                    options.ForPath("/admin", policy => policy
                        .WithContentSecurityPolicy(csp => csp.ScriptSources("'none'")));
                });
            })
            .Build();
    }

    private static async Task<IHost> CreateWebHostAsync()
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSimpleOwaspHeaders(_ => { });
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseSimpleOwaspHeaders();
                });
            })
            .Build();

        await host.StartAsync();
        return host;
    }
}
