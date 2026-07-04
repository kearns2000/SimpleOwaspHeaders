using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SimpleOwaspHeaders.Matching;
using SimpleOwaspHeaders.Options;

namespace SimpleOwaspHeaders.Diagnostics;

public enum SecurityHeadersReportExportFormat
{
    Html,
    Json,
    Both
}

public sealed class SecurityHeadersReportExportRequest
{
    public required string OutputPath { get; init; }

    public SecurityHeadersReportExportFormat Format { get; init; } = SecurityHeadersReportExportFormat.Both;
}

public static class SecurityHeadersReportExporter
{
    public const string ExportFlag = "--export-security-report";
    public const string ExportFlagAlias = "--generate-security-report";
    public const string FormatFlag = "--export-security-report-format";
    public const string ReportPathEnvironmentVariable = "SIMPLE_OWASP_HEADERS_REPORT_PATH";
    public const string ReportFormatEnvironmentVariable = "SIMPLE_OWASP_HEADERS_REPORT_FORMAT";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static bool TryExport(IServiceProvider services, string[] args, out int exitCode)
    {
        exitCode = 0;

        if (!TryParseRequest(args, out var request))
        {
            return false;
        }

        try
        {
            Export(services, request);
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to export SimpleOwaspHeaders report: {ex.Message}");
            exitCode = 1;
            return true;
        }
    }

    public static void Export(IServiceProvider services, SecurityHeadersReportExportRequest request)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(request);

        var options = services.GetRequiredService<IOptions<SimpleOwaspHeadersOptions>>().Value;
        var resolver = services.GetRequiredService<SecurityHeaderPolicyResolver>();
        var matrix = SecurityHeadersMatrixBuilder.Build(options, resolver);

        var outputPath = Path.GetFullPath(request.OutputPath);
        var outputDirectory = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
        }

        switch (request.Format)
        {
            case SecurityHeadersReportExportFormat.Html:
                WriteHtml(outputPath, matrix);
                Console.WriteLine($"SimpleOwaspHeaders report written to {outputPath}");
                break;
            case SecurityHeadersReportExportFormat.Json:
                WriteJson(outputPath, matrix);
                Console.WriteLine($"SimpleOwaspHeaders report written to {outputPath}");
                break;
            case SecurityHeadersReportExportFormat.Both:
                var htmlPath = outputPath;
                var jsonPath = Path.ChangeExtension(outputPath, ".json");
                if (string.Equals(Path.GetExtension(outputPath), ".json", StringComparison.OrdinalIgnoreCase))
                {
                    jsonPath = outputPath;
                    htmlPath = Path.ChangeExtension(outputPath, ".html");
                }

                WriteHtml(htmlPath, matrix);
                WriteJson(jsonPath, matrix);
                Console.WriteLine($"SimpleOwaspHeaders reports written to {htmlPath} and {jsonPath}");
                break;
        }
    }

    public static bool TryParseRequest(string[] args, out SecurityHeadersReportExportRequest request)
    {
        request = null!;

        var outputPath = Environment.GetEnvironmentVariable(ReportPathEnvironmentVariable);
        ParseArgs(args, ref outputPath, out var formatFromArgs);

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            return false;
        }

        var format = formatFromArgs ?? ParseFormat(Environment.GetEnvironmentVariable(ReportFormatEnvironmentVariable))
            ?? SecurityHeadersReportExportFormat.Both;

        request = new SecurityHeadersReportExportRequest
        {
            OutputPath = outputPath,
            Format = format
        };

        return true;
    }

    private static void ParseArgs(string[] args, ref string? outputPath, out SecurityHeadersReportExportFormat? format)
    {
        format = null;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (TryReadFlagValue(arg, ExportFlag, out var exportValue) ||
                TryReadFlagValue(arg, ExportFlagAlias, out exportValue))
            {
                outputPath = exportValue ?? ReadNextArg(args, ref i);
                continue;
            }

            if (TryReadFlagValue(arg, FormatFlag, out var formatValue))
            {
                format = ParseFormat(formatValue ?? ReadNextArg(args, ref i));
            }
        }
    }

    private static bool TryReadFlagValue(string arg, string flag, out string? value)
    {
        if (arg.Equals(flag, StringComparison.OrdinalIgnoreCase))
        {
            value = null;
            return true;
        }

        if (arg.StartsWith(flag + "=", StringComparison.OrdinalIgnoreCase))
        {
            value = arg[(flag.Length + 1)..];
            return true;
        }

        value = null;
        return false;
    }

    private static string? ReadNextArg(string[] args, ref int index) =>
        index + 1 < args.Length ? args[++index] : null;

    private static SecurityHeadersReportExportFormat? ParseFormat(string? value) =>
        value?.Trim().ToLowerInvariant() switch
        {
            "html" => SecurityHeadersReportExportFormat.Html,
            "json" => SecurityHeadersReportExportFormat.Json,
            "both" => SecurityHeadersReportExportFormat.Both,
            _ => null
        };

    private static void WriteHtml(string path, SecurityHeadersConfigurationMatrix matrix) =>
        File.WriteAllText(path, SecurityHeadersHtmlRenderer.RenderMatrix(matrix));

    private static void WriteJson(string path, SecurityHeadersConfigurationMatrix matrix)
    {
        var payload = SecurityHeadersMatrixSerializer.CreatePayload(matrix);
        File.WriteAllText(path, JsonSerializer.Serialize(payload, JsonOptions));
    }
}

internal static class SecurityHeadersMatrixSerializer
{
    public static object CreatePayload(SecurityHeadersConfigurationMatrix matrix) => new
    {
        preset = matrix.DefaultPreset,
        scenarios = matrix.Scenarios.Select(scenario => new
        {
            label = scenario.Label,
            path = scenario.SamplePath,
            ignored = scenario.IsIgnored,
            resolution = scenario.ResolutionSteps,
            headers = scenario.Headers
        }),
        namedPolicies = matrix.NamedPolicies.Select(named => new
        {
            name = named.Name,
            referencedBy = named.ReferencedBy,
            headers = named.MergedHeaders
        }),
        comparisons = matrix.HeaderComparisons.Select(row => new
        {
            header = row.HeaderName,
            differsFromDefault = row.DiffersFromDefault,
            values = row.Cells.ToDictionary(cell => cell.ScenarioLabel, cell => cell.Value)
        })
    };
}
