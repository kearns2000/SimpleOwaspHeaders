using SimpleOwaspHeaders.Matching;
using SimpleOwaspHeaders.Options;

namespace SimpleOwaspHeaders.Diagnostics;

public sealed class SecurityHeadersConfigurationMatrix
{
    public required string DefaultPreset { get; init; }

    public required IReadOnlyList<PolicyScenarioRow> Scenarios { get; init; }

    public required IReadOnlyList<NamedPolicySummary> NamedPolicies { get; init; }

    public required IReadOnlyList<HeaderComparisonRow> HeaderComparisons { get; init; }
}

public sealed class PolicyScenarioRow
{
    public required string Label { get; init; }

    public required string SamplePath { get; init; }

    public required IReadOnlyList<string> ResolutionSteps { get; init; }

    public required bool IsIgnored { get; init; }

    public required IReadOnlyDictionary<string, string> Headers { get; init; }
}

public sealed class NamedPolicySummary
{
    public required string Name { get; init; }

    public required IReadOnlyList<string> ReferencedBy { get; init; }

    public required IReadOnlyDictionary<string, string> MergedHeaders { get; init; }
}

public sealed class HeaderComparisonRow
{
    public required string HeaderName { get; init; }

    public required IReadOnlyList<HeaderComparisonCell> Cells { get; init; }

    public bool DiffersFromDefault { get; init; }
}

public sealed class HeaderComparisonCell
{
    public required string ScenarioLabel { get; init; }

    public string? Value { get; init; }

    public bool DiffersFromDefault { get; init; }
}

internal static class SecurityHeadersMatrixBuilder
{
    public static SecurityHeadersConfigurationMatrix Build(
        SimpleOwaspHeadersOptions options,
        SecurityHeaderPolicyResolver resolver)
    {
        var scenarios = BuildScenarios(options, resolver);
        var namedPolicies = BuildNamedPolicies(options, resolver);

        return new SecurityHeadersConfigurationMatrix
        {
            DefaultPreset = options.DefaultPreset,
            Scenarios = scenarios,
            NamedPolicies = namedPolicies,
            HeaderComparisons = BuildHeaderComparisons(scenarios)
        };
    }

    private static List<PolicyScenarioRow> BuildScenarios(
        SimpleOwaspHeadersOptions options,
        SecurityHeaderPolicyResolver resolver)
    {
        var scenarios = new List<PolicyScenarioRow>();
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        AddScenario(
            scenarios,
            seenPaths,
            resolver,
            "/",
            "Default policy",
            isIgnored: false);

        foreach (var pathPolicy in options.PathPolicies)
        {
            if (string.IsNullOrWhiteSpace(pathPolicy.Pattern))
            {
                continue;
            }

            var samplePath = SecurityHeadersDiagnosticsShared.GetSamplePath(pathPolicy);
            AddScenario(
                scenarios,
                seenPaths,
                resolver,
                samplePath,
                SecurityHeadersDiagnosticsShared.DescribePathPolicy(pathPolicy),
                isIgnored: false);
        }

        foreach (var ignored in options.IgnoredPaths)
        {
            if (string.IsNullOrWhiteSpace(ignored))
            {
                continue;
            }

            AddScenario(
                scenarios,
                seenPaths,
                resolver,
                ignored,
                $"Ignored path {ignored}",
                isIgnored: true);
        }

        return scenarios;
    }

    private static void AddScenario(
        List<PolicyScenarioRow> scenarios,
        HashSet<string> seenPaths,
        SecurityHeaderPolicyResolver resolver,
        string samplePath,
        string label,
        bool isIgnored)
    {
        if (!seenPaths.Add(samplePath))
        {
            return;
        }

        var normalizedPath = SecurityHeadersDiagnosticsShared.NormalizePath(samplePath);
        var resolution = resolver.ResolveDetailsForPath(normalizedPath);

        scenarios.Add(new PolicyScenarioRow
        {
            Label = label,
            SamplePath = normalizedPath,
            ResolutionSteps = resolution.Steps.Select(step => step.Source).ToList(),
            IsIgnored = resolution.IsIgnored || isIgnored,
            Headers = SecurityHeadersDiagnosticsShared.BuildHeadersFromResolution(resolution, normalizedPath)
        });
    }

    private static List<NamedPolicySummary> BuildNamedPolicies(
        SimpleOwaspHeadersOptions options,
        SecurityHeaderPolicyResolver resolver)
    {
        var summaries = new List<NamedPolicySummary>();

        foreach (var (name, policy) in options.NamedPolicies)
        {
            var references = options.PathPolicies
                .Where(pathPolicy => string.Equals(pathPolicy.NamedPolicy, name, StringComparison.OrdinalIgnoreCase))
                .Select(SecurityHeadersDiagnosticsShared.DescribePathPolicy)
                .ToList();

            var merged = resolver.DefaultPolicy.Merge(policy);
            summaries.Add(new NamedPolicySummary
            {
                Name = name,
                ReferencedBy = references,
                MergedHeaders = SecurityHeadersDiagnosticsShared.BuildHeadersFromPolicy(merged)
            });
        }

        return summaries
            .OrderBy(summary => summary.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<HeaderComparisonRow> BuildHeaderComparisons(IReadOnlyList<PolicyScenarioRow> scenarios)
    {
        var activeScenarios = scenarios.Where(scenario => !scenario.IsIgnored).ToList();
        if (activeScenarios.Count == 0)
        {
            return [];
        }

        var defaultScenario = activeScenarios.FirstOrDefault(scenario => scenario.SamplePath == "/")
            ?? activeScenarios[0];

        var headerNames = activeScenarios
            .SelectMany(scenario => scenario.Headers.Keys)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var comparisons = new List<HeaderComparisonRow>();

        foreach (var headerName in headerNames)
        {
            var defaultValue = defaultScenario.Headers.GetValueOrDefault(headerName);
            var cells = activeScenarios
                .Select(scenario =>
                {
                    var value = scenario.Headers.GetValueOrDefault(headerName);
                    return new HeaderComparisonCell
                    {
                        ScenarioLabel = scenario.Label,
                        Value = value,
                        DiffersFromDefault = !string.Equals(value, defaultValue, StringComparison.Ordinal)
                    };
                })
                .ToList();

            comparisons.Add(new HeaderComparisonRow
            {
                HeaderName = headerName,
                Cells = cells,
                DiffersFromDefault = cells.Any(cell => cell.DiffersFromDefault)
            });
        }

        return comparisons;
    }
}
