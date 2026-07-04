using SimpleOwaspHeaders.Matching;
using SimpleOwaspHeaders.Policies;

namespace SimpleOwaspHeaders.Options;

public sealed class PathSecurityHeaderPolicy
{
    /// <summary>
    /// Path prefix or regex pattern depending on <see cref="MatchKind"/>.
    /// </summary>
    public string Pattern { get; set; } = string.Empty;

    public PathMatchKind MatchKind { get; set; } = PathMatchKind.Prefix;

    /// <summary>
    /// Optional named policy registered in <see cref="SimpleOwaspHeadersOptions.NamedPolicies"/>.
    /// When set, <see cref="Policy"/> is ignored.
    /// </summary>
    public string? NamedPolicy { get; set; }

    public SecurityHeaderPolicy? Policy { get; set; }
}

public sealed class SimpleOwaspHeadersOptions
{
    /// <summary>
    /// Preset name from configuration: OwaspRecommended, Strict, ApiOnly.
    /// Ignored when <see cref="DefaultPolicy"/> is assigned in code.
    /// </summary>
    public string DefaultPreset { get; set; } = "OwaspRecommended";

    public SecurityHeaderPolicy DefaultPolicy { get; set; } = SecurityHeaderPolicy.OwaspRecommended;

    public bool DefaultPolicyConfiguredInCode { get; set; }

    public IDictionary<string, SecurityHeaderPolicy> NamedPolicies { get; } =
        new Dictionary<string, SecurityHeaderPolicy>(StringComparer.OrdinalIgnoreCase);

    public IList<PathSecurityHeaderPolicy> PathPolicies { get; } = [];

    public IList<string> IgnoredPaths { get; } = [];

    /// <summary>
    /// When true, exposes GET /_simple-owasp-headers (JSON), /report (HTML), and /matrix (HTML).
    /// </summary>
    public bool EnableDiagnosticsEndpoint { get; set; }
}
