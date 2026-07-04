using SimpleOwaspHeaders.Policies;

namespace SimpleOwaspHeaders.Diagnostics;

public sealed class PolicyResolutionDetails
{
    public required string RequestPath { get; init; }

    public required SecurityHeaderPolicy EffectivePolicy { get; init; }

    public required IReadOnlyList<PolicyResolutionStep> Steps { get; init; }

    public bool IsIgnored { get; init; }

    public static PolicyResolutionDetails Ignored(string path) => new()
    {
        RequestPath = path,
        EffectivePolicy = new SecurityHeaderPolicy(),
        Steps = [],
        IsIgnored = true
    };
}

public sealed class PolicyResolutionStep
{
    public required string Source { get; init; }

    public required SecurityHeaderPolicy Policy { get; init; }

    public PolicyResolutionRole Role { get; init; }
}

public enum PolicyResolutionRole
{
    Base,
    Override
}
