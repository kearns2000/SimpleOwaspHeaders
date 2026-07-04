using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using SimpleOwaspHeaders.Diagnostics;
using SimpleOwaspHeaders.Metadata;
using SimpleOwaspHeaders.Options;
using SimpleOwaspHeaders.Policies;

namespace SimpleOwaspHeaders.Matching;

public sealed class SecurityHeaderPolicyResolver
{
    private static readonly TimeSpan RegexMatchTimeout = TimeSpan.FromMilliseconds(100);

    private readonly SecurityHeaderPolicy _defaultPolicy;
    private readonly IReadOnlyDictionary<string, SecurityHeaderPolicy> _namedPolicies;
    private readonly IReadOnlyList<PathPolicyEntry> _pathPolicies;
    private readonly IReadOnlyList<string> _ignoredPaths;

    public SecurityHeaderPolicyResolver(IOptions<SimpleOwaspHeadersOptions> options)
    {
        var config = options.Value;
        _defaultPolicy = config.DefaultPolicy;
        _namedPolicies = config.NamedPolicies as IReadOnlyDictionary<string, SecurityHeaderPolicy>
            ?? new Dictionary<string, SecurityHeaderPolicy>(config.NamedPolicies);
        _ignoredPaths = config.IgnoredPaths.ToList();

        _pathPolicies = config.PathPolicies
            .Select(CreatePathEntry)
            .Where(e => e is not null)
            .Cast<PathPolicyEntry>()
            .OrderByDescending(e => e.Priority)
            .ToList();
    }

    public SecurityHeaderPolicy Resolve(HttpContext context) =>
        ResolveDetails(context).EffectivePolicy;

    public PolicyResolutionDetails ResolveDetails(HttpContext context)
    {
        var path = context.Request.Path.HasValue ? context.Request.Path.Value! : "/";

        if (IsIgnored(path))
        {
            return PolicyResolutionDetails.Ignored(path);
        }

        var attribute = context.GetEndpoint()?.Metadata.GetMetadata<SecureHeadersAttribute>();
        if (attribute is not null)
        {
            if (!_namedPolicies.TryGetValue(attribute.PolicyName, out var endpointPolicy))
            {
                throw new InvalidOperationException(
                    $"Named security header policy '{attribute.PolicyName}' was not found. " +
                    "Register it via SimpleOwaspHeadersOptions.NamedPolicies.");
            }

            return BuildDetails(
                path,
                endpointPolicy,
                $"Endpoint [SecureHeaders(\"{attribute.PolicyName}\")]");
        }

        return ResolveDetailsForPath(path);
    }

    public PolicyResolutionDetails ResolveDetailsForPath(string path)
    {
        if (IsIgnored(path))
        {
            return PolicyResolutionDetails.Ignored(path);
        }

        foreach (var entry in _pathPolicies)
        {
            if (entry.IsMatch(path))
            {
                return BuildDetails(path, entry.Policy, entry.SourceDescription);
            }
        }

        return BuildDetails(path, null, null);
    }

    public SecurityHeaderPolicy DefaultPolicy => _defaultPolicy;

    private PolicyResolutionDetails BuildDetails(
        string path,
        SecurityHeaderPolicy? overridePolicy,
        string? overrideSource)
    {
        var steps = new List<PolicyResolutionStep>
        {
            new()
            {
                Source = "Default policy",
                Policy = _defaultPolicy,
                Role = PolicyResolutionRole.Base
            }
        };

        var effective = _defaultPolicy;

        if (overridePolicy is not null && overrideSource is not null)
        {
            effective = effective.Merge(overridePolicy);
            steps.Add(new PolicyResolutionStep
            {
                Source = overrideSource,
                Policy = overridePolicy,
                Role = PolicyResolutionRole.Override
            });
        }

        return new PolicyResolutionDetails
        {
            RequestPath = path,
            EffectivePolicy = effective,
            Steps = steps,
            IsIgnored = false
        };
    }

    private bool IsIgnored(string path) =>
        _ignoredPaths.Any(ignored => path.Equals(ignored, StringComparison.OrdinalIgnoreCase));

    private PathPolicyEntry? CreatePathEntry(PathSecurityHeaderPolicy pathPolicy)
    {
        SecurityHeaderPolicy? policy = null;
        string? namedPolicy = null;

        if (!string.IsNullOrWhiteSpace(pathPolicy.NamedPolicy))
        {
            namedPolicy = pathPolicy.NamedPolicy;
            if (!_namedPolicies.TryGetValue(namedPolicy, out policy))
            {
                throw new InvalidOperationException(
                    $"Path policy references unknown named policy '{pathPolicy.NamedPolicy}'.");
            }
        }
        else
        {
            policy = pathPolicy.Policy;
        }

        if (policy is null)
        {
            return null;
        }

        Regex? regex = null;
        if (pathPolicy.MatchKind == PathMatchKind.Regex)
        {
            regex = new Regex(
                pathPolicy.Pattern,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                RegexMatchTimeout);
        }

        return new PathPolicyEntry(pathPolicy.Pattern, pathPolicy.MatchKind, regex, policy, namedPolicy);
    }

    private sealed class PathPolicyEntry
    {
        public PathPolicyEntry(
            string pattern,
            PathMatchKind kind,
            Regex? regex,
            SecurityHeaderPolicy policy,
            string? namedPolicy)
        {
            Pattern = pattern;
            Kind = kind;
            Regex = regex;
            Policy = policy;
            NamedPolicy = namedPolicy;
            Priority = kind == PathMatchKind.Prefix ? pattern.Length : 10_000;
            SourceDescription = kind switch
            {
                PathMatchKind.Prefix when !string.IsNullOrWhiteSpace(namedPolicy) =>
                    $"Path prefix \"{pattern}\" (named policy \"{namedPolicy}\")",
                PathMatchKind.Prefix => $"Path prefix \"{pattern}\"",
                PathMatchKind.Regex when !string.IsNullOrWhiteSpace(namedPolicy) =>
                    $"Path regex \"{pattern}\" (named policy \"{namedPolicy}\")",
                PathMatchKind.Regex => $"Path regex \"{pattern}\"",
                _ => pattern
            };
        }

        public string Pattern { get; }
        public PathMatchKind Kind { get; }
        public Regex? Regex { get; }
        public SecurityHeaderPolicy Policy { get; }
        public string? NamedPolicy { get; }
        public int Priority { get; }
        public string SourceDescription { get; }

        public bool IsMatch(string path) => Kind switch
        {
            PathMatchKind.Prefix => path.StartsWith(Pattern, StringComparison.OrdinalIgnoreCase),
            PathMatchKind.Regex => TryRegexMatch(path),
            _ => false
        };

        private bool TryRegexMatch(string path)
        {
            if (Regex is null)
            {
                return false;
            }

            try
            {
                return Regex.IsMatch(path);
            }
            catch (RegexMatchTimeoutException)
            {
                return false;
            }
        }
    }
}
