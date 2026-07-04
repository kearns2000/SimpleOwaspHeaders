using Microsoft.Extensions.Options;
using SimpleOwaspHeaders.Matching;
using SimpleOwaspHeaders.Options;

namespace SimpleOwaspHeaders.Validation;

internal sealed class SimpleOwaspHeadersOptionsValidator : IValidateOptions<SimpleOwaspHeadersOptions>
{
    public ValidateOptionsResult Validate(string? name, SimpleOwaspHeadersOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var failures = new List<string>();

        try
        {
            options.DefaultPolicy.BuildHeaders();
        }
        catch (Exception ex)
        {
            failures.Add($"DefaultPolicy is invalid: {ex.Message}");
        }

        foreach (var (policyName, policy) in options.NamedPolicies)
        {
            try
            {
                options.DefaultPolicy.Merge(policy).BuildHeaders();
            }
            catch (Exception ex)
            {
                failures.Add($"Named policy '{policyName}' is invalid: {ex.Message}");
            }
        }

        foreach (var pathPolicy in options.PathPolicies)
        {
            if (string.IsNullOrWhiteSpace(pathPolicy.Pattern) &&
                string.IsNullOrWhiteSpace(pathPolicy.NamedPolicy))
            {
                failures.Add("PathPolicies contains an entry with no Pattern or NamedPolicy.");
                continue;
            }

            if (pathPolicy.MatchKind == PathMatchKind.Prefix &&
                !string.IsNullOrWhiteSpace(pathPolicy.Pattern) &&
                !pathPolicy.Pattern.StartsWith('/'))
            {
                failures.Add($"Prefix path policy '{pathPolicy.Pattern}' must start with '/'.");
            }

            if (pathPolicy.MatchKind == PathMatchKind.Regex &&
                !string.IsNullOrWhiteSpace(pathPolicy.Pattern))
            {
                try
                {
                    _ = new System.Text.RegularExpressions.Regex(pathPolicy.Pattern);
                }
                catch (Exception ex)
                {
                    failures.Add($"Regex path policy '{pathPolicy.Pattern}' is invalid: {ex.Message}");
                }
            }
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
