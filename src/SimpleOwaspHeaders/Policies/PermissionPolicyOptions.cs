namespace SimpleOwaspHeaders.Policies;

/// <summary>
/// Permissions-Policy header configuration. This header remains experimental in some browsers.
/// </summary>
public sealed class PermissionPolicyOptions
{
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Features { get; init; }
        = new Dictionary<string, IReadOnlyList<string>>();

    public string BuildValue()
    {
        if (Features.Count == 0)
        {
            return string.Empty;
        }

        var parts = Features.Select(feature =>
        {
            var allowList = feature.Value.Count == 0
                ? "()"
                : $"({string.Join(' ', feature.Value)})";

            return $"{feature.Key}={allowList}";
        });

        return string.Join(", ", parts);
    }
}
