namespace SimpleOwaspHeaders.Metadata;

/// <summary>
/// Applies a named security header policy to a controller or minimal API endpoint.
/// Register the policy via <see cref="Options.SimpleOwaspHeadersOptions.NamedPolicies"/>.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class SecureHeadersAttribute(string policyName) : Attribute
{
    public string PolicyName { get; } = policyName;
}
