using Microsoft.Extensions.Options;
using SimpleOwaspHeaders.Options;
using SimpleOwaspHeaders.Policies;

namespace SimpleOwaspHeaders.Configuration;

internal sealed class SimpleOwaspHeadersOptionsPostConfigure : IPostConfigureOptions<SimpleOwaspHeadersOptions>
{
    public void PostConfigure(string? name, SimpleOwaspHeadersOptions options)
    {
        if (!options.DefaultPolicyConfiguredInCode)
        {
            options.DefaultPolicy = SecurityHeaderPresets.ResolveOrDefault(options.DefaultPreset);
        }
    }
}
