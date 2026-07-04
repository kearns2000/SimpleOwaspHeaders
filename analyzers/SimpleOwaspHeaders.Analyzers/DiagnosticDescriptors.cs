using Microsoft.CodeAnalysis;

namespace SimpleOwaspHeaders.Analyzers;

internal static class DiagnosticIds
{
    public const string PathPrefixMustStartWithSlash = "SOH001";
    public const string InvalidRegexPattern = "SOH002";
    public const string EmptyNamedPolicy = "SOH003";
    public const string MissingUseMiddleware = "SOH004";
    public const string CoepRequiresCorp = "SOH005";
}

internal static class DiagnosticDescriptors
{
    public static readonly DiagnosticDescriptor PathPrefixMustStartWithSlash = new(
        DiagnosticIds.PathPrefixMustStartWithSlash,
        "Path prefix must start with '/'",
        "Path prefix '{0}' must start with '/'. Use ForPath(\"/{0}\", ...) instead.",
        "Usage",
        DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    public static readonly DiagnosticDescriptor InvalidRegexPattern = new(
        DiagnosticIds.InvalidRegexPattern,
        "Invalid regex path pattern",
        "Regex path pattern '{0}' is invalid: {1}",
        "Usage",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    public static readonly DiagnosticDescriptor EmptyNamedPolicy = new(
        DiagnosticIds.EmptyNamedPolicy,
        "Named policy must not be empty",
        "SecureHeaders attribute and named policy references must supply a non-empty policy name",
        "Usage",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    public static readonly DiagnosticDescriptor MissingUseMiddleware = new(
        DiagnosticIds.MissingUseMiddleware,
        "Missing UseSimpleOwaspHeaders middleware",
        "AddSimpleOwaspHeaders() is registered but UseSimpleOwaspHeaders() was not found in this compilation. Security headers will not be applied.",
        "Usage",
        DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        customTags: ["CompilationEnd"]);

    public static readonly DiagnosticDescriptor CoepRequiresCorp = new(
        DiagnosticIds.CoepRequiresCorp,
        "Cross-Origin-Embedder-Policy require-corp needs CORP",
        "WithCrossOriginEmbedderPolicy(RequireCorp) requires WithCrossOriginResourcePolicy to be configured in the same policy builder chain",
        "Usage",
        DiagnosticSeverity.Warning,
        isEnabledByDefault: true);
}
