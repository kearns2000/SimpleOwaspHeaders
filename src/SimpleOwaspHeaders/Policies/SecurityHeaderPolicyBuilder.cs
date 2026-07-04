namespace SimpleOwaspHeaders.Policies;

public sealed class SecurityHeaderPolicyBuilder
{
    private HstsOptions? _hsts;
    private FrameOptions? _xFrameOptions;
    private bool _xContentTypeOptions;
    private ContentSecurityPolicyOptions? _csp;
    private ContentSecurityPolicyOptions? _cspReportOnly;
    private string? _permittedCrossDomainPolicies;
    private ReferrerPolicyValue? _referrerPolicy;
    private CacheControlOptions? _cacheControl;
    private bool _xXssProtectionDisabled;
    private CrossOriginResourcePolicyValue? _corp;
    private CrossOriginOpenerPolicyValue? _coop;
    private CrossOriginEmbedderPolicyValue? _coep;
    private ClearSiteDataPathOptions? _clearSiteData;
    private ReportingEndpointsOptions? _reportingEndpoints;
    private PermissionPolicyOptions? _permissionPolicy;

    public static SecurityHeaderPolicyBuilder Create() => new();

    public SecurityHeaderPolicyBuilder WithHsts(int maxAge = 31_536_000, bool includeSubDomains = true)
    {
        _hsts = new HstsOptions { MaxAge = maxAge, IncludeSubDomains = includeSubDomains };
        return this;
    }

    public SecurityHeaderPolicyBuilder WithXFrameOptions(FrameOptions value)
    {
        _xFrameOptions = value;
        return this;
    }

    public SecurityHeaderPolicyBuilder WithXContentTypeOptions()
    {
        _xContentTypeOptions = true;
        return this;
    }

    public SecurityHeaderPolicyBuilder WithContentSecurityPolicy(Action<ContentSecurityPolicyBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var builder = new ContentSecurityPolicyBuilder();
        configure(builder);
        _csp = builder.Build();
        return this;
    }

    public SecurityHeaderPolicyBuilder WithContentSecurityPolicyReportOnly(Action<ContentSecurityPolicyBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var builder = new ContentSecurityPolicyBuilder();
        configure(builder);
        _cspReportOnly = builder.Build();
        return this;
    }

    public SecurityHeaderPolicyBuilder WithPermittedCrossDomainPolicies(string value)
    {
        _permittedCrossDomainPolicies = value;
        return this;
    }

    public SecurityHeaderPolicyBuilder WithReferrerPolicy(ReferrerPolicyValue value)
    {
        _referrerPolicy = value;
        return this;
    }

    public SecurityHeaderPolicyBuilder WithCacheControl(
        bool noStore = true,
        int maxAge = 0,
        bool noCache = false,
        bool @private = false,
        bool mustRevalidate = false)
    {
        _cacheControl = new CacheControlOptions
        {
            NoStore = noStore,
            MaxAge = maxAge,
            NoCache = noCache,
            Private = @private,
            MustRevalidate = mustRevalidate
        };
        return this;
    }

    public SecurityHeaderPolicyBuilder WithXXssProtectionDisabled()
    {
        _xXssProtectionDisabled = true;
        return this;
    }

    public SecurityHeaderPolicyBuilder WithCrossOriginResourcePolicy(CrossOriginResourcePolicyValue value)
    {
        _corp = value;
        return this;
    }

    public SecurityHeaderPolicyBuilder WithCrossOriginOpenerPolicy(CrossOriginOpenerPolicyValue value)
    {
        _coop = value;
        return this;
    }

    public SecurityHeaderPolicyBuilder WithCrossOriginEmbedderPolicy(CrossOriginEmbedderPolicyValue value)
    {
        _coep = value;
        return this;
    }

    public SecurityHeaderPolicyBuilder WithClearSiteData(Action<ClearSiteDataBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var builder = new ClearSiteDataBuilder();
        configure(builder);
        _clearSiteData = builder.Build();
        return this;
    }

    public SecurityHeaderPolicyBuilder WithReportingEndpoints(Action<ReportingEndpointsBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var builder = new ReportingEndpointsBuilder();
        configure(builder);
        _reportingEndpoints = builder.Build();
        return this;
    }

    public SecurityHeaderPolicyBuilder WithPermissionPolicy(Action<PermissionPolicyBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var builder = new PermissionPolicyBuilder();
        configure(builder);
        _permissionPolicy = builder.Build();
        return this;
    }

    public SecurityHeaderPolicy Build() => new()
    {
        Hsts = _hsts,
        XFrameOptions = _xFrameOptions,
        XContentTypeOptions = _xContentTypeOptions,
        ContentSecurityPolicy = _csp,
        ContentSecurityPolicyReportOnly = _cspReportOnly,
        PermittedCrossDomainPolicies = _permittedCrossDomainPolicies,
        ReferrerPolicy = _referrerPolicy,
        CacheControl = _cacheControl,
        XXssProtectionDisabled = _xXssProtectionDisabled,
        CrossOriginResourcePolicy = _corp,
        CrossOriginOpenerPolicy = _coop,
        CrossOriginEmbedderPolicy = _coep,
        ClearSiteData = _clearSiteData,
        ReportingEndpoints = _reportingEndpoints,
        PermissionPolicy = _permissionPolicy
    };
}

public sealed class ContentSecurityPolicyBuilder
{
    private readonly List<string> _baseUri = [];
    private readonly List<string> _scriptSources = [];
    private readonly List<string> _objectSources = [];
    private readonly List<string> _imageSources = [];
    private readonly List<string> _styleSources = [];
    private readonly List<string> _defaultSources = [];
    private readonly List<string> _mediaSources = [];
    private readonly List<string> _frameSources = [];
    private readonly List<string> _childSources = [];
    private readonly List<string> _frameAncestors = [];
    private readonly List<string> _fontSources = [];
    private readonly List<string> _connectSources = [];
    private readonly List<string> _manifestSources = [];
    private readonly List<string> _formActions = [];
    private bool _blockAllMixedContent;
    private bool _upgradeInsecureRequests;
    private string? _reportUri;
    private string? _reportTo;
    private Func<HttpContext, string?>? _nonceProvider;

    public ContentSecurityPolicyBuilder BaseUri(params string[] sources) => Add(_baseUri, sources);
    public ContentSecurityPolicyBuilder ScriptSources(params string[] sources) => Add(_scriptSources, sources);
    public ContentSecurityPolicyBuilder ObjectSources(params string[] sources) => Add(_objectSources, sources);
    public ContentSecurityPolicyBuilder ImageSources(params string[] sources) => Add(_imageSources, sources);
    public ContentSecurityPolicyBuilder StyleSources(params string[] sources) => Add(_styleSources, sources);
    public ContentSecurityPolicyBuilder DefaultSources(params string[] sources) => Add(_defaultSources, sources);
    public ContentSecurityPolicyBuilder MediaSources(params string[] sources) => Add(_mediaSources, sources);
    public ContentSecurityPolicyBuilder FrameSources(params string[] sources) => Add(_frameSources, sources);
    public ContentSecurityPolicyBuilder ChildSources(params string[] sources) => Add(_childSources, sources);
    public ContentSecurityPolicyBuilder FrameAncestors(params string[] sources) => Add(_frameAncestors, sources);
    public ContentSecurityPolicyBuilder FontSources(params string[] sources) => Add(_fontSources, sources);
    public ContentSecurityPolicyBuilder ConnectSources(params string[] sources) => Add(_connectSources, sources);
    public ContentSecurityPolicyBuilder ManifestSources(params string[] sources) => Add(_manifestSources, sources);
    public ContentSecurityPolicyBuilder FormActions(params string[] sources) => Add(_formActions, sources);

    public ContentSecurityPolicyBuilder BlockAllMixedContent()
    {
        _blockAllMixedContent = true;
        return this;
    }

    public ContentSecurityPolicyBuilder UpgradeInsecureRequests()
    {
        _upgradeInsecureRequests = true;
        return this;
    }

    public ContentSecurityPolicyBuilder ReportUri(string reportUri)
    {
        _reportUri = reportUri;
        return this;
    }

    public ContentSecurityPolicyBuilder ReportTo(string endpointName)
    {
        _reportTo = endpointName;
        return this;
    }

    public ContentSecurityPolicyBuilder WithNonce(Func<HttpContext, string?> nonceProvider)
    {
        _nonceProvider = nonceProvider;
        return this;
    }

    private ContentSecurityPolicyBuilder Add(List<string> target, string[] sources)
    {
        target.AddRange(sources);
        return this;
    }

    internal ContentSecurityPolicyOptions Build() => new()
    {
        BaseUri = _baseUri,
        ScriptSources = _scriptSources,
        ObjectSources = _objectSources,
        ImageSources = _imageSources,
        StyleSources = _styleSources,
        DefaultSources = _defaultSources,
        MediaSources = _mediaSources,
        FrameSources = _frameSources,
        ChildSources = _childSources,
        FrameAncestors = _frameAncestors,
        FontSources = _fontSources,
        ConnectSources = _connectSources,
        ManifestSources = _manifestSources,
        FormActions = _formActions,
        BlockAllMixedContent = _blockAllMixedContent,
        UpgradeInsecureRequests = _upgradeInsecureRequests,
        ReportUri = _reportUri,
        ReportTo = _reportTo,
        NonceProvider = _nonceProvider
    };
}

public sealed class ClearSiteDataBuilder
{
    private ClearSiteDataValueOptions? _default;
    private readonly Dictionary<string, ClearSiteDataValueOptions> _pathOverrides = new(StringComparer.OrdinalIgnoreCase);

    public ClearSiteDataBuilder Default(params ClearSiteDataDirective[] directives)
    {
        _default = CreateValue(directives);
        return this;
    }

    public ClearSiteDataBuilder ForPath(string pathPrefix, params ClearSiteDataDirective[] directives)
    {
        _pathOverrides[pathPrefix] = CreateValue(directives);
        return this;
    }

    internal ClearSiteDataPathOptions Build() => new()
    {
        Default = _default,
        PathOverrides = _pathOverrides
    };

    private static ClearSiteDataValueOptions CreateValue(ClearSiteDataDirective[] directives) => new()
    {
        Directives = directives
    };
}

public sealed class ReportingEndpointsBuilder
{
    private readonly Dictionary<string, string> _endpoints = new(StringComparer.OrdinalIgnoreCase);

    public ReportingEndpointsBuilder Add(string name, string uri)
    {
        _endpoints[name] = uri;
        return this;
    }

    internal ReportingEndpointsOptions Build() => new() { Endpoints = _endpoints };
}

public sealed class PermissionPolicyBuilder
{
    private readonly Dictionary<string, IReadOnlyList<string>> _features = new(StringComparer.OrdinalIgnoreCase);

    public PermissionPolicyBuilder Disable(string feature) => Allow(feature);

    public PermissionPolicyBuilder Allow(string feature, params string[] origins)
    {
        _features[feature] = origins;
        return this;
    }

    internal PermissionPolicyOptions Build() => new() { Features = _features };
}
