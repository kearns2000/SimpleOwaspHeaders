![SimpleOwaspHeaders](https://raw.githubusercontent.com/kearns2000/SimpleOwaspHeaders/main/icon.png)

# SimpleOwaspHeaders

[![NuGet](https://img.shields.io/nuget/v/SimpleOwaspHeaders?style=flat&logo=nuget)](https://www.nuget.org/packages/SimpleOwaspHeaders)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?style=flat&logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/download/dotnet/10.0)
[![Build](https://github.com/kearns2000/SimpleOwaspHeaders/actions/workflows/ci.yml/badge.svg)](https://github.com/kearns2000/SimpleOwaspHeaders/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/kearns2000/SimpleOwaspHeaders)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-xUnit-5C2D91?style=flat&logo=xunit)](tests/SimpleOwaspHeaders.Tests)

**Target framework:** `net10.0` · **Language:** C# · **Test runner:** xUnit

Route-aware OWASP security headers for **ASP.NET Core 10**, configured with `IOptions<T>` and `appsettings.json`.

## Install

```bash
dotnet add package SimpleOwaspHeaders
# optional cookie hardening
dotnet add package SimpleOwaspHeaders.Cookies
```

## Quick start

```csharp
builder.Services.AddSimpleOwaspHeaders(options =>
{
    options.DefaultPolicy = SecurityHeaderPolicy.OwaspRecommended;

    options.AddNamedPolicy("Admin", policy => policy
        .WithContentSecurityPolicy(csp => csp
            .ScriptSources("'self'")
            .ImageSources("'self'", "data:")));

    options.ForPath("/admin", "Admin");
    options.ForPathRegex(@"^/api/public/.*", policy => policy
        .WithContentSecurityPolicy(csp => csp.DefaultSources("'none'")));

    options.IgnorePath("/health");
});

app.UseSimpleOwaspHeaders();
app.MapSimpleOwaspHeadersDiagnostics(); // optional — dev diagnostics when EnableDiagnosticsEndpoint = true
await app.RunOrExportSecurityReportAsync();
```

### appsettings.json

```json
{
  "SimpleOwaspHeaders": {
    "DefaultPreset": "OwaspRecommended",
    "EnableDiagnosticsEndpoint": true
  }
}
```

```csharp
builder.Services.AddSimpleOwaspHeaders(builder.Configuration.GetSection("SimpleOwaspHeaders"));
```

## How it works

1. **AddSimpleOwaspHeaders** — register options, presets, and path policies
2. **ValidateOnStart** — fail fast on invalid configuration
3. **UseSimpleOwaspHeaders** — middleware runs on each request
4. **Policy resolver** — match path, merge policies, pick effective headers
5. **Response** — security header values written to the HTTP response

Each request passes through the middleware. The resolver picks the effective policy for that path, merges it onto the default, and the middleware writes the header values to the response.

See [docs/POLICY_MERGE.md](docs/POLICY_MERGE.md) for merge order and path-matching rules.

## Features

- **Options-first** — `AddSimpleOwaspHeaders()` + startup validation
- **Per-route CSP** — prefix, regex, and `[SecureHeaders("Name")]` endpoint policies; CSP directives merge individually
- **Presets** — `OwaspRecommended`, `Strict`, `ApiOnly`, `SpaWithCdn(cdnUrl)`
- **Full CSP builder** — all major directives, `data:`, nonces, Report-Only, `report-to`
- **Clear-Site-Data** — path-specific (logout flows)
- **Permission-Policy** — experimental, opt-in
- **Reporting-Endpoints** — pairs with CSP `report-to`
- **SimpleOwaspHeaders.Cookies** — `HttpOnly`, `Secure`, `SameSite` on `Set-Cookie`
- **Roslyn analyzers** — compile-time checks for common misconfiguration ([docs/ANALYZERS.md](docs/ANALYZERS.md))
- **Diagnostics** — HTML reports with per-directive CSP breakdown (dev only)

### Diagnostics (development)

Enable with `EnableDiagnosticsEndpoint = true` in configuration (development environment only).

**HTTP endpoints** (via `MapSimpleOwaspHeadersDiagnostics`):

| Endpoint | Output |
|----------|--------|
| `GET /_simple-owasp-headers` | JSON for the current request |
| `GET /_simple-owasp-headers/report?path=/admin` | HTML path report with CSP directive breakdown |
| `GET /_simple-owasp-headers/matrix` | Configuration matrix across all routes |
| `GET /_simple-owasp-headers/matrix?format=json` | Matrix data as JSON |

**Build-time / CI export** (via `RunOrExportSecurityReportAsync`, CLI flags, env vars, or MSBuild):

Export the configuration matrix without starting the web server:

```bash
dotnet run -- --export-security-report ./artifacts/security-headers-report.html
dotnet run -- --export-security-report ./report.html --export-security-report-format=json
```

Environment variables:

- `SIMPLE_OWASP_HEADERS_REPORT_PATH` — output path
- `SIMPLE_OWASP_HEADERS_REPORT_FORMAT` — `html`, `json`, or `both` (default)

MSBuild (web projects referencing the package):

```xml
<PropertyGroup>
  <ExportSimpleOwaspHeadersReport>true</ExportSimpleOwaspHeadersReport>
  <SimpleOwaspHeadersReportOutputPath>$(OutputPath)security-headers-report.html</SimpleOwaspHeadersReportOutputPath>
</PropertyGroup>
```

`AddSimpleOwaspHeaders()` registers a startup export hook, so MSBuild export works without `RunOrExportSecurityReportAsync()` — export flags or `SIMPLE_OWASP_HEADERS_REPORT_PATH` exit the process after writing the report.

## Sample app

```bash
cd samples/SimpleOwaspHeaders.Sample
dotnet run
```

| Route | Behaviour |
|-------|-----------|
| `/` | Default OWASP headers |
| `/admin` | Named Admin CSP policy |
| `/api/public/info` | Regex path policy |
| `/logout` | Clear-Site-Data |
| `/_simple-owasp-headers/report` | HTML security report |
| `/_simple-owasp-headers/matrix` | Configuration matrix |

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, project layout, and how to add presets, policies, or analyzers.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

Quick start for contributors:

```bash
git clone https://github.com/kearns2000/SimpleOwaspHeaders.git
cd SimpleOwaspHeaders
dotnet build -c Release
dotnet test -c Release
```

Open a pull request with tests for any behaviour change. CI runs build and test on every PR.

## License

MIT
