# Diagrams

Visual flowcharts for the GitHub repo. NuGet.org does not render Mermaid — the [package README](../README.md) uses tables and numbered steps instead.

## Request pipeline

```mermaid
flowchart LR
    A[AddSimpleOwaspHeaders] --> B[IOptions configuration]
    B --> C[ValidateOnStart]
    C --> D[UseSimpleOwaspHeaders middleware]
    D --> E[Policy resolver]
    E --> F[Security headers on response]
```

## Diagnostics

```mermaid
flowchart TD
    A[MapSimpleOwaspHeadersDiagnostics] --> B["/_simple-owasp-headers"]
    A --> C["/_simple-owasp-headers/report"]
    A --> D["/_simple-owasp-headers/matrix"]
    B --> E[JSON for current request]
    C --> F[HTML path report + CSP directives]
    D --> G[HTML matrix — all routes compared]
    H[RunOrExportSecurityReportAsync] --> I[CI / build-time HTML + JSON export]
```
