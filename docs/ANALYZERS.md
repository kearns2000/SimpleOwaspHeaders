# SimpleOwaspHeaders Analyzers

Roslyn analyzers are included with `SimpleOwaspHeaders` — no separate package required.

## Rules

| ID | Severity | Description |
|----|----------|-------------|
| **SOH001** | Warning | `ForPath()` prefix must start with `/` (e.g. use `"/admin"` not `"admin"`) |
| **SOH002** | Error | `ForPathRegex()` pattern is not a valid regular expression |
| **SOH003** | Error | `[SecureHeaders("")]` or named path policy reference is empty |
| **SOH004** | Warning | `AddSimpleOwaspHeaders()` called without `UseSimpleOwaspHeaders()` in the same project |
| **SOH005** | Warning | `WithCrossOriginEmbedderPolicy(RequireCorp)` without `WithCrossOriginResourcePolicy` in the same builder chain |

## Examples

### SOH001 — fix path prefix

```csharp
// Warning SOH001
options.ForPath("admin", p => p.WithContentSecurityPolicy(...));

// Correct
options.ForPath("/admin", p => p.WithContentSecurityPolicy(...));
```

### SOH004 — register middleware

```csharp
builder.Services.AddSimpleOwaspHeaders();
// Warning SOH004 if missing:
app.UseSimpleOwaspHeaders();
```

### SOH005 — COEP requires CORP

```csharp
// Warning SOH005
SecurityHeaderPolicyBuilder.Create()
    .WithCrossOriginEmbedderPolicy(CrossOriginEmbedderPolicyValue.RequireCorp);

// Correct
SecurityHeaderPolicyBuilder.Create()
    .WithCrossOriginResourcePolicy(CrossOriginResourcePolicyValue.SameOrigin)
    .WithCrossOriginEmbedderPolicy(CrossOriginEmbedderPolicyValue.RequireCorp);
```

## Suppressing a rule

```csharp
#pragma warning disable SOH001
options.ForPath("legacy-path", ...);
#pragma warning restore SOH001
```

Or in `.editorconfig`:

```ini
[*.cs]
dotnet_diagnostic.SOH001.severity = none
```
