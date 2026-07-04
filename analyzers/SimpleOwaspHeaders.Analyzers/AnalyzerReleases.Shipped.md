; Shipped analyzer release
; https://github.com/dotnet/roslyn-analyzers/blob/main/src/Microsoft.CodeAnalysis.Analyzers/ReleaseTrackingAnalyzers.Help.md

## Release 1.0.0

### New Rules

Rule ID | Category | Severity | Notes
--------|----------|----------|-------
SOH001  | Usage    | Warning  | Path prefix must start with '/'
SOH002  | Usage    | Error    | Invalid regex path pattern
SOH003  | Usage    | Error    | Named policy must not be empty
SOH004  | Usage    | Warning  | Missing UseSimpleOwaspHeaders middleware
SOH005  | Usage    | Warning  | COEP require-corp needs CORP
