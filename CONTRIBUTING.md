# Contributing to SimpleOwaspHeaders

Thanks for your interest in contributing. SimpleOwaspHeaders is a small, focused library — contributions that improve OWASP security header configuration, validation, and diagnostics are welcome.

## Before you start

- Search [existing issues](https://github.com/kearns2000/SimpleOwaspHeaders/issues) to avoid duplicate work.
- For large changes (new presets, API changes, analyzer rules, architecture), open an issue first to discuss approach.
- Keep pull requests focused. One feature or fix per PR is easier to review.

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- Any editor (VS, VS Code, Rider)

## Getting started

```bash
git clone https://github.com/kearns2000/SimpleOwaspHeaders.git
cd SimpleOwaspHeaders
dotnet build
dotnet test
```

Run the sample:

```bash
dotnet run --project samples/SimpleOwaspHeaders.Sample
```

## Project layout

```text
src/SimpleOwaspHeaders/              # Main library
  Policies/                          # Header policies, presets, CSP builder
  Matching/                          # Path/regex policy resolver
  Middleware/                        # Response header middleware
  Diagnostics/                       # Dev reports, matrix, CI export
  Validation/                        # Options validation on startup
analyzers/SimpleOwaspHeaders.Analyzers/  # Roslyn analyzers
src/SimpleOwaspHeaders.Cookies/    # Optional cookie hardening package
tests/SimpleOwaspHeaders.Tests/    # xUnit tests
samples/SimpleOwaspHeaders.Sample/
docs/                              # Policy merge, analyzers, etc.
```

## Making changes

### Bug fixes

1. Add a failing test in `tests/SimpleOwaspHeaders.Tests/` that reproduces the bug.
2. Fix the issue in `src/SimpleOwaspHeaders/` (or the relevant project).
3. Ensure `dotnet test -c Release` passes.

### New presets or policy behaviour

1. Add or extend presets in `src/SimpleOwaspHeaders/Policies/SecurityHeaderPresets.cs`.
2. Cover merge and path resolution in tests (see `docs/POLICY_MERGE.md`).
3. Update `README.md` if the preset is user-facing.

### CSP or header options

1. Extend the relevant options type under `src/SimpleOwaspHeaders/Policies/`.
2. Wire through the middleware and diagnostics renderers if output changes.
3. Add tests for serialization, merge behaviour, and rendered header values.

### Roslyn analyzers

1. Add rules under `analyzers/SimpleOwaspHeaders.Analyzers/`.
2. Document new diagnostics in `docs/ANALYZERS.md`.
3. Add analyzer tests in `tests/SimpleOwaspHeaders.Tests/`.

### Diagnostics and reports

1. Changes under `src/SimpleOwaspHeaders/Diagnostics/` should stay dev-only (gated by `EnableDiagnosticsEndpoint`).
2. Update HTML/JSON export tests when report shape changes.
3. Keep exported reports free of inline scripts (CSP-safe HTML).

### Public API changes

- Keep the public surface small.
- Update `README.md` for any user-visible API change.
- Avoid breaking changes in patch/minor releases without discussion.

## Code guidelines

- Use nullable reference types; avoid suppressing null warnings without reason.
- Match existing naming and file structure.
- Prefer options-based configuration (`IOptions<T>`, `appsettings.json`) over magic strings.
- Policy merge must remain predictable — see `docs/POLICY_MERGE.md`.

## Testing expectations

All PRs should pass:

```bash
dotnet build -c Release
dotnet test -c Release
```

Add tests when you:

- Fix a bug
- Change policy merge or path matching
- Add presets, headers, or CSP directives
- Touch analyzers or diagnostics output

## Pull request checklist

- [ ] `dotnet build -c Release` succeeds
- [ ] `dotnet test -c Release` passes
- [ ] Tests added or updated for the change
- [ ] README or `docs/` updated if public API or behaviour changed
- [ ] No unrelated formatting or drive-by refactors

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

## Questions

Open a [GitHub issue](https://github.com/kearns2000/SimpleOwaspHeaders/issues) for questions or ideas.
