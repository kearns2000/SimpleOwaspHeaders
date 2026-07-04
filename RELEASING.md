# Releasing

Maintainer notes for building, packing, and publishing packages.

See [PUBLISHING.md](PUBLISHING.md) for NuGet trusted publishing setup and first-release steps.

## Build and test

```bash
dotnet build -c Release
dotnet test -c Release
```

## Pack locally

```bash
dotnet pack src/SimpleOwaspHeaders/SimpleOwaspHeaders.csproj -c Release -o ./artifacts
dotnet pack src/SimpleOwaspHeaders.Cookies/SimpleOwaspHeaders.Cookies.csproj -c Release -o ./artifacts
```

## Publish to NuGet.org

1. Configure trusted publishing on nuget.org (see [PUBLISHING.md](PUBLISHING.md))
2. Add `NUGET_USER` as a GitHub repository secret
3. Bump `<Version>` in `Directory.Build.props` if needed
4. Tag a release: `git tag v1.0.0 && git push origin v1.0.0`
5. The [ci workflow](.github/workflows/ci.yml) builds, tests, packs, and pushes both packages on tag push

## Analyzers

The analyzer project lives at `analyzers/SimpleOwaspHeaders.Analyzers/`. It is referenced by the main library and embedded in the `SimpleOwaspHeaders` NuGet package automatically (`IsPackable=false` on the analyzer project).

## CI security report export

The sample app exports a report in CI via:

```bash
dotnet exec samples/SimpleOwaspHeaders.Sample/bin/Release/net10.0/SimpleOwaspHeaders.Sample.dll -- --export-security-report ./artifacts/security-headers-report.html
```

Consumer apps can enable MSBuild export with `ExportSimpleOwaspHeadersReport=true` in their `.csproj`.
