# Publishing to NuGet

SimpleOwaspHeaders uses [NuGet trusted publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing) from GitHub Actions. No long-lived API keys are stored in the repo.

## One-time setup (maintainers)

### 1. Create trusted publishing policies on nuget.org

Create one policy per package (or as required by your NuGet account):

1. Sign in at [nuget.org](https://www.nuget.org)
2. Click your username → **Trusted Publishing**
3. **Add new policy** for each package:

| Field | Value |
|-------|-------|
| Policy name | `simpleowaspheaders` (or any label) |
| Package owner | Your nuget.org account |
| Repository owner | `kearns2000` |
| Repository | `SimpleOwaspHeaders` |
| Workflow file | `ci.yml` |
| Environment | *(leave empty)* |

Repeat for `SimpleOwaspHeaders.Cookies` if NuGet requires a separate policy per package ID.

Docs: [Trusted Publishing on Microsoft Learn](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing)

### 2. Add a GitHub repository secret

**Settings → Secrets and variables → Actions → New repository secret**

| Name | Value |
|------|-------|
| `NUGET_USER` | Your **nuget.org username** (profile name, not your email) |

### 3. Push the repository and publish v1.0.0

```bash
git remote add origin https://github.com/kearns2000/SimpleOwaspHeaders.git
git push -u origin main
git tag v1.0.0
git push origin v1.0.0
```

4. Watch **Actions → ci** on GitHub
5. After validation, packages appear at:
   - https://www.nuget.org/packages/SimpleOwaspHeaders
   - https://www.nuget.org/packages/SimpleOwaspHeaders.Cookies

## Releasing a new version

1. Bump `<Version>` in `Directory.Build.props` (keeps both packages in sync)
2. Commit and push to `main`
3. Tag and push: `git tag v1.0.1 && git push origin v1.0.1`

The publish workflow also sets `Version` from the tag (`v1.0.1` → `1.0.1`), so the tag is the source of truth at release time.

## Notes

- Tags must match `v*` (e.g. `v1.0.0`, `v1.2.3`)
- NuGet does not allow republishing the same version — use a new tag for every release
- Package readme images must use an [allowlisted domain](https://learn.microsoft.com/en-us/nuget/nuget-org/package-readme-on-nuget-org#allowed-domains-for-images) (e.g. `raw.githubusercontent.com`)
- Do **not** store a `NUGET_API_KEY` secret — trusted publishing replaces that
- Analyzers ship inside the main `SimpleOwaspHeaders` package (not as a separate NuGet)
