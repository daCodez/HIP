# CI Security Baseline

HIP runs `.github/workflows/ci.yml` for every pull request, every push to `master`, and manual workflow dispatches. The workflow has read-only repository permissions and never uses `pull_request_target`.

## Required Gates

- Gitleaks scans the complete Git history for committed secrets.
- NuGet direct and transitive dependencies are checked through the .NET 10 JSON report, and the job fails when any vulnerability entry exists.
- The full solution builds in Release mode with warnings treated as errors.
- The complete .NET test suite runs, including architecture and source-contract tests.
- Every browser-extension JavaScript file passes `node --check`, then all Node tests run.
- Every third-party action is pinned to a reviewed 40-character commit SHA.

## Local Verification

Run these commands from the repository root before pushing:

```powershell
dotnet restore HIP.slnx
dotnet package list --project HIP.slnx --vulnerable --include-transitive --format json --output-version 1
dotnet build HIP.slnx --configuration Release --no-restore --warnaserror
dotnet test HIP.slnx --configuration Release --no-build --no-restore

Get-ChildItem -Path clients/browser-extension -Filter *.js -Recurse |
    ForEach-Object { node --check $_.FullName }

Push-Location clients/browser-extension
npm test
Pop-Location
```

The vulnerability command emits machine-readable JSON. CI additionally rejects the report when any package contains a non-empty `vulnerabilities` collection.

For an optional local secret scan, install Gitleaks and run `gitleaks git .`. CI remains the authoritative full-history secret gate.

## Action Provenance

The workflow pins immutable commits corresponding to these official releases:

- [actions/checkout v7.0.0](https://github.com/actions/checkout/releases/tag/v7.0.0)
- [actions/setup-dotnet v6.0.0](https://github.com/actions/setup-dotnet/releases/tag/v6.0.0)
- [actions/setup-node v7.0.0](https://github.com/actions/setup-node/releases/tag/v7.0.0)
- [gitleaks-action v3.0.0](https://github.com/gitleaks/gitleaks-action/releases/tag/v3.0.0)

When updating an action, review its official release notes, replace the full commit SHA, rerun the contract tests, and keep workflow permissions at read-only unless a separately reviewed feature requires more authority.

## Repository Settings

After the workflow has completed successfully on GitHub, configure branch protection for `master` to require both `Secret scan` and `Build, test, and dependency audit`. Branch protection is repository state and is intentionally not changed by this code-only package.
