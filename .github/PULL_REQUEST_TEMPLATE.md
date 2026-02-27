## Summary
- What changed?
- Why?

## Validation
- [ ] `dotnet test HIP.Tests/HIP.Tests.csproj`
- [ ] `dotnet test HIP.Sdk.Tests/HIP.Sdk.Tests.csproj` (if SDK touched or API contracts changed)
- [ ] Manual smoke checks (if relevant)

## SDK Sync Checklist (required when API contracts/endpoints change)
- [ ] Updated `HIP.Sdk/Models/*` and/or `HIP.Sdk/HipSdkClient.cs`
- [ ] Added/updated SDK tests in `HIP.Sdk.Tests`
- [ ] Updated `HIP.Sdk.Demo` if usage/behavior changed
- [ ] Updated docs: `HIP/README.md` and/or `HIP.Sdk/README.md`
- [ ] Called out breaking changes (if any)

## Risk / Rollback
- Risk level: Low / Medium / High
- Rollback plan:
