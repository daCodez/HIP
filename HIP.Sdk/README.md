# HIP.Sdk

Lightweight .NET client for HIP API endpoints.

## Current coverage
- `GetStatusAsync()` → `GET /api/status`
- `GetIdentityAsync(id)` → `GET /api/identity/{id}`
- `GetReputationAsync(identityId)` → `GET /api/reputation/{identityId}`

## Install/use in solution
Project reference:

```xml
<ItemGroup>
  <ProjectReference Include="..\HIP.Sdk\HIP.Sdk.csproj" />
</ItemGroup>
```

DI registration:

```csharp
using HIP.Sdk;

builder.Services.AddHipSdkClient(o => o.BaseUrl = "http://127.0.0.1:5101");
```

Consume:

```csharp
var hip = app.Services.GetRequiredService<IHipSdkClient>();
var status = await hip.GetStatusAsync();
var identity = await hip.GetIdentityAsync("hip-system");
var reputation = await hip.GetReputationAsync("hip-system");
```

## Developer maintenance rules
When HIP.ApiService contracts/endpoints change:
1. Update `HIP.Sdk/Models/*` and `HipSdkClient`.
2. Add/adjust tests in `HIP.Sdk.Tests` first.
3. Update `HIP.Sdk.Demo` if behavior/args changed.
4. Update docs (`HIP/README.md` + this file).
5. Run:
   - `dotnet test HIP.Sdk.Tests/HIP.Sdk.Tests.csproj`
   - `dotnet test HIP.Tests/HIP.Tests.csproj`

## Versioning guidance
- Keep SDK backward-compatible where practical.
- For breaking response/request changes, call them out explicitly in commit messages and release notes.
