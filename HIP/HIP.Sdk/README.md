# HIP.Sdk

Lightweight .NET client for HIP API endpoints.

## Current coverage
- `GetStatusAsync()` → `GET /api/status`
- `GetIdentityAsync(id)` → `GET /api/identity/{id}`
- `GetReputationAsync(identityId)` → `GET /api/reputation/{identityId}`
- `GetAuditEventsAsync(query, identityId)` (admin) → `GET /api/admin/audit`

What to expect:
- `GetIdentityAsync` and `GetReputationAsync` return `null` when the item is not found (`404`).
- Admin audit access is privileged and evaluated by server-side admin policy.
- If the API rejects a call (`429`, `413`, `403`, or other non-2xx), the SDK throws `HttpRequestException`.

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
var identity = await hip.GetIdentityAsync("hip-system"); // null when not found
var reputation = await hip.GetReputationAsync("hip-system"); // null when not found

var admin = app.Services.GetRequiredService<IHipSdkAdminClient>();
var audit = await admin.GetAuditEventsAsync(
    new HIP.Audit.Models.AuditQuery(Take: 25, EventType: "jarvis.token.issue"),
    identityId: "hip-system");
```

## Admin audit access guidance (important)

`IHipSdkAdminClient` is a privileged surface and should only be used in trusted admin/runtime contexts.

Server-side policy notes:
- `/api/admin/audit` is protected by HIP admin access policy.
- Internal/admin routes can be disabled by environment (`HIP:ExposeInternalApis=false`).
- By default, server policy resolves identity from `x-hip-identity` header or `identityId` query parameter.
- Low-trust identities can receive `403` even when request format is valid.

SDK usage tip:
- Pass `identityId` explicitly when calling `GetAuditEventsAsync(...)` unless your runtime already injects `x-hip-identity`.

```csharp
var admin = app.Services.GetRequiredService<IHipSdkAdminClient>();
var events = await admin.GetAuditEventsAsync(
    new HIP.Audit.Models.AuditQuery(Take: 50, EventType: "api.rate_limit.rejected"),
    identityId: "hip-system");
```

Simple error handling:

```csharp
try
{
    var status = await hip.GetStatusAsync();
}
catch (HttpRequestException ex)
{
    // Usually means rate limit hit, auth/policy denial, payload too large,
    // or another non-success HTTP response.
    Console.WriteLine($"HIP call failed: {ex.Message}");
}
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
