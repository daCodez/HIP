# HIP.Agent.Worker (Installer v1 Scaffold)

Cross-platform .NET worker scaffold for HIP agent installation/runtime.

## What this scaffold includes

- Background worker service (`net10.0`) for periodic heartbeats.
- API enrollment flow:
  - `enroll --token <ENROLLMENT_TOKEN>` calls API enrollment endpoint.
  - Stores returned credential locally in encrypted-at-rest placeholder file.
- Heartbeat sender to:
  - `/api/agent/heartbeat`
  - Uses `Authorization: Bearer <bootstrapToken>` from stored credential when available.
- Packaging scripts for:
  - Windows MSI (WiX v3/v4 pipeline with prereq checks)
  - macOS PKG (placeholder)
  - Linux DEB scaffold artifact (implemented in Phase 2)

## Configuration

Base settings are in `appsettings.json` under `Agent`:

```json
{
  "Agent": {
    "BaseUrl": "http://localhost:5000",
    "EnrollmentPath": "/api/agent/enroll",
    "HeartbeatPath": "/api/agent/heartbeat",
    "HeartbeatIntervalSeconds": 30,
    "DeviceId": "REPLACE_WITH_DEVICE_ID",
    "DeviceName": "REPLACE_WITH_DEVICE_NAME",
    "EnrollmentToken": "REPLACE_WITH_ENROLLMENT_TOKEN",
    "CredentialStorePath": ""
  }
}
```

If `CredentialStorePath` is empty, credentials are persisted at:
- `./agent-credentials.enc` (relative to app base directory).

> Security note: file encryption is a scaffold placeholder. TODO hooks are included to move key material to OS keychains (DPAPI/Keychain/libsecret).

## Build

```bash
dotnet build HIP.Agent.Worker/HIP.Agent.Worker.csproj
```

## Enroll

1) Issue single-use token (admin API):

```bash
curl -X POST http://127.0.0.1:44985/api/admin/agent/enrollment-tokens \
  -H "Content-Type: application/json" \
  -H "x-hip-identity: hip-system" \
  -d '{"issuedBy":"admin","ttlMinutes":30}'
```

2) Enroll agent using issued token:

```bash
dotnet run --project HIP.Agent.Worker/HIP.Agent.Worker.csproj -- enroll --token YOUR_TOKEN_HERE
```

## Run

```bash
dotnet run --project HIP.Agent.Worker/HIP.Agent.Worker.csproj
```

## Windows MSI build

From repository root:

```powershell
pwsh ./HIP.Agent.Worker/packaging/windows/build-msi.ps1 -Configuration Release -Version 0.1.0 -Runtime win-x64
```

Prerequisites:
- .NET SDK available on PATH (`dotnet`)
- WiX Toolset available on PATH:
  - v4 (`wix` command), or
  - v3 (`candle` + `light` commands)

Output artifact:
- `out/windows/hip-agent-worker_0.1.0_win-x64.msi`

If WiX is not installed, the script stops with install guidance and leaves published binaries in:
- `out/windows/publish`

## Linux DEB scaffold output

```bash
./HIP.Agent.Worker/packaging/linux/build-deb.sh Release 0.1.0
```

Output artifact:
- `out/deb/hip-agent-worker_0.1.0_linux-x64.deb`

This is a first scaffold package (wrapper + published binaries), intended to unblock installer pipeline wiring.
