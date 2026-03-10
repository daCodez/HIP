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
  - Windows MSI (placeholder)
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

```bash
dotnet run --project HIP.Agent.Worker/HIP.Agent.Worker.csproj -- enroll --token YOUR_TOKEN_HERE
```

## Run

```bash
dotnet run --project HIP.Agent.Worker/HIP.Agent.Worker.csproj
```

## Linux DEB scaffold output

```bash
./HIP.Agent.Worker/packaging/linux/build-deb.sh Release 0.1.0
```

Output artifact:
- `out/deb/hip-agent-worker_0.1.0_linux-x64.deb`

This is a first scaffold package (wrapper + published binaries), intended to unblock installer pipeline wiring.
