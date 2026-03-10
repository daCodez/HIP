# HIP.ApiService - Agent Enrollment (Phase 2)

This phase adds agent enrollment + heartbeat contracts for `HIP.Agent.Worker`.

## Enrollment endpoint

`POST /api/agent/enroll` (alias: `/api/v1/agent/enroll`)

Request:

```json
{
  "deviceId": "device-001",
  "deviceName": "FrontDesk-Laptop",
  "enrollmentToken": "operator-issued-token"
}
```

Response:

```json
{
  "deviceId": "device-001",
  "assignedIdentity": "agent:device-001",
  "bootstrapToken": "boot_...",
  "issuedAtUtc": "2026-03-10T22:00:00Z"
}
```

Enrollment records persist to disk at:
- `HIP.ApiService/SecurityEvents/agent-enrollments.store.json`
- Overridable via `HIP:AgentEnrollment:StorePath`

## Heartbeat endpoint

`POST /api/agent/heartbeat` (alias: `/api/v1/agent/heartbeat`)

Headers:
- `Authorization: Bearer <bootstrapToken>`

Request:

```json
{
  "deviceId": "device-001",
  "assignedIdentity": "agent:device-001",
  "status": "online",
  "timestampUtc": "2026-03-10T22:02:00Z",
  "agentVersion": "1.0.0"
}
```

Behavior:
- Validates bearer token against stored enrollment.
- Ensures token/device binding is consistent.
- Updates `LastSeenUtc` for enrolled device.
- Emits audit event `agent.heartbeat.received`.
