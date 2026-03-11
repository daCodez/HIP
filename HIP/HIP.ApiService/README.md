# HIP.ApiService - Agent Enrollment (Phase 2)

This phase adds agent enrollment + heartbeat contracts for `HIP.Agent.Worker`.

## Enrollment token issuance endpoint (admin)

`POST /api/admin/agent/enrollment-tokens` (alias: `/api/v1/admin/agent/enrollment-tokens`)

Request (optional):

```json
{
  "issuedBy": "admin",
  "ttlMinutes": 30
}
```

Response:

```json
{
  "enrollmentToken": "enr_...",
  "issuedBy": "admin",
  "issuedAtUtc": "2026-03-10T22:00:00Z",
  "expiresAtUtc": "2026-03-10T22:30:00Z"
}
```

- Tokens are **single-use**.
- Tokens expire after TTL.
- Enrollment rejects with reason codes:
  - `agent.enrollment.invalid`
  - `agent.enrollment.expired`
  - `agent.enrollment.already_used`

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

---

## Gmail Personal Connector MVP

The API now includes an admin Gmail connector under:
- `GET /api/admin/connectors/gmail/status`
- `GET /api/admin/connectors/gmail/oauth/start`
- `GET /api/admin/connectors/gmail/oauth/callback`

### Environment variables

Set these before running `HIP.ApiService`:

- `GOOGLE_OAUTH_CLIENT_ID`
- `GOOGLE_OAUTH_CLIENT_SECRET`
- `GOOGLE_OAUTH_REDIRECT_URI`

Optional tuning:
- `GMAIL_CONNECTOR_POLL_MINUTES` (default `5`, min `1`, max `60`)
- `GMAIL_CONNECTOR_MAX_MESSAGES` (default `25`, min `5`, max `100`)

If required variables are missing, the connector reports a clear status error and remains idle (no crash).

### OAuth setup flow

1. In Google Cloud Console, create an OAuth client.
2. Add redirect URI exactly matching:
   - `https://<your-api-host>/api/admin/connectors/gmail/oauth/callback`
3. Start API and call:
   - `GET /api/admin/connectors/gmail/oauth/start`
4. Complete Google consent.
5. Verify status:
   - `GET /api/admin/connectors/gmail/status`

### Token/state persistence

Connector state persists to:
- `HIP.ApiService/SecurityEvents/gmail-connector.store.json`

Stored fields include access token metadata, refresh token, poll watermark, recent message IDs, and last connector error.

### Polling + audit behavior

A background hosted service polls Gmail metadata using `gmail.readonly` scope and emits audit entries without reading full message bodies.

Mapped events:
- `connector.gmail.email.sent`
- `connector.gmail.email.received`
- `connector.gmail.account.security_alert` (heuristic for login/security-alert style notifications)

The poller processes message metadata (`From`, `To`, `Subject`, `Date`, labels) only.
