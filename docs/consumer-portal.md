# HIP Consumer Portal MVP

The Consumer Portal is an optional web surface for users who want more visibility and control over HIP protection.

The Second Life HUD does not require a web login. It can continue using setup-code/license activation and privacy-safe reporting without the Consumer Portal.

## Routes

- `/consumer`
- `/consumer/scans`
- `/consumer/reports`
- `/consumer/appeals`
- `/consumer/settings`
- `/consumer/devices`

## API Routes

- `GET /api/v1/consumer/status`
- `GET /api/v1/consumer/scans`
- `GET /api/v1/consumer/reports`
- `GET /api/v1/consumer/appeals`
- `GET /api/v1/consumer/settings`
- `POST /api/v1/consumer/settings`

The MVP APIs require development authentication through `X-HIP-Consumer-Id`. This is not production authentication.

## Portal Features

- protection status
- scan history
- report history
- appeal status
- alert settings
- license/device status
- trusted identities placeholder

## Alert Settings

Supported settings:

- enable popup alerts
- enable private warnings
- enable safety page routing
- scan mode

Supported scan modes:

- Quiet
- Normal
- Strict
- Paranoid

Invalid scan modes are rejected.

## Privacy Rules

Scan history can show:

- date
- domain
- risk level
- reason summary
- action taken

The Consumer Portal must not show full private chat logs, private message bodies, form contents, full email text, raw private evidence, original risky URLs by default, or sender hashes.

## Known Limitations

- Development authentication only.
- Settings are in-memory MVP state.
- Consumer history is not filtered by real user account/license yet.
- Trusted identities are a placeholder.
- Device/license management is a display foundation only.
