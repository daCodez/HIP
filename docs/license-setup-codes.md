# HIP License / Setup Code Manager

The license/setup code manager supports Second Life HUD buyers who need to activate without a web login. HIP remains the product; the HUD is a HIP client that uses setup-code activation.

## Purpose

Setup codes allow a marketplace buyer to activate one or more HUD devices while keeping private avatar details out of HIP by default.

## Activation Flow

1. Support/admin creates a setup code.
2. The buyer places the setup code in the HUD configuration.
3. The HUD calls `POST /api/v1/sl-hud/activate`.
4. HIP validates the code, status, and device limit.
5. HIP returns a device ID and HUD settings.

Example response:

```json
{
  "activated": true,
  "licenseStatus": "Active",
  "deviceId": "sl-hud-example",
  "settings": {
    "mode": "Normal",
    "popupAlertsEnabled": true,
    "privateWarningsEnabled": true,
    "safetyRoutingEnabled": true
  }
}
```

## License Statuses

- `Pending`: code exists but has not activated a HUD.
- `Active`: code can activate or continue using linked HUD devices.
- `Suspended`: code is temporarily blocked.
- `Revoked`: code is blocked by support/admin action.
- `Expired`: code is outside its valid use window.

## Setup Code Security

Setup codes are generated with cryptographic randomness and are not sequential. List/detail views show masked setup codes. The raw setup code is shown only immediately after creation so support can deliver it to the buyer.

Default allowed device count is `1` unless support/admin chooses another value.

## Admin / Support Flow

Protected endpoints:

- `POST /api/v1/licenses/setup-codes`
- `GET /api/v1/licenses/{licenseId}`
- `POST /api/v1/licenses/{licenseId}/reset`
- `POST /api/v1/licenses/{licenseId}/revoke`
- `POST /api/v1/licenses/{licenseId}/suspend`
- `POST /api/v1/licenses/{licenseId}/reactivate`

UI routes:

- `/admin/licenses`
- `/admin/licenses/new`
- `/admin/licenses/{id}`

## Consumer Device View

The optional consumer portal page `/consumer/devices` shows license status, masked device ID, HUD version, activation date, last seen date, scan mode, popup alerts, private warnings, and safety routing state.

## Privacy Rules

HIP must not expose raw avatar identity, full setup codes in lists, private chat logs, private scan details, or user secrets. Avatar identity should be hashed when supplied.

## MVP Limitations

- In-memory storage only.
- No production billing or marketplace validation yet.
- No rate limiting yet.
- No durable audit trail for license lifecycle actions yet.
