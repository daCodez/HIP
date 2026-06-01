# HIP Second Life HUD Foundation

HIP is the product. The Second Life HUD is a client/component that uses HIP APIs.

The HUD MVP foundation supports:

- setup code/license activation foundation
- suspicious link detection
- shortened link detection
- broken-up and obfuscated link detection
- private owner warnings
- optional popup alerts
- HUD status text
- safety page routing guidance
- privacy-safe reporting

The current LSL MVP script lives at `clients/second-life-hud/scripts/HIP_HUD_MVP.lsl`.

## API Endpoints

- `POST /api/v1/sl-hud/activate`
- `POST /api/v1/sl-hud/scan`
- `GET /api/v1/sl-hud/settings/{deviceId}`
- `POST /api/v1/sl-hud/settings/{deviceId}`
- `POST /api/v1/sl-hud/report`
- `POST /api/v1/sl-hud/report-finding`

`/report-finding` is kept as a compatibility alias. New HUD clients should use `/report`.

Activation input:

- setup code
- optional HUD device ID
- optional avatar/avatar ID hash
- HUD version

Activation returns:

- activated flag
- license status
- device ID
- activation timestamp
- client settings/config

The setup-code/license manager is documented in `docs/license-setup-codes.md`. HUD activation does not require web login.

Scan input:

- device ID
- source such as `PublicChat`, `GroupChat`, or `PrivateIm`
- limited suspicious snippet only when needed
- detected risky URLs
- optional sender hash

Scan output:

- risk level
- score
- plain-English reasons
- recommended HUD action
- safety page URL when the risk requires routing

Report input:

- HUD device ID
- optional avatar hash
- domain
- risky URL or URL hash
- optional sender hash
- risk level
- reason
- timestamp
- HIP signature placeholder

## Alert Levels

- Low risk: HUD status only.
- Medium risk: private owner chat warning.
- High risk: private owner chat warning and optional popup.
- Critical risk: strong popup and safety page routing guidance.

The HUD should warn only on suspicious links or suspicious patterns, not every unknown message.

## Modes

- Quiet
- Normal
- Strict
- Paranoid

## Privacy

The HUD must not collect or send full chat logs, full private IM logs, raw conversations, or real avatar names by default. It reports only privacy-safe risk signals.

Allowed default scan/report fields:

- detected risky URL or reconstructed suspicious URL
- domain
- URL hash
- sender hash if needed
- platform/source
- risk reason
- timestamp
- limited suspicious snippet only when needed

Not allowed by default:

- full public chat logs
- full private IM logs
- harmless chat messages
- real avatar names
- private conversations

## LSL Limitations

Second Life does not provide browser-like link control. The HUD cannot guarantee true blocking. It provides warnings and routes users toward the HIP safety page.

A normal LSL HUD can listen to local chat channels it registers for, but it cannot reliably inspect all group chat, private IM, or viewer-click flows without explicit user, viewer, relay, or platform support. Private IM support must be opt-in and must not upload full IM logs.

## Known Limitations

- Development setup code only.
- In-memory backend activation only.
- No production license persistence.
- No full AI chat analysis.
- No account login.
- No marketplace billing.
