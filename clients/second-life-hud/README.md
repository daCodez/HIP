# HIP Second Life HUD MVP Foundation

HIP is the product. The Second Life HUD is a HIP client/component that uses HIP APIs to warn the owner about suspicious links.

This MVP foundation includes:

- setup code/license activation foundation
- public/group chat scanning plan
- private IM scanning plan
- suspicious link detection
- shortened link detection
- broken-up and obfuscated link detection
- private owner warnings
- optional popup alerts
- on-screen HUD status text concept
- safety page routing response support
- privacy-safe reporting to HIP

## Structure

- `scripts/hip_chat_shield_hud.lsl`: main HUD MVP script.
- `scripts/hip_link_detector.lsl`: reusable link detection helper reference.
- `scripts/hip_config.example.lsl`: configuration example.
- `docs/setup.md`: setup and activation notes.
- `docs/privacy.md`: privacy rules.
- `docs/limitations.md`: Second Life platform limitations.

## Modes

- Quiet: HUD status only unless risk is high or worse.
- Normal: private owner warning for suspicious links.
- Strict: more frequent warnings for caution-level patterns.
- Paranoid: caution on all local suspicious patterns.

## Alert Levels

- Low risk: HUD status only.
- Medium risk: private owner chat warning.
- High risk: private owner warning and optional popup.
- Critical risk: strong popup and HIP safety page routing.

## Backend Endpoints

- `POST /api/v1/public/sl-hud/activate`
- `POST /api/v1/public/sl-hud/report-finding`

Compatibility aliases:

- `POST /api/public/sl-hud/activate`
- `POST /api/public/sl-hud/report-finding`

## Privacy

The HUD must not send full chat logs or full IM logs to HIP. Reports include only risky domain/URL signal data, sender hash where possible, risk reason, timestamp, setup/license device placeholder, and HIP signature placeholder.

## Known Limitations

Second Life LSL cannot provide browser-like link blocking. The HUD focuses on warnings and HIP safety page routing guidance.
