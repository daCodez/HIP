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

- `scripts/HIP_HUD_MVP.lsl`: current owner-worn HUD MVP script that activates, scans suspicious local chat signals, loads/saves settings, warns the owner, routes safety links, and reports privacy-safe findings.
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

- `POST /api/v1/sl-hud/activate`
- `POST /api/v1/sl-hud/scan`
- `GET /api/v1/sl-hud/settings/{deviceId}`
- `POST /api/v1/sl-hud/settings/{deviceId}`
- `POST /api/v1/sl-hud/report`
- `POST /api/v1/sl-hud/report-finding`

`/report-finding` is a compatibility alias. New HUD scripts should use `/report`.

## MVP Script Behavior

`HIP_HUD_MVP.lsl` listens to local chat, runs local suspicious-link checks first, and calls HIP only when it sees a risky signal. It looks for normal URLs, shortened URLs, `hxxp`/`hxxps`, broken-up `dot` domains, simple obfuscation, and reward/prize wording near link-like text.

The HUD does not claim browser-style blocking. When HIP returns a risky result, it warns the owner privately and opens the official HIP safety page when the owner chooses `Open Safety`.

## Privacy

The HUD must not send full chat logs or full IM logs to HIP. Reports include only risky domain/URL signal data, sender hash where possible, risk reason, timestamp, setup/license device placeholder, and HIP signature placeholder. The MVP script sends only a short suspicious snippet after local detection has already found a risky link signal.

## Manual Test Steps

1. Start the HIP API/Web host locally.
2. Copy `scripts/HIP_HUD_MVP.lsl` into a Second Life HUD prim script.
3. Set `HIP_API_BASE_URL` to the reachable HIP host and `HIP_SETUP_CODE` to a valid development setup code.
4. Wear or attach the HUD and confirm owner chat says `HIP Shield: Active`.
5. Say a safe local chat message and confirm the HUD status remains low risk.
6. Say `hxxps://scam-prize dot example` in local chat and confirm a private owner warning appears.
7. Click `Open Safety` in the popup and confirm it opens the HIP safety page URL.
8. Touch the HUD and confirm status/settings are shown without exposing chat content.

## Known Limitations

Second Life LSL cannot provide browser-like link blocking. The HUD focuses on warnings and HIP safety page routing guidance.

Normal LSL HUD scripts cannot reliably read every group chat, private IM, or viewer-click flow. Private IM scanning needs explicit user/viewer/relay support and must still avoid full IM log upload.
