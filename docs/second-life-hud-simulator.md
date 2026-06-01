# Second Life HUD Simulator

The Second Life HUD simulator is a dev/test harness for HIP client behavior. HIP is still the product; the simulator exists so HUD scanning, warning, privacy, and safety-page behavior can be tested without launching Second Life for every change.

## Routes

- UI: `/admin/sl-hud-simulator`
- API: `POST /api/v1/sl-hud/simulate`

## What It Tests

- safe chat messages
- normal URLs
- shortened URLs
- broken-up URLs
- `hxxp` / `hxxps` obfuscation
- reward/prize bait wording
- urgency/scam wording
- low-reputation sender hints
- critical-risk URLs
- safety-page routing
- popup enabled/disabled behavior
- scan modes

## Scan Modes

- `Quiet`: only high and critical alerts interrupt the owner.
- `Normal`: medium, high, and critical alerts warn the owner.
- `Strict`: low/caution and above can warn.
- `Paranoid`: every non-safe signal can warn.

## HUD Actions

- `NoAction`
- `HudStatusOnly`
- `PrivateWarning`
- `PrivateWarningAndPopup`
- `SafetyPageWarning`
- `CriticalBlockWarning`

## Privacy-Safe Payload

The simulator deliberately separates the entered message text from the payload preview. Payloads include only risk signals such as source, risk level, reason, detected risky URL, domain, URL hash, sender hash, timestamp, and a limited suspicious snippet only when useful.

Private IM simulations do not include the limited suspicious snippet by default. The simulator must not normalize sending full private chat logs to HIP.

## Manual Test Steps

1. Run HIP.Web.
2. Open `/admin/sl-hud-simulator`.
3. Load the scam sample.
4. Run the simulation.
5. Confirm the result shows high risk, reasons, warning preview, popup preview, safety URL, and privacy-safe payload.
6. Load the safe sample.
7. Confirm the result returns `NoAction` and `sentToHip=false`.

## Known MVP Limitations

- The simulator approximates HUD behavior; it does not execute LSL.
- Domain reconstruction is best effort.
- Reputation is represented by simple sender hints for now.
- It does not replace real Second Life testing for viewer dialogs, `llLoadURL`, attachment behavior, chat channels, or HTTP throttling.

## Still Needs Real Second Life Testing

- HUD attach/wear behavior.
- `llListen` channel behavior.
- Owner-only warning visibility.
- `llDialog` popup behavior.
- `llLoadURL` safety page opening.
- HTTP request throttling and script memory limits.
