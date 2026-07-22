# HIP Second Life HUD Setup

Use `scripts/HIP_HUD_MVP.lsl` as the release script. The other scripts in the folder are helper or historical reference implementations.

## Buyer activation

1. Rez or wear the HUD in an area that permits scripts and outbound HTTP.
2. Open `HIP_HUD_MVP.lsl` only if the merchant distributes a modifiable setup copy.
3. Confirm `HIP_DEMO_MODE` is `FALSE`.
4. Set `HIP_API_BASE_URL` to the HTTPS HIP service address supplied by the merchant.
5. Enter the one-time setup code supplied with the purchase, save the script, and allow it to reset.
6. Confirm owner chat reports `HIP Shield: Active` and the HUD shows an active license.
7. Remove the setup code from the script after activation if the product is modifiable. The code is consumed after a successful single-device activation, but removing it avoids unnecessary disclosure.

HIP activation does not require a website login. The service returns an opaque device credential bound to this license and HUD device. Resetting or transferring a license invalidates the prior credential.

## Privacy check

The release script runs local link-pattern checks before contacting HIP. It sends a bounded suspicious snippet only after detecting a suspicious signal; it does not upload full chat or IM logs. Second Life scripts cannot reliably inspect all group chat, private IM, or viewer-click activity.

## Troubleshooting

- `Inactive` or an activation error: request a fresh setup code from the merchant; do not post the code in public chat.
- No local detections: confirm the HUD is attached, scripts are enabled, and the message contains a supported URL-like signal.
- HTTP failures: confirm the configured service uses HTTPS and is reachable from Second Life.
- No popup: touch the HUD to inspect settings and confirm popup and private-warning preferences are enabled.

Demo mode is not an activated product. It is local-only and cannot provide live HIP lookup, reporting, synchronized settings, or safety-page results.
