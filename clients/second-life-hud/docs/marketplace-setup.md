# Marketplace Packaging and Demo Setup

HIP is the service; the Second Life HUD is a client. Marketplace copy must not claim universal chat interception, browser-style blocking, guaranteed threat detection, or access to private IMs.

## Product packages

Prepare two clearly named copies from `scripts/HIP_HUD_MVP.lsl`:

- `HIP Shield Demo - Local Only`: set `HIP_DEMO_MODE = TRUE`. Do not embed a setup code. The demo performs local pattern detection and owner-only warnings and makes no HIP network requests.
- `HIP Shield`: keep `HIP_DEMO_MODE = FALSE`, configure the production HTTPS HIP base URL, and use the buyer's bounded-lifetime setup-code handoff process.

Do not ship development hostnames, `HIP-DEV-SETUP`, admin credentials, signing keys, database secrets, or shared production setup codes in an object or notecard.

## Buyer handoff

1. Issue a short-lived, single-device setup code through the HIP license administration page.
2. Deliver it through a private channel with the activation steps in `setup.md`.
3. Ask the buyer to activate promptly and remove the code from modifiable script contents afterward.
4. Use license reset for a legitimate replacement or transfer. Reset invalidates the old device credential before a new activation.

## Release checklist

- Demo and licensed objects are visibly distinct.
- Demo copy displays `Demo (local-only)` and makes no HTTP requests.
- Licensed copy has demo mode disabled and uses an HTTPS production endpoint.
- No reusable credential or secret is present in scripts, notecards, object descriptions, or screenshots.
- Privacy and platform limitations are included in the listing.
- Owner-only warnings, optional popup behavior, safety-page routing, activation, reset, and expiry are tested in Second Life.
- Support instructions explain how to request a replacement setup code without posting it publicly.

Marketplace billing and entitlement verification remain external to this MVP. A marketplace sale does not by itself create or validate a HIP license until that integration is implemented.
