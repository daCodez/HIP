# HIP Mail Bridge (Chrome/Edge)

MV3 extension for Gmail + Outlook Web that signs email body content using HIP.

## Features (v1)
- Adds **Sign with HIP** button in compose windows (best-effort selectors)
- Calls `POST /api/messages/sign`
- Appends signed payload block into draft body
- Detects `HIP-Signature` blocks in read mode and verifies with `POST /api/messages/verify`
- Shows trust badge: `VALID` / `INVALID(<reason>)`

## Load unpacked
1. Open `chrome://extensions` (or `edge://extensions`)
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select folder: `HIP/extensions/hip-mail-bridge`

## Configure
Click extension icon and set:
- HIP API base URL (default `http://100.67.76.107:5101`)
- Identity ID (`hip-system`)
- Key ID (`hip-system`)

## Notes
- Host permissions include Gmail/Outlook web and HIP API URL.
- If your HIP URL changes, update popup settings and `manifest.json` host permissions if needed.
- Gmail/Outlook DOM can change; selectors may need periodic tuning.
