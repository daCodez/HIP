# HIP Mail Bridge (Chrome/Edge)

MV3 extension for Gmail + Outlook Web that signs email body content using HIP.

## Features (v1)
- Gmail compose:
  - **Attach HIP Signature** (body-stamp fallback)
  - **Send via Gmail API (HIP headers)** (adds `X-HIP-*` headers)
- Outlook compose:
  - **Attach HIP Signature** (body-stamp fallback)
- Read mode verification from `HIP-Signature` block with trust badge
  - `✅ Verified by HIP` / `❌ HIP verify failed(...)`

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
- Click **Authorize Google** (required for Gmail API header-send mode)

## Notes
- Host permissions include Gmail/Outlook web and HIP API URL.
- If your HIP URL changes, update popup settings and `manifest.json` host permissions if needed.
- Gmail/Outlook DOM can change; selectors may need periodic tuning.
