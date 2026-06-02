# HIP Browser Extension MVP

This Chromium Manifest V3 client helps users see HIP website trust, link risk, and safety warnings. HIP itself is the product; this extension is only one HIP client.

## Features

- Current website HIP score and status in the popup.
- A simple trust message: HTTPS secures the connection; HIP verifies trust.
- Score band and status badge display.
- Public lookup and safety details links.
- Verified identity and signed identity status where available.
- Page link scan summary.
- Risky link badges.
- High-risk website warning banner.
- Safety page routing for HighRisk, Dangerous, and Critical links.
- Privacy-safe browser scan result submission.
- HIP Site Safety Scan popup panel for malware, phishing, redirect, download, and script risk.
- Privacy-safe risk finding reports for risky links.
- Injected HIP trust banner with score/status, Details, Looks Safe, Looks Suspicious, and dismiss controls.
- Download-like link detection foundation.
- Login/form risk indicator foundation.
- Social feed and webmail link detection hooks.
- API availability status.
- Scan refresh button.
- Settings page.

## Settings

Open extension settings from the popup.

Settings:

- HIP API base URL
- HIP Web base URL
- Submit scan results
- Enable link scanning
- Enable link badges
- Enable warning banner
- Banner display mode
- Enable safety routing
- Scan mode

Scan modes:

- Quiet: popup score only; no page badges unless dangerous.
- Normal: suspicious/dangerous badges and high-risk banner.
- Strict: unknown, caution, suspicious, and dangerous badges.
- Paranoid: all non-trusted signals.

Settings are stored with `chrome.storage.sync`.

Current setting keys:

- `hipApiBaseUrl`
- `submitScanResults`
- `enableLinkScanning`
- `enableSafetyPageRouting`
- `showRiskyLinkIcons`
- `scanMode`
- `bannerDisplayMode`

Banner display modes:

- `WarningsOnly`: default. Show the banner only for meaningful risk.
- `DangerousOnly`: show only for dangerous or critical page risk.
- `AlwaysShow`: show on every page unless dismissed.
- `NeverShow`: never inject the page banner.

Default banner behavior:

- `Trusted`: no banner
- `MostlyTrusted`: no banner
- `LimitedTrustData`: no banner unless the page has login, password, payment, or executable download risk
- `Unknown`: no banner
- `Suspicious`: soft warning banner
- `HighRisk`: warning banner
- `Dangerous` / `Critical`: strong warning banner

The popup remains the default place to view full HIP details. The banner is for protecting users when page risk is meaningful, not for forcing users to close a banner on normal pages.

## Trust Banner Feedback

The injected page banner shows the current HIP Trust Score, status, Details link, and simple feedback buttons:

- `Looks Safe`
- `Looks Suspicious`

This is feedback, not voting. HIP should treat it as weighted trust evidence:

- anonymous or unauthenticated browser feedback has low weight
- verified HIP users can receive medium weight later
- trusted users and admin-confirmed findings can receive stronger weight
- suspicious reporter behavior should lower reporter trust over time

The extension submits only privacy-safe evidence:

- domain
- URL hash
- displayed score/status
- feedback type
- source = `BrowserPluginBanner`
- timestamp
- scan mode

It does not submit page text, form values, passwords, tokens, private messages, or email content.

When the user closes the banner, the extension stores a per-domain dismissal flag in `chrome.storage.local`. This is only a local display preference and does not affect HIP scoring, reputation, safety routing, or trust decisions.

## Configuration

Default local endpoints:

```js
apiBaseUrl: "http://localhost:5099"
webBaseUrl: "http://localhost:5260"
```

These match the default HTTP launch profiles used by Aspire for `hip-api` and `hip-web`. Update these in settings if local launch profiles use different ports.

## Safety Page Flow

The content script scans anchor `href` values only. It sends the current page URL and discovered link URLs to `/api/v1/browser/scan-links`.

When HIP returns a risky result:

- `Safe` / `Trusted` / `ProbablySafe`: leave the link unchanged and do not add an icon.
- `Unknown` / `Caution`: optionally show an attention label depending on scan mode.
- `HighRisk` / `Suspicious`: show a suspicious label and route clicks through the HIP safety page.
- `Dangerous`: show a dangerous label and route clicks through the HIP safety page.
- `Critical`: route through the HIP safety page and rely on the safety page block/continue rules.

Safety URLs use:

```text
/safety?url={encodedUrl}&source=browser&risk={riskStatus}
```

The extension stores the HIP Web base URL in settings and builds the final safety page URL from that value. The original target URL is passed through `URLSearchParams`, so it is encoded before routing.

The extension does not permanently rewrite safe links. Risky click interception is attached only when the result is `HighRisk`, `Dangerous`, or `Critical` and safety routing is enabled.

## Scan Result Submission

After a page scan completes, the extension submits a privacy-safe summary to:

```text
POST /api/v1/browser/scan-results
```

The payload includes domain, current page URL for backend hashing, score, status, reasons, link counts, recommended action, scan timestamp metadata, and scan mode. The backend hashes the page URL by default and stores only public-safe summary fields.

If submission fails, the popup and link scanning keep working. The extension records `Failure` in the popup summary and logs only a safe development warning. It does not retry aggressively.

## Site Safety Scan

The popup also calls:

```text
POST /api/v1/site-safety/scan
```

The request includes the active tab URL plus privacy-safe observations from the content script:

- download-like link URLs for extension checks
- login/password form presence
- inline script count
- external script source URLs
- suspicious script pattern count placeholder

The request does not include page body text, script contents, form values, passwords, tokens, private messages, or email contents.

The popup displays Site Safety status and compact malware, phishing, redirect, download, and script risk labels. These labels describe page safety risk only; they do not replace the overall HIP trust score.

## Privacy Promises

The extension must not send:

- page body text
- form values
- passwords
- usernames
- email text
- message bodies
- private chat content

The extension may send:

- current domain
- target link domain
- URL hash
- risk reason
- scan mode
- source client
- privacy-safe scan counts

Login detection only checks whether a form and password field exist and whether the form action points to a different domain. It does not read field values.

Social and webmail detection only scans `href` URLs. It does not parse message text.

Download detection only flags download-like links by URL extension. It does not download or inspect files.

## Manual Test Steps

1. Start the HIP API/Web host:
   ```powershell
   dotnet run --project src/HIP.Web/HIP.Web.csproj --launch-profile https
   ```
2. Open Chrome or Edge.
3. Go to `chrome://extensions` or `edge://extensions`.
4. Enable developer mode.
5. Select **Load unpacked**.
6. Choose `clients/browser-extension`.
7. Visit a normal test page.
8. Open the HIP popup and confirm the website score appears.
9. Confirm the popup shows the current domain, status badge, reason summary, public lookup link, links scanned count, risky links count, and last scan time.
10. Add or visit links containing test domains such as `danger-example.com`, `new-short-example.com`, or `verified-example.com`.
11. Confirm risky link badges appear.
12. Confirm a warning banner appears for a high-risk site.
13. Click a risky link and confirm safety page routing.
    - The destination should be the configured HIP Web host.
    - The query string should include `source=browser`.
    - The original URL should be encoded in the `url` parameter.
14. Open settings, change scan mode, save, close, reopen, and confirm settings reload.
15. Add a download-like link such as `.exe`, `.zip`, `.msi`, `.dmg`, `.pdf`, `.docx`, or `.scr` and confirm it is flagged as a download risk candidate.
16. Add a login form with a cross-domain action and confirm a caution indicator appears without entering or collecting values.
17. Stop HIP locally and confirm the popup shows HIP unavailable while links continue to work.
18. Open `/api/v1/browser/scan-results/{domain}` on the API host and confirm the latest scan summary was stored.
19. Confirm the popup Site Safety panel shows a status plus malware, phishing, redirect, download, and script risk labels.
20. Add a link to an executable such as `https://example.com/setup.exe` and confirm the Site Safety download risk changes after refresh.

## Popup Privacy Behavior

The popup scores only the active tab URL/domain. It does not read or send page text, form values, passwords, tokens, private messages, or email content.

## Known Limitations

- No full download scanning.
- No file content inspection.
- No AI page reading.
- No webmail message parsing.
- No form data collection.
- Link lookups are still domain-based.
- Risk reports use a placeholder HIP signature.
- Local HTTPS development certificates may need to be trusted before extension API calls work.
