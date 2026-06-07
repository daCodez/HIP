# HIP Browser Plugin MVP

HIP is the trust and origin verification protocol/platform. The browser plugin is one HIP client that consumes HIP APIs for website scoring and link risk signals.

The MVP supports current website scoring, page link scanning, attention-only link badges, safety-page routing for high-risk links, privacy-safe risk finding reports, and popup score summaries.

The browser plugin uses versioned v1 endpoints:

- `POST /api/v1/browser/score-site`
- `POST /api/v1/browser/scan-links`
- `POST /api/v1/browser/scan-results`
- `GET /api/v1/browser/scan-results/{domain}`

## Plugin Configuration

The extension settings include:

- `hipApiBaseUrl`: HIP API host used for `/api/v1/...` requests.
- `submitScanResults`: submits privacy-safe page scan summaries after scanning. Enabled by default for the dev/MVP path.
- `enableLinkScanning`: scans page anchor href values when enabled.
- `enableSafetyPageRouting`: routes high-risk links through `/safety`.
- `showRiskyLinkIcons`: shows attention badges beside risky links.
- `scanMode`: `Quiet`, `Normal`, `Strict`, or `Paranoid`.

Legacy setting names such as `apiBaseUrl`, `enableLinkBadges`, and `enableSafetyRouting` are still normalized for installed MVP builds.

## Browser Scan Result Persistence

After each successful scan, the extension sends a privacy-safe summary to HIP so later versions can show real data in the popup, public lookup, website scoring, and admin dashboard.

Stored fields:

- domain
- hashed page URL
- HTTPS status
- HIP plugin version
- scan source (`BrowserPlugin`)
- score, risk level, and status
- plain-English reasons
- links scanned count
- risky, suspicious, and dangerous link counts
- login, password, and payment field presence as counts/booleans only
- download, executable download, shortener, obfuscation, and redirect candidate counts
- last checked UTC
- recommended action
- small privacy-safe metadata such as scan mode and candidate counts

HIP does not store full page text, form values, passwords, tokens, usernames, email body text, private messages, or unrelated browsing history from this browser scan flow. The full page URL is hashed by default; raw URL storage is reserved for a future explicit safe-storage policy.

By default, extension setting `allowRawPageUrlSubmission` is `false`. Normal scan submissions send `pageUrlHash` and set `pageUrl` to `null`. If a future development diagnostic explicitly enables raw URL submission, the plugin strips query strings and fragments before sending the URL.

If scan-result submission fails, link scanning and the popup continue to work. The extension records a small `Failure` state in the popup summary and logs only a safe development warning. It does not retry aggressively.

The content script and background worker both guard rapid duplicate submissions. The content script de-duplicates by domain plus page URL hash during the active scan, and the background worker suppresses duplicate in-flight saves using the same hash when available.

Example save request:

```http
POST /api/v1/browser/scan-results
Content-Type: application/json
```

```json
{
  "domain": "example.com",
  "pageUrl": null,
  "pageUrlHash": "sha256:...",
  "pluginVersion": "HIP Plugin v0.1.0-dev",
  "score": 84,
  "riskLevel": "Trusted",
  "status": "Trusted",
  "reasons": [
    "No risky links found"
  ],
  "linksScanned": 42,
  "riskyLinksFound": 2,
  "suspiciousLinksFound": 2,
  "dangerousLinksFound": 0,
  "recommendedAction": "Allow",
  "privacySafeMetadata": {
    "scanMode": "Normal",
    "apiStatus": "Available",
    "isHttps": "true",
    "loginFormsDetected": "0",
    "passwordFieldsDetected": "0",
    "paymentFieldsDetected": "0",
    "downloadCandidates": "0",
    "executableDownloadCandidates": "0",
    "shortenedLinkCandidates": "0",
    "obfuscatedLinkCandidates": "0",
    "redirectCandidates": "0",
    "pluginVersion": "HIP Plugin v0.1.0-dev"
  }
}
```

Example response:

```json
{
  "saved": true,
  "domain": "example.com",
  "lastCheckedUtc": "2026-06-01T00:00:00Z"
}
```

## Safety Page Integration

The browser plugin routes only risky links through HIP:

- Safe/Trusted/MostlyTrusted links are left unchanged and do not get icons.
- LimitedTrustData/Unknown links may show labels depending on scan mode.
- HighRisk/Suspicious, Dangerous, and Critical links get attention badges and click interception.
- Intercepted clicks go to `/safety?url={encodedUrl}&source=browser&risk={riskStatus}` on the configured HIP Web host.

The plugin uses `URLSearchParams` to encode the original target URL before routing. If HIP is unavailable, the extension fails open and does not block links.

The plugin does not send page text, form contents, field values, email body text, or private messages as part of safety routing.

## Popup Website Score UI

The browser popup explains the core HIP relationship in plain language:

> HTTPS secures the connection. HIP verifies the trust.

The popup shows the active tab domain, final HIP website score, status badge, plain-English reasons, links scanned, risky links, last scan time, public lookup link, and safety details link when the current site is risky.

The popup is the primary HIP details surface. It should be where users see the full trust result without forcing a page banner onto normal sites.

The popup shows the layered score components:

- `DomainTrustScore`: how trustworthy the root domain is overall.
- `PageTrustScore`: how trustworthy the exact page or URL is.
- `ContentRiskScore`: how risky the page content, links, forms, downloads, and behavior look.
- `FinalHipScore`: the user-facing score derived from the separate scores.

Plain-English popup labels:

- `Domain Trust`: how trustworthy this website is overall.
- `Page Trust`: how trustworthy this exact page is.
- `Content Risk`: how risky the content on this page is.
- `Final HIP Score`: the final trust score for this interaction.

Plain-English status copy:

- `Trusted`: HIP found strong trust signals for this site.
- `MostlyTrusted`: HIP found mostly positive trust signals, but you should still use normal caution.
- `LimitedTrustData`: HIP has limited trust data for this website.
- `Unknown`: HIP does not have enough information about this website yet.
- `Suspicious`: HIP found suspicious signals on this page.
- `HighRisk`: HIP found high-risk signals. Be careful.
- `Dangerous`: HIP found strong phishing or malware indicators. Avoid this page.

The popup also shows Site Safety status, confidence level, summary, warnings when useful, and feedback buttons when reporting is available. Feedback is weighted trust evidence, not voting. The popup submits only domain, URL hash, displayed score/status, feedback type, plugin version, scan mode, and a privacy-safe timestamp.

## Warning-Only Banner

The injected banner is not the normal HIP details surface. It appears only when HIP finds meaningful risk, unless the user explicitly changes the banner mode in extension settings.

Default mode: `WarningsOnly`.

Default behavior:

- `Trusted`: no banner.
- `MostlyTrusted`: no banner.
- `LimitedTrustData`: no banner by default.
- `Unknown`: no banner by default.
- `Suspicious`: soft warning banner.
- `HighRisk`: warning banner.
- `Dangerous`: strong warning banner.

`LimitedTrustData` pages show a banner only when privacy-safe structural signals justify interrupting the user:

- login form present
- password field present
- payment field present
- executable download present
- suspicious redirect present
- phishing wording present
- scam wording present
- impersonation wording present
- known risky provider evidence present
- trusted domain with risky page/content mismatch

Banner modes:

- `WarningsOnly`: show for Suspicious, HighRisk, Dangerous, and risky LimitedTrustData pages.
- `DangerousOnly`: show only when the current page status is `Dangerous`.
- `AlwaysShow`: show on all HTTP/HTTPS pages unless dismissed.
- `NeverShow`: never inject the banner.

Dismissal is stored in extension-owned storage with a domain and URL hash. HIP does not store raw page URLs for dismissal, and dismissal is only a local display preference. It does not change HIP scoring, reputation, reporting, or safety routing.

The Details link opens the configured public lookup page. Content scripts cannot programmatically open the browser-action popup in a reliable cross-browser way, so the MVP keeps the existing details-link behavior.

Status bands:

- `0-9`: Dangerous
- `10-24`: HighRisk
- `25-39`: Suspicious
- `40-49`: Unknown
- `50-69`: LimitedTrustData
- `70-84`: MostlyTrusted
- `85-100`: Trusted

Popup scoring sends only the current URL/domain. It does not send page text, form contents, credentials, tokens, private messages, or email content.
- `POST /api/v1/public/risk-findings`

Normal safe links do not receive badges. HIP shows labels only when attention is useful: `Unknown`, `Caution`, `Suspicious`, `Dangerous`, or `Verified`.

The plugin may send the current URL/domain, href URLs needed for link scoring, URL hashes in risk reports, risk reason summaries, scan mode, and source client.

The plugin must not send page body text, form values, passwords, usernames, email text, message bodies, or private chat content.

Manual test:

1. Run HIP API and Web through Aspire or Visual Studio.
2. In the extension settings, set `hipApiBaseUrl` to the running API host and `webBaseUrl` to the running Web host.
3. Load `clients/browser-extension` as an unpacked Chromium extension.
4. Visit a normal HTTP/HTTPS test page.
5. Open the popup and confirm the plugin version, score, link counts, Site Safety section, and `Last submitted: Success`.
6. Open `GET /api/v1/browser/scan-results/{domain}` on the API host and confirm `privacySafeMetadata` includes HTTPS, form flags, download counts, shortener/redirect counts, and plugin version.
7. Refresh the page or click popup refresh rapidly and confirm only one in-flight save is attempted at a time.
8. Visit the HIP admin dashboard and click Refresh to confirm the stored scan appears in live scan counts.

Known limitations: link analysis is mostly domain-based with a shortener heuristic, risk reports use a placeholder HIP signature, and file content, AI page analysis, full social parsing, and webmail parsing are deferred.
