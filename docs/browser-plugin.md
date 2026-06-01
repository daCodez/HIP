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
- scan source (`BrowserPlugin`)
- score, risk level, and status
- plain-English reasons
- links scanned count
- risky, suspicious, and dangerous link counts
- last checked UTC
- recommended action
- small privacy-safe metadata such as scan mode and candidate counts

HIP does not store full page text, form values, passwords, tokens, usernames, email body text, private messages, or unrelated browsing history from this browser scan flow. The full page URL is hashed by default; raw URL storage is reserved for a future explicit safe-storage policy.

If scan-result submission fails, link scanning and the popup continue to work. The extension records a small `Failure` state in the popup summary and logs only a safe development warning. It does not retry aggressively.

Example save request:

```http
POST /api/v1/browser/scan-results
Content-Type: application/json
```

```json
{
  "domain": "example.com",
  "pageUrl": "https://example.com/page",
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
    "apiStatus": "Available"
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

- Safe/Trusted/ProbablySafe links are left unchanged and do not get icons.
- Unknown/Caution links may show labels depending on scan mode.
- HighRisk/Suspicious, Dangerous, and Critical links get attention badges and click interception.
- Intercepted clicks go to `/safety?url={encodedUrl}&source=browser&risk={riskStatus}` on the configured HIP Web host.

The plugin uses `URLSearchParams` to encode the original target URL before routing. If HIP is unavailable, the extension fails open and does not block links.

The plugin does not send page text, form contents, field values, email body text, or private messages as part of safety routing.

## Popup Website Score UI

The browser popup explains the core HIP relationship in plain language:

> HTTPS secures the connection. HIP verifies the trust.

The popup shows the active tab domain, HIP website score, status badge, plain-English reasons, links scanned, risky links, last scan time, public lookup link, and safety details link when the current site is risky.

Status bands:

- `0-20`: Dangerous
- `21-40`: High Risk
- `41-60`: Unknown / Caution
- `61-80`: Probably Safe
- `81-100`: Trusted

Popup scoring sends only the current URL/domain. It does not send page text, form contents, credentials, tokens, private messages, or email content.
- `POST /api/v1/public/risk-findings`

Normal safe links do not receive badges. HIP shows labels only when attention is useful: `Unknown`, `Caution`, `Suspicious`, `Dangerous`, or `Verified`.

The plugin may send the current URL/domain, href URLs needed for link scoring, URL hashes in risk reports, risk reason summaries, scan mode, and source client.

The plugin must not send page body text, form values, passwords, usernames, email text, message bodies, or private chat content.

Manual test: run `dotnet run --project src/HIP.Web/HIP.Web.csproj --launch-profile https`, load `clients/browser-extension` as an unpacked Chromium extension, visit a test page, and confirm the popup score plus attention-only link badges.

Known limitations: link analysis is mostly domain-based with a shortener heuristic, risk reports use a placeholder HIP signature, and file content, AI page analysis, full social parsing, and webmail parsing are deferred.
