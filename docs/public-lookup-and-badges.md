# Public Lookup and Live Badges

HIP is the Human Identity Protocol. TCP connects devices. TLS encrypts the connection. HIP verifies trust, origin, reputation, and risk.

## Public Lookup

Public lookup lets anyone check public trust data for a domain without exposing private user data.

Routes:

- `/lookup`
- `/lookup/{domain}`
- `/lookup/domain/{domain}`
- `/api/v1/public/lookup/{domain}`
- `/api/v1/public/lookup/domain/{domain}`
- `POST /api/v1/public/lookup`

Public lookup can show:

- domain
- HIP score
- status
- risk level
- public verification state
- signed identity status
- known public risks
- plain-English reasons
- recommended action
- last checked date
- `DomainTrustScore`, `PageTrustScore`, `ContentRiskScore`, and `FinalHipScore`
- final HIP score explanation
- separate score breakdown
- browser scan counts when available
- data source
- signed identity placeholders for future DNS TXT and `.well-known/hip.json` verification

Public lookup now prefers stored browser plugin scan results. When HIP has a stored scan for a domain, lookup displays layered HIP scoring, reasons, link scan counts, last checked date, recommended action, and `dataSource = BrowserPluginScan`.

When HIP has not scanned a domain yet, lookup returns a no-data MVP state with `status = LimitedTrustData`, `recommendedAction = ShowCaution`, `dataSource = NoStoredData`, and the message `HIP has not scanned this domain yet`. This avoids pretending HIP has real threat intelligence for a domain before it has stored scan data.

Public lookup must not expose private chat logs, private reports, user identities, private sender names, private scan history, raw user-submitted evidence, full page URLs from browser scans, page URL hashes, form contents, private messages, or raw scan payloads.

Stored browser scan response example:

```json
{
  "domain": "example.com",
  "score": 76,
  "status": "MostlyTrusted",
  "riskLevel": "MostlyTrusted",
  "domainTrustScore": 95,
  "pageTrustScore": 70,
  "contentRiskScore": 65,
  "finalHipScore": 76,
  "finalHipScoreExplanation": "GitHub has strong domain trust signals, but individual repositories, downloads, and user-generated content still need separate review.",
  "reasons": [
    "Last browser scan found no dangerous links",
    "This lookup is based on the latest privacy-safe browser plugin scan summary."
  ],
  "linksScanned": 42,
  "riskyLinksFound": 2,
  "suspiciousLinksFound": 2,
  "dangerousLinksFound": 0,
  "lastCheckedUtc": "2026-06-01T00:00:00Z",
  "recommendedAction": "Allow",
  "dataSource": "BrowserPluginScan"
}
```

No stored data response example:

```json
{
  "domain": "newsite.com",
  "score": 56,
  "status": "LimitedTrustData",
  "domainTrustScore": 50,
  "pageTrustScore": 55,
  "contentRiskScore": 65,
  "finalHipScore": 56,
  "finalHipScoreExplanation": "HIP did not find strong trust signals for this website yet. No major risk signals were found, but the site has not earned a high trust score.",
  "reasons": [
    "HIP has not scanned this domain yet"
  ],
  "recommendedAction": "ShowCaution",
  "dataSource": "NoStoredData"
}
```

MVP limitation: response compatibility still includes numeric `score` and `finalHipScore`; no-data responses use a conservative limited-data score instead of a nullable score until clients can safely adopt nullable score fields.

## Website Scoring MVP

HIP website scoring now uses stored browser plugin scan results when available. Domains without stored scans show an explicit `LimitedTrustData` no-data state until HIP receives real scan data.

Current score bands:

- `0-9` = Dangerous
- `10-24` = HighRisk
- `25-39` = Suspicious
- `40-49` = Unknown
- `50-69` = LimitedTrustData
- `70-84` = MostlyTrusted
- `85-100` = Trusted

Layered scoring rules:

- Domain trust does not automatically make every page safe.
- Trusted domains can still host risky user-generated pages or downloads.
- Clean page scans do not make an unknown domain trusted.
- Downloads do not inherit full trust from their parent domain.
- Page-level and content-level risks can lower the final user-facing HIP score.

Current recommended actions:

- `Allow`
- `ShowCaution`
- `ShowWarning`
- `RouteToSafetyPage`
- `Block`

MVP signals include:

- malformed or missing domains are rejected
- browser plugin scan summaries provide real stored link-count and score data
- unknown domains without stored scans return a no-data caution state
- `verified` test domains return placeholder signed identity fields only when lookup has stored scan data

HIP must not claim real-world safety until live reputation, rule simulation, verified identity data, and threat feeds are connected.

## Verified Does Not Mean Safe

A verified identity does not automatically mean safe. It means HIP knows who signed or owns the domain or content. The trust score still matters.

Future signed website support is expected to use DNS TXT and `.well-known/hip.json` verification. The public lookup response already includes placeholders for signed identity status, verification method, verified organization, and signature status.

## Live Trust Badges

HIP badges are live data widgets, not static images. A badge must always show the score and status so a site cannot hide a low trust score behind a generic "verified" label.

Badge API:

- `/api/v1/badge/{domain}`
- `/api/v1/badge/{domain}/script`
- `/api/v1/public/badge/domain/{domain}`

The response always includes:

- domain
- score
- status
- verified domain state
- last checked UTC
- public lookup URL / lookup URL
- badge text
- badge variant

## Embed Example

Preferred MVP embed:

```html
<div data-hip-badge="example.com"></div>
<script src="https://hip.example.com/api/v1/badge/example.com/script"></script>
```

Static shared script alternative:

```html
<div
  class="hip-trust-badge"
  data-domain="example.com">
</div>
<script src="https://hip.example.com/hip-badge.js"></script>
```

For local development:

```html
<div
  class="hip-trust-badge"
  data-domain="example.com"
  data-api-base="https://localhost:7053">
</div>
<script src="https://localhost:7053/hip-badge.js"></script>
```

## Anti-Fake Foundation

The badge API returns the domain it verified. The badge script compares the requested domain with the current page hostname where possible. If they do not match, it renders:

`HIP Badge Domain Mismatch`

Every badge links to the official public HIP lookup page.

The badge is live data, not a static image. It must always show the score or status. A site must not be able to display only `Verified by HIP` because verified identity does not automatically mean safe.

The browser plugin is expected to later detect fake, hidden, or altered badges by comparing page badge data with official HIP lookup data.

## Known Limitations

- Badge responses are not cryptographically signed yet.
- Domain matching is exact after removing a leading `www.`.
- Badge data follows public lookup and may show Unknown when no stored browser scan exists.
- A future browser plugin check should detect fake, hidden, or altered badges.

## Future Signed Badge Responses

The badge response model includes a signature placeholder so HIP can later sign badge payloads. Clients should eventually verify the signature before trusting rendered badge data.
