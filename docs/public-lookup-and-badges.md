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

HIP Domain Trust Certificate enrollment uses DNS TXT and HTTPS `.well-known/hip.json` verification. Public lookup keeps certificate identity evidence separate from the current risk score; certificate details are published through the dedicated public certificate response and page.

## Live Trust Badges

HIP badges are certificate-bound live data widgets, not static trust images. Certificate level and lifecycle state are displayed separately from the current HIP risk score. A certificate or verified identity does not automatically mean safe.

Badge and certificate routes:

- `GET /api/v1/badge/{domain}`
- `GET /api/v1/badge/{domain}/script`
- `GET /api/v1/public/badge/domain/{domain}`
- `POST /api/v1/public/badge/verify`
- `GET /api/v1/public/certificates/{certificateId}`
- `/certificate/{certificateId}`

A badge response includes the public lookup facts, a short-lived signed `hip-live-badge` document, signature status, and—when one exists—the current public certificate ID, exact domain, level, lifecycle state, signature status, expiry, public URL, and active flag. HIP derives this projection from the persisted certificate and verifies its signature before release.

## Embed example

```html
<div data-hip-badge="example.com"></div>
<script
  src="https://hip.example.com/api/v1/badge/example.com/script"
  async>
</script>
```

For local development, copy the environment-correct embed from the active certificate in the owner portal. For the default HIP Web HTTP profile it resembles:

```html
<div data-hip-badge="example.com"></div>
<script
  src="http://localhost:5123/api/v1/badge/example.com/script"
  async>
</script>
```

A loopback embed is a local preview only: it works only while HIP is running on that computer. A visitor-facing badge requires a publicly reachable HTTPS HIP origin.

Use the exact canonical hostname. HIP does not silently treat `www.example.com` and `example.com` as the same certificate domain.

## Anti-fake behavior

The generated and shared scripts compare the current page hostname with the requested domain, require a current signed badge document, bind displayed certificate fields to that signed payload, and call HIP's badge verification endpoint. Active presentation additionally requires an Active certificate with Verified signature state. Failure, expiry, revocation, suspension, unavailable verification, or domain mismatch renders a non-active state.

The browser extension independently retrieves the badge and public certificate from HIP, verifies the signed badge through HIP, and compares certificate ID, exact domain, level, lifecycle state, signature status, expiry, public URL, and active flag. It never trusts the website's visual badge by itself.

A screenshot can imitate any visual. It cannot create a current signed, domain-matched HIP certificate response. Every real badge shows the verified domain, links to the public certificate, and keeps the current risk score visible.

The badge sends no page text, form values, visitor identity, cookies, or browsing history. See [HIP Domain Trust Certificates](domain-trust-certificates.md) for enrollment, lifecycle, signing, privacy, CSP, extension, and Aspire guidance.

## Operational limitations

- Online verification is required; local cached presentation never creates an active state.
- The default managed signer and certificate authority allowlist fail closed until a deployment explicitly configures approved key custody and authoritative public key state.
- Extension verification is server-authoritative and online, not offline cryptographic verification inside the extension.
- The current signing implementation must not be described as quantum-resistant.
