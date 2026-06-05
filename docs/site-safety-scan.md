# HIP Site Safety Scan MVP

HIP Site Safety Scan is a page-level risk layer used by HIP clients before a user trusts a website, link, form, or download.

TCP connects devices. TLS encrypts the connection. HIP verifies trust, origin, reputation, and risk.

## What It Does

The MVP scan accepts a public HTTP or HTTPS URL plus optional privacy-safe observations from HIP clients. It returns:

- malware risk score
- phishing risk score
- redirect risk score
- script risk score
- download risk score
- form risk score
- reputation risk score
- overall safety risk score
- status
- plain-English summary
- reasons, warnings, positive signals, and negative signals
- confidence level
- impact on `DomainTrustScore`, `PageTrustScore`, `ContentRiskScore`, and final HIP score
- normalized provider evidence used by the scan

## Status Labels

- `Clean`: no obvious malware/phishing found and HIP has enough supporting trust data.
- `LimitedData`: no obvious malware/phishing found, but HIP does not have enough trust data to call the site trusted.
- `Unknown`: reserved for future scanners when risk cannot be categorized.
- `Suspicious`: review recommended.
- `HighRisk`: strong warning and safety routing recommended.
- `Dangerous`: avoid the page.
- `ScanFailed`: HIP could not complete the scan safely and no trust boost is applied.

## API Route

Current version:

```http
POST /api/v1/site-safety/scan
```

Example request:

```json
{
  "url": "https://example.com/login",
  "observedSignals": {
    "downloadLinks": ["https://example.com/setup.exe"],
    "hasLoginForm": true,
    "hasPasswordField": true,
    "inlineScriptCount": 4,
    "externalScriptUrls": ["https://cdn.example.com/app.js"],
    "trustDataAvailable": false
  }
}
```

## Privacy Rules

The scanner must not receive or store:

- page body text
- script contents
- form values
- passwords
- tokens
- private messages
- full chat logs

The browser plugin sends only structural facts such as counts, source URLs, download-link URLs for extension checks, and whether login fields exist.

## Provider-Based Evidence

Site Safety Scan is provider-based. Providers return normalized evidence; they do not directly decide the final HIP score.

Current provider types:

- `BrowserObserved`: active in the MVP. Uses privacy-safe browser facts.
- `UserFeedback`: active in the MVP. Uses weighted HIP trust feedback as weak evidence.
- `TlsScanner`: SSL Labs / Qualys-style TLS provider. Enabled in development/MVP config and configurable at runtime.
- `ThreatIntel`: Google Web Risk / Safe Browsing-style provider foundation. Disabled by default.
- `UrlReputation`: VirusTotal-style URL/domain reputation provider foundation. Disabled by default.

Planned provider types:

- `HipHistory`: future HIP scan, report, and reputation history.
- `AdminReview`: future moderator/admin review signals.
- `DomainReputation`: future domain reputation providers.
- `MalwareScanner`: future malware scanner providers.
- `PhishingScanner`: future phishing scanner providers.

Each provider returns:

- provider name
- provider type
- target type
- domain
- URL hash when applicable
- evidence items
- confidence
- checked time
- expiry time
- safe errors
- whether it is authoritative for risk
- whether it is authoritative for trust

Each evidence item includes:

- evidence type
- category
- normalized status
- safe summary
- risk impact
- trust impact
- confidence
- severity
- evidence quality
- optional safe source reference
- positive signal flag
- negative signal flag
- blocking signal flag

Evidence item metadata is normalized before scoring. Providers collect facts and labels; they do not directly decide the final HIP score or mark a site trusted.

The scanner combines provider evidence with browser-observed facts. Provider failures and timeouts lower confidence but do not crash HIP scoring.

## Weighted Feedback Evidence

The `HIP Weighted Feedback` provider converts recent feedback aggregates into normalized evidence. Feedback is intentionally weak:

- `LooksSafe` can add a small capped support signal.
- `LooksSuspicious` and `ReportIssue` can increase `ReputationRiskScore`.
- conflicting feedback lowers `ConfidenceLevel`.
- repetitive or high-volume patterns create an admin-review signal.

Feedback does not directly create malware or phishing findings. A single anonymous report cannot make a site `Trusted` or `Dangerous`. Many low-trust reports create review pressure instead of direct enforcement.

Feedback evidence explanations must avoid voting language. Use "reported" or "feedback" rather than "voted."

## Admin Review Signals

Site Safety Scan now creates privacy-safe admin review signals for cases that should not be silently enforced. These signals are routed to:

```http
GET /api/v1/admin/review-queue
```

Current MVP review reasons include:

- `HighRiskLowConfidence`: high-risk or dangerous result with low confidence.
- `ConflictingProviderEvidence`: external provider evidence conflicts.
- `TrustedDomainRiskyPageContent`: trusted parent domain with risky page or content signals.
- `UnknownDomainLoginForm`: limited-data site with login/password fields.
- `UnknownDomainPaymentField`: limited-data or suspicious site with payment fields.
- `WeightedFeedbackReview`: feedback volume or reporter trust recommends review.
- `ConflictingFeedbackReports`: safe and suspicious feedback conflict.
- `ImportantProviderFailure`: provider failure on a high-trust target.

Review records store only public-safe data:

- domain
- URL hash, when available
- target type
- final HIP score/status
- confidence label
- plain-English summary
- privacy-safe evidence summary
- related scan, rule, or feedback IDs when available

Review records must not store page text, form values, passwords, tokens, cookies, private messages, raw private URLs, or private chat logs. Admin decisions are recorded as evidence and audit history only in the MVP. They do not silently override scoring; future scoring can consume approved admin-review evidence through a dedicated provider.

## Rule-Based Scoring

Site Safety scoring now evaluates small strongly typed rule objects instead of one long conditional chain. The scanner builds a privacy-safe rule input, evaluates matched rules, then calculates risk scores from the matched rule results.

Built-in code rule collections:

- `MalwareRiskRules`
- `PhishingRiskRules`
- `DownloadRiskRules`
- `FormRiskRules`
- `RedirectRiskRules`
- `ScriptRiskRules`
- `ReputationRiskRules`
- `ExternalEvidenceRules`
- `ConfidenceRules`
- `StatusLabelRules`
- `OverrideRules`

Each built-in rule includes a stable rule ID, name, source, description, typed condition, risk or trust impact, reason, optional warning, severity, evidence quality, and optional status override. Built-in rule tuning is exposed through `SiteSafetyRuleOptions` so MVP thresholds and risk impacts can be configured without scattering constants through the scanner.

The scanner evaluates rule results first, then aggregates the matched results into malware, phishing, redirect, script, download, form, reputation, confidence, and trust-impact scores. HTTPS is represented as a small positive rule result only. Missing HTTPS is a warning and a modest phishing/page-risk signal. A clean scan does not make a site trusted; it only means HIP did not find major safety risk in the available signals.

Status labels are selected by ordered status rules:

- confirmed malware or phishing overrides can set `Dangerous`
- authoritative external threat evidence can set `HighRisk` or `Dangerous`
- high overall safety risk becomes `HighRisk`
- moderate overall safety risk or executable downloads become `Suspicious`
- no major risk with trust data becomes `Clean`
- no major risk without trust data stays `LimitedData`

Matched rule results are returned in the scan response so admins and tests can explain why a score changed. User-facing surfaces should summarize those results instead of dumping internal rule details into banners.

## Admin-Managed Site Safety Rules

HIP supports a foundation for database-backed admin Site Safety rules. Admin rules are structured data, not executable code. They can be stored, validated, simulated, approved, activated, disabled, versioned, and rolled back without redeploying HIP.

Admin rules support:

- statuses: `Draft`, `PendingApproval`, `Approved`, `Active`, `Disabled`, `Archived`
- modes: `Simulation`, `WatchOnly`, `Enforced`
- safe operators: `Equals`, `NotEquals`, `GreaterThan`, `GreaterThanOrEqual`, `LessThan`, `LessThanOrEqual`, `Contains`, `ContainsAny`, `StartsWith`, `EndsWith`, `InList`
- allow-listed fields such as `Domain`, `Tld`, `RedirectCount`, `ExecutableDownloadCount`, `HasLoginForm`, `DomainReputationScore`, `MatchedRiskTerms`, and provider evidence labels
- structured effects such as increasing specific risk categories, adding reasons or warnings, lowering confidence, status overrides, and sending a result to admin review

Guardrails:

- Admin rules cannot execute C#, JavaScript, expressions, dynamic eval, or external API calls.
- Admin rules cannot access raw page text, passwords, tokens, cookies, form values, private messages, or chat logs.
- Simulation and watch-only rules can match but do not enforce score changes.
- Enforced rules must be approved or active.
- Admin rules cannot mark an unknown clean site trusted by themselves.
- Dangerous overrides require high/critical severity plus explicit approval metadata.
- Rule updates store previous versions so rollback can restore the prior rule.

The current EF implementation stores admin rules in HIP's SQLite-backed JSON record store. This keeps the repository boundary clean while leaving room for a more normalized production schema later.

## External Scanner Policy

External evidence providers are configurable and disabled by default. Operators can explicitly enable the SSL Labs / Qualys-style TLS provider for local MVP scans. Google Web Risk, VirusTotal, Safe Browsing, and any other third-party scanner remain disabled until an operator explicitly configures them.

Current MVP provider foundations:

- `SSL Labs / Qualys TLS`: calls the SSL Labs domain assessment endpoint with only the normalized domain. Strong TLS gives only a small trust boost; weak TLS lowers confidence. Pending or failed TLS checks do not make a site trusted.
- `Google Web Risk / Safe Browsing`: normalizes future phishing/social-engineering matches as authoritative risk evidence.
- `VirusTotal`: normalizes future malware or malicious URL/domain matches as authoritative risk evidence.

Configuration section:

```json
{
  "ExternalSiteEvidence": {
    "ExternalProvidersEnabled": false,
    "AllowFullUrlChecks": false,
    "ProviderTimeout": "00:00:02",
    "DefaultCacheDuration": "06:00:00",
    "SslLabs": {
      "Enabled": false,
      "Endpoint": "https://api.ssllabs.com/api/v3/analyze"
    },
    "GoogleWebRisk": {
      "Enabled": false,
      "Endpoint": null,
      "ApiKey": null
    },
    "VirusTotal": {
      "Enabled": false,
      "Endpoint": null,
      "ApiKey": null
    }
  }
}
```

Runtime MVP controls:

- Admin page: `/admin/settings`
- Admin API: `GET /api/v1/admin/site-safety/external-providers`
- Admin API: `POST /api/v1/admin/site-safety/external-providers`

These runtime controls update the current running HIP process. Production deployments should persist the same values in configuration or a secure settings store and keep API keys in secret storage.

To enable the live TLS provider during development, turn on both:

- `ExternalSiteEvidence:ExternalProvidersEnabled`
- `ExternalSiteEvidence:SslLabs:Enabled`

The same switches are available in `/admin/settings` while the app is running.

External provider rules:

- Prefer cached results when available.
- Prefer domain-only checks.
- Use URL hashes where supported.
- Do not send private page content.
- Do not send page body text.
- Do not send form values.
- Do not send passwords, tokens, cookies, or email content.
- Do not send full URLs unless policy explicitly allows it.
- Handle timeouts and failures safely.
- Scanner failure must not crash HIP scoring.
- Pending SSL Labs scans are treated as limited evidence and do not create a trust boost.
- Clean scanner results do not make unknown domains trusted.
- No scanner result does not mean trusted.
- Conflicting scanner results lower confidence and produce a review warning.

Scoring impact rules:

- Strong TLS evidence gives only a small trust boost.
- Weak TLS lowers confidence.
- Threat-intel malware or phishing hits can force `HighRisk` or `Dangerous`.
- External evidence can affect `ReputationRiskScore`, `DomainTrustScore`, `PageTrustScore`, `ContentRiskScore`, and `ConfidenceLevel`.

## Security Rules

The MVP scanner does not:

- execute scripts
- download or run files
- submit forms
- crawl full websites
- follow unlimited redirects
- scan localhost, loopback, private network, or link-local hosts

The validator blocks non-public targets to reduce SSRF risk.

## Download Risk

Executable-like extensions create high risk:

`.exe`, `.dll`, `.bat`, `.cmd`, `.scr`, `.ps1`, `.vbs`, `.js`, `.jar`, `.apk`, `.msi`

Archive-like extensions require review but are not automatically dangerous:

`.zip`, `.rar`, `.7z`, `.iso`

## Scoring Behavior

Clean site-safety findings provide only a small trust improvement. Unknown or limited-data sites do not receive a trust boost. A clean scan with no reputation or identity data returns `LimitedData`, not `Trusted`.

Site Safety affects:

- `DomainTrustScore`
- `PageTrustScore`
- `ContentRiskScore`
- final HIP score

The malware, phishing, redirect, script, download, form, and reputation fields are raw risk scores where higher means more risk. The layered `ContentRiskScore` is a trust component where higher means safer content. This distinction keeps internal risk detection explicit while keeping the user-facing layered HIP scores consistent.

It does not replace domain reputation, identity verification, signed content verification, or rule-engine decisions.

## Browser Plugin Display

The browser plugin popup shows:

- Site Safety status
- malware risk
- phishing risk
- redirect risk
- download risk
- script risk
- plain-English scan summary

The plugin still avoids collecting page text and form contents.

## Known MVP Limits

- No real malware sandboxing is performed.
- SSL Labs TLS checks can take time; the first response may be pending and should be refreshed later.
- Google Web Risk and VirusTotal adapters are still disabled foundations, not live threat-intelligence integrations.
- Redirects are scored from observed client facts, not crawled server-side.
- Recent scan caching is short-lived and in-process only.
- Site Safety is one signal in the final HIP decision, not the whole decision.
