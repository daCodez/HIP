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

## End-To-End Scan Flow

HIP's MVP scan flow is intentionally client-observed and provider-based. The server does not crawl random websites, download files, submit forms, read page body text, or inspect private content.

The expected flow is:

1. The browser plugin observes the current page safely.
2. The plugin builds a privacy-safe signal payload using structural facts only.
3. HIP API validation rejects malformed, unsafe, private-network, or private-content input.
4. HIP checks short-lived cache/history before recomputing a scan.
5. Evidence providers return normalized evidence. Providers collect evidence, not final scores.
6. Built-in rules and approved admin rules evaluate the normalized signals.
7. Malware, phishing, redirect, script, download, form, and reputation risk scores are calculated.
8. `DomainTrustScore` is calculated.
9. `PageTrustScore` is calculated.
10. `ContentRiskScore` is calculated.
11. `FinalHipScore` is calculated from the layered scores.
12. A status label is assigned.
13. `ConfidenceLevel` is assigned.
14. Plain-English reasons and warnings are generated.
15. A privacy-safe scan result is stored for lookup and dashboard use.
16. The browser popup displays the layered details and is the primary user experience.
17. The injected banner appears only when warning rules require interruption.
18. Users can submit weighted feedback such as Looks Safe or Looks Suspicious.
19. The admin review queue receives important uncertain, risky, conflicting, or high-impact cases.

MVP browser observations may include:

- current domain
- URL hash
- link counts
- risky link counts
- redirect counts
- download-like link URLs used for local extension checks
- login/password/payment field presence
- structural script counts
- privacy-safe risk labels such as `CrackedSoftware` or `DisableAntivirus`

MVP browser observations must not include:

- page body text
- form values
- passwords
- tokens
- cookies
- private messages
- email body content
- unrelated browsing history

This means HIP can evaluate page risk without becoming a crawler or surveillance system.

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

The browser plugin sends only structural facts such as counts, source URLs, download-link URLs for extension checks, and whether login fields exist. HIP sanitizes observed URL collections before scoring: query strings and fragments are stripped, collection sizes are bounded, and localhost/private-network URLs are rejected so scan payloads cannot become SSRF probes or accidental secret carriers.

## Scan Result Storage

The live Site Safety route stores a privacy-safe scan summary after a successful scan:

```http
POST /api/v1/site-safety/scan
```

Storage uses the same browser scan result repository that already feeds public lookup and the Admin Dashboard. This avoids a duplicate persistence path while keeping the flow easy to trace:

```text
Browser Plugin -> HIP API -> Site Safety Scan -> Stored Scan Result -> Admin Dashboard
```

Stored fields are limited to public-safe scan facts:

- normalized domain
- hashed page URL
- target type
- `DomainTrustScore`
- `PageTrustScore`
- `ContentRiskScore`
- `FinalHipScore`
- status and risk label
- confidence label
- plain-English reasons and warnings
- provider names and provider error count
- matched built-in/admin rule IDs
- plugin version when the client sends it
- scan timestamp

The stored summary must not include:

- page body text
- form values
- passwords
- tokens
- cookies
- private messages
- email body content
- unrelated browsing history
- raw full URLs unless a future explicit policy allows it

The Admin Dashboard reads these stored summaries for live cards such as total scans, status counts, recent risky scans, provider error count, and recent threat rows. If no summaries exist, the dashboard should show a no-data state instead of fake data.

## Duplicate Submission Controls

Public feedback, privacy-safe reports, browser scan results, and Site Safety scan requests use a short in-memory duplicate guard. The guard hashes normalized fingerprint parts and keeps only the fingerprint expiry, not the raw request body. This reduces accidental double-submits and simple replay spam during MVP testing.

The guard is single-node only. Production should replace or supplement it with distributed rate limiting, signed HIP client requests, abuse scoring, and persistence-backed deduplication.

## Provider-Based Evidence

Site Safety Scan is provider-based. Providers return normalized evidence; they do not directly decide the final HIP score.

Current provider types:

- `BrowserObserved`: active in the MVP. Uses privacy-safe browser facts.
- `UserFeedback`: active in the MVP. Uses weighted HIP trust feedback as weak evidence.
- `AdminReview`: active in the MVP. Uses approved admin review decisions as transparent scoring evidence.
- `TlsScanner`: SSL Labs / Qualys-style TLS provider. Available for opt-in runtime configuration, but not called unless the global provider switch is enabled.
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

Review records must not store page text, form values, passwords, tokens, cookies, private messages, raw private URLs, or private chat logs.

Approved generated-review decisions now flow back into Site Safety through the `HIP Admin Review` evidence provider. This keeps admin influence visible in the scan response under `ProviderEvidence` and `MatchedRules`.

Admin review effects are intentionally bounded:

- `ConfirmSafe` and `FalsePositive` provide a small capped trust support signal only.
- `NeedsMoreData` lowers confidence and recommends more review.
- `ConfirmSuspicious` increases reputation risk.
- `ConfirmHighRisk` can set HighRisk through an explicit built-in rule.
- `ConfirmDangerous` can set Dangerous through an explicit built-in rule.

Admin review evidence does not execute code, call external APIs, store private content, or mark an unknown clean site Trusted by itself. URL-hash-specific decisions apply only to the matching page hash; domain-level decisions can apply across the domain.

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

Simulation is intentionally diagnostic. The admin simulation response includes matched conditions, failed conditions, risk score impact, trust score impact, status impact, warnings, reasons, confidence impact, approval-required state, and whether admin review would be triggered. Simulation uses privacy-safe sample facts only and never calls external providers from the rule itself.

### Rule Versioning And Rollback

Admin-created Site Safety rules are versioned. A rule update stores the current rule as a version record before saving the new rule. The saved rule keeps:

- `RuleId`
- `Version`
- `PreviousVersionId`
- `CreatedAtUtc`
- `UpdatedAtUtc`
- `CreatedBy`
- `UpdatedBy`
- `ApprovedBy`
- `ApprovedAtUtc`
- `IsRollbackAvailable`

`PreviousVersionId` points to the prior rule version using the format `{RuleId}:v{Version}`. Rollback restores the most recent stored version as a new version instead of deleting history or rewinding in place. For example, rolling back from version 2 to version 1 produces a new version 3 whose `PreviousVersionId` points to version 2.

Rollback guardrails:

- rollback validates the restored rule before saving it
- rollback cannot restore raw-code rule data
- rollback cannot bypass approval requirements
- dangerous enforced overrides still require high/critical severity and approval metadata
- disabled and archived rules do not run
- old versions are preserved unless a future cleanup policy explicitly defines safe retention
- rollback writes an audit log entry and does not erase earlier audit entries

Current limitation: the MVP rollback API restores the most recent stored previous version. A future admin UI can add explicit version selection after version browsing and approval controls are built.

The current EF implementation stores admin rules in HIP's SQLite-backed JSON record store. This keeps the repository boundary clean while leaving room for a more normalized production schema later.

## External Scanner Policy

External evidence providers are configurable. For the dev/MVP build, the global external-provider switch is disabled by default so HIP never calls third-party scanners without explicit operator action. SSL Labs / Qualys-style TLS is the first provider ready for opt-in use once the global switch is enabled. Credentialed threat-intelligence providers such as Google Web Risk / Safe Browsing and VirusTotal remain disabled until API credentials and concrete adapters are configured.

Providers return normalized evidence only. They do not decide the final HIP score. HIP scoring combines provider evidence with browser-observed signals, HIP history, weighted feedback, admin review evidence, and built-in/admin rules.

Current MVP provider foundations:

- `SSL Labs / Qualys TLS`: available for opt-in dev/MVP configuration. When globally enabled, it calls the SSL Labs domain assessment endpoint with only the normalized domain. Strong TLS gives only a small trust boost; weak TLS lowers confidence. Pending or failed TLS checks do not make a site trusted.
- `Google Web Risk / Safe Browsing`: disabled until credentials and a concrete adapter are configured. It normalizes future phishing/social-engineering matches as authoritative risk evidence.
- `VirusTotal`: disabled until credentials and a concrete adapter are configured. It normalizes future malware or malicious URL/domain matches as authoritative risk evidence.

Configuration section:

```json
{
  "ExternalSiteEvidence": {
    "ExternalProvidersEnabled": true,
    "AllowFullUrlChecks": false,
    "ProviderTimeout": "00:00:02",
    "DefaultCacheDuration": "06:00:00",
    "SslLabs": {
      "Enabled": true,
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

To enable or disable a provider, use both the global switch and the provider-specific switch:

- `ExternalSiteEvidence:ExternalProvidersEnabled`
- `ExternalSiteEvidence:<ProviderName>:Enabled`

The same switches are available in `/admin/settings` while the app is running. To enable SSL Labs / Qualys TLS checks, turn on both `ExternalProvidersEnabled` and `SslLabs.Enabled`. Turning either switch off prevents outbound TLS scanner calls.

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
- Provider failures lower confidence only; they must not create trust or danger by themselves.
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

Known high-trust public domains can receive a higher `DomainTrustScore` baseline, but that trust is intentionally layered. The baseline applies to the parent domain only. Repository pages, release/download pages, user-generated content, forms, redirects, scripts, and downloads are still scored separately at the page and content layers.

For example, `github.com` may earn high domain trust. A URL such as `github.com/random-user/free-cracked-tool` does not inherit full trust from `github.com`; HIP caps page trust for likely user-generated surfaces and lowers the final score further when executable downloads or risky labels are observed.

Site Safety affects:

- `DomainTrustScore`
- `PageTrustScore`
- `ContentRiskScore`
- final HIP score

The malware, phishing, redirect, script, download, form, and reputation fields are raw risk scores where higher means more risk. The layered `ContentRiskScore` is a trust component where higher means safer content. This distinction keeps internal risk detection explicit while keeping the user-facing layered HIP scores consistent.

It does not replace domain reputation, identity verification, signed content verification, or rule-engine decisions.

## Browser Plugin Display

The browser plugin popup is the default place for HIP details. It shows:

- Site Safety status
- malware risk
- phishing risk
- redirect risk
- download risk
- script risk
- plain-English scan summary
- `DomainTrustScore`
- `PageTrustScore`
- `ContentRiskScore`
- `FinalHipScore`
- confidence level
- normalized external evidence summaries when available

The plugin still avoids collecting page text and form contents.

The injected banner is warning-only by default:

- `Trusted`: no banner
- `MostlyTrusted`: no banner
- `LimitedTrustData`: no banner unless structural risk exists, such as login, payment, executable download, risky redirect, or trusted-domain risk mismatch
- `Unknown`: no banner by default
- `Suspicious`: soft warning banner
- `HighRisk`: warning banner
- `Dangerous`: strong warning banner

This keeps HIP protective without forcing users to dismiss a banner on normal pages.

## Flow Verification

The scan flow is covered by service-level tests rather than full Chromium automation for now. These tests verify:

- unknown clean sites remain `LimitedData` or `Unknown`
- known trusted domains can have high `DomainTrustScore` without hiding page/content risk
- GitHub repository-like pages are scored as mixed trust surfaces
- executable downloads raise content risk
- login forms on unknown domains raise warnings
- provider timeouts do not crash scoring
- external providers make no outbound calls unless `ExternalProvidersEnabled` is true and the specific provider is enabled
- SSL Labs / Qualys TLS can be enabled for live TLS evidence, while credentialed threat-intelligence providers stay disabled until configured
- feedback is weighted evidence, not voting
- high-risk low-confidence cases create generated admin review signals
- popup responses expose the layered fields required by the extension
- banner policy keeps normal clean pages out of injected warning UI

## Known MVP Limits

- No real malware sandboxing is performed.
- SSL Labs TLS checks can take time; the first response may be pending and should be refreshed later.
- Google Web Risk and VirusTotal adapters are still disabled foundations, not live threat-intelligence integrations.
- Redirects are scored from observed client facts, not crawled server-side.
- Recent scan caching is short-lived and in-process only.
- Site Safety is one signal in the final HIP decision, not the whole decision.
