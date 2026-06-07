# HIP Privacy-Safe Reporting

HIP clients can report suspicious findings without sending full private chats, private page content, form contents, or personal data.

The primary MVP report routes are:

- `POST /api/v1/reports`
- `POST /api/v1/public/risk-findings`
- `GET /api/v1/consumer/reports`
- `GET /api/v1/admin/reports`

`/api/v1/reports` is the general privacy-safe reporting foundation. `/api/v1/public/risk-findings` remains the client-focused risk finding path used by the browser plugin and SL HUD foundations.

## Report Types

Supported report types:

- RiskyUrl
- SuspiciousSender
- FalsePositive
- ReportAsSafe
- ReportAsDangerous
- SuspiciousDomain
- SuspiciousContentPattern

Supported report statuses:

- Submitted
- InReview
- Confirmed
- Rejected
- NeedsMoreInfo
- Closed

Supported sources:

- BrowserPlugin
- SecondLifeHud
- PublicLookup
- SafetyPage
- ConsumerPortal
- AdminPortal
- ApiClient

## What HIP Collects

Risk finding reports may include:

- source client
- platform
- target type
- domain
- URL hash
- optional original URL
- optional sender hash
- risk level
- risk reason
- detection timestamp
- reporter trust level
- short privacy-safe evidence summary
- HIP signature placeholder

General privacy-safe reports may include:

- report type
- source
- platform
- domain
- risky URL when needed
- URL hash
- sender hash when needed
- device/license hash when needed
- risk level
- reason summary
- timestamp
- HIP signature placeholder

If an original URL is supplied, it is treated as sensitive and is not returned in the ingestion response.

## What HIP Must Not Collect By Default

HIP reports must not require:

- full chat logs
- private messages
- form contents
- full page body
- real user names
- unrelated user data
- personal data
- passwords
- tokens
- harmless messages
- unrelated browsing history

Reports marked as containing private content are rejected by the ingestion service.

## Hashing Behavior

HIP hashes privacy-sensitive identifiers before storage when raw values are supplied:

- full URL when a URL hash is not supplied
- sender identity when a raw sender identifier is supplied
- device or license identity when a raw device/license identifier is supplied

The MVP hashing service returns values with a `sha256:` compatibility prefix, but the value is now produced with keyed HMAC-SHA256. The key comes from `HipSecurity:PrivacyHashingKey`.

Development defaults are intentionally marked as development-only. Outside local Development, HIP refuses the shared default key so deployments must provide real secret material. HMAC hashing is for privacy minimization and stable correlation of the same risky URL/sender/device within HIP; it is not authentication and must not replace HIP signatures.

## Retention Policy

The MVP retention model defines:

- normal risky findings: about 90 days
- confirmed dangerous patterns: long-term
- user-linked/private-adjacent data: shortest practical period, currently modeled as 30 days

No cleanup worker is enabled yet.

## Browser Plugin Reporting

The browser plugin reports suspicious or dangerous link domains with:

- source client: `BrowserPlugin`
- platform: `Web`
- target link domain
- URL hash
- risk level
- reason
- timestamp
- privacy-safe evidence facts

It does not send the page body, form contents, or private messages.

## Second Life HUD Reporting Plan

The Second Life HUD should report only:

- risky URL/domain
- sender hash if needed
- platform: `SecondLife`
- reason
- risk level
- timestamp

It must not send full private IM logs by default.

The MVP SL HUD endpoints are:

- `POST /api/v1/sl-hud/activate`
- `POST /api/v1/sl-hud/report-finding`

## Review Queue Connection

High-risk, Dangerous, and Critical reports create review items automatically. Lower-risk reports can be stored without forcing admin review.

## Self-Healing Connection

Accepted reports can be converted into privacy-safe suspicious findings for self-healing pattern detection. The self-healing path receives hashes, domains, risk reasons, platform, timestamps, and anonymized evidence only.

## Known Limitations

- In-memory report storage only.
- HIP signatures are placeholders.
- No rate limiting or reporter identity trust enforcement yet.
- Retention policy is modeled but cleanup is not automated yet.
- No production queue or database persistence yet.
