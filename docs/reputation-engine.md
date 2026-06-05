# HIP Reputation Engine v1

HIP reputation is separated by target type. It is not one flat score.

Supported reputation targets:

- Sender
- Domain
- DeviceKey
- Organization
- ContentPattern
- Website
- Url

Each target has its own `ReputationProfile` with score, status, event counts, confirmed abuse count, accidental issue count, update time, and plain-English explanations.

## Feedback Weighting

Feedback impact is weighted by reporter trust:

- Anonymous: `0.25`
- Verified: `0.50`
- Trusted: `0.80`
- Moderator: `1.00`
- Admin: `1.00`
- KnownFalseReporter: `0.05`

Low-trust feedback can still create a signal, but it cannot heavily damage reputation by itself.

## Weighted Trust Feedback

HIP treats user feedback as trust evidence, not voting. Feedback helps HIP learn over time, but it does not directly control the final score.

Supported feedback types:

- `LooksSafe`
- `LooksSuspicious`
- `ReportIssue`

Supported privacy-safe reason codes:

- `ScamOrPhishing`
- `FakeLogin`
- `SuspiciousDownload`
- `BadRedirect`
- `MisleadingContent`
- `FalsePositive`
- `Other`

MVP aggregation weights:

- Anonymous: `1`
- Verified: `3`
- Trusted: `6`
- Moderator: `8`
- Admin: `10`
- KnownFalseReporter: `1`

The aggregation service calculates:

- total `LooksSafe` weight
- total `LooksSuspicious` weight
- total `ReportIssue` weight
- recent feedback count
- repeated reporter count
- suspicious feedback pattern flag
- conflicting feedback spike flag
- confidence impact
- recommended admin-review flag

Feedback may affect `ReputationRiskScore`, `DomainTrustScore`, `PageTrustScore`, and `ConfidenceLevel`. It does not directly affect `MalwareRiskScore` or `PhishingRiskScore` unless an admin-reviewed report later confirms the issue.

Examples of safe explanations:

- "Some users have reported this site as suspicious, but HIP has not confirmed a threat."
- "Trusted feedback suggests this warning may be too strong."
- "Recent feedback is conflicting, so HIP lowered confidence and recommends review."

Do not describe feedback as votes. Voting language implies popularity control, while HIP needs weighted trust evidence.

## Feedback Privacy Rules

Feedback can store:

- domain
- feedback type
- source
- reporter trust level
- timestamp
- page URL hash
- reporter/browser/device hash
- plugin version
- reason code

Feedback must not store:

- page body text
- form values
- passwords
- tokens
- cookies
- private messages
- unrelated browsing history
- full raw URLs unless a future explicit policy allows it

## Abuse Protection Foundation

The MVP flags review when:

- many suspicious reports arrive quickly
- repeated reports come from the same reporter hash
- safe and suspicious feedback spikes conflict
- a trusted or admin source reports suspicious behavior
- many safe reports suggest a possible false positive
- low-trust feedback appears spammy

These signals recommend review instead of instantly marking a site safe or dangerous.

## Events

Reputation events include:

- event ID
- target type and target ID
- event type
- severity
- score impact
- reporter trust level
- reason
- created time
- optional expiration time
- confirmed flag
- accidental flag

Events are privacy-safe. Public feedback does not require private chat logs, raw private conversations, names, or personal data.

## Decay Rules

MVP decay behavior:

- Low-severity accidental issues can expire.
- Medium-severity events decay slowly.
- Confirmed Dangerous and Critical events do not fully expire.
- Repeated intentional abuse applies stronger penalties.

This lets accidental issues recover while keeping confirmed malicious behavior visible long-term.

## Status Mapping

Scores are clamped to `0-100`.

- `0-20`: Dangerous
- `21-40`: HighRisk
- `41-60`: Caution
- `61-80`: ProbablySafe
- `81-100`: Trusted

## APIs

Admin/dev routes:

- `GET /api/v1/admin/reputation/{targetType}/{targetId}`
- `POST /api/v1/admin/reputation/events`
- `POST /api/v1/admin/reputation/{targetType}/{targetId}/recalculate`

Public privacy-safe feedback:

- `POST /api/v1/public/feedback`

## Known Limitations

- In-memory repositories only.
- No production abuse-resistant reporter identity yet.
- No durable event store.
- No reputation dashboards.
- No manual merge with reputation override approval results yet.
- Decay formulas are intentionally simple and should be tuned with real false-positive data.
