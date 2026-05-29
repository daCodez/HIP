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

- `GET /api/admin/reputation/{targetType}/{targetId}`
- `POST /api/admin/reputation/events`
- `POST /api/admin/reputation/{targetType}/{targetId}/recalculate`

Public privacy-safe feedback:

- `POST /api/public/feedback`

## Known Limitations

- In-memory repositories only.
- No production abuse-resistant reporter identity yet.
- No durable event store.
- No reputation dashboards.
- No manual merge with reputation override approval results yet.
- Decay formulas are intentionally simple and should be tuned with real false-positive data.
