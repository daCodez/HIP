# HIP Review Queue, Appeals, and Reputation Overrides

HIP must not blindly punish users, domains, keys, organizations, or content patterns. The review foundation gives admins a privacy-safe way to inspect serious decisions, process appeals, and approve risky reputation changes.

This is a dev/admin MVP. Admin routes require development admin authorization. Production deployment must replace dev auth with production authentication, durable storage, and tamper-resistant audit retention.

## Review Queue

Review items can represent:

- risky domains
- risky senders
- risky device keys
- risky organizations
- reputation overrides
- appeals
- false positives
- rule suggestions
- safety reports

Review items include target type, target ID, risk level, priority, status, evidence summary, privacy-safe evidence, recommended action, and decision details.

Review statuses:

- Submitted
- InReview
- Confirmed
- Rejected
- NeedsMoreInfo
- Closed

Supported actions:

- create review item
- list review items
- get review item
- assign review item
- approve
- reject
- request more info
- close

## Generated Safety Review Signals

HIP also maintains a generated review-signal queue for cases created by Site Safety Scan, weighted feedback, external evidence providers, HIP history, admin rules, and system checks.

Generated review signals are not raw enforcement decisions. They are privacy-safe evidence that tells an admin, "this case deserves human review before HIP makes a stronger trust or risk change."

Signal statuses:

- Open
- InReview
- Resolved
- Dismissed
- Escalated

Signal decisions:

- ConfirmSafe
- ConfirmSuspicious
- ConfirmHighRisk
- ConfirmDangerous
- FalsePositive
- NeedsMoreData
- NoAction

Generated signals can be created for high-risk low-confidence scans, conflicting external provider evidence, trusted parent domains with risky page/content, unknown login or payment forms, repeated suspicious feedback, conflicting feedback, provider failures on important targets, and future self-healing or admin-rule cases.

Generated review signals store only privacy-safe fields: domain, URL hash, target type, source, score/status, confidence, summaries, and related IDs. They must not store page text, form values, passwords, tokens, cookies, private messages, raw private URLs, or private chat logs.

## Appeal Process

Appeals support domains, senders, device keys, organizations, and content patterns. Appeals require only privacy-safe evidence such as hashes, public remediation notes, domain identifiers, risk reasons, and timestamps.

Appeal statuses:

- Submitted
- InReview
- Approved
- Rejected
- NeedsMoreInfo
- Closed

Full private chat logs, raw private conversations, private user names, and personal information are not required by default.

Consumers can submit and view appeal status through the consumer portal. Consumer appeal responses do not expose private reviewer IDs or internal reviewer notes beyond privacy-safe status and summary fields.

## Reputation Override Approval Flow

Manual reputation changes are requested first. They are not considered applied until the required approvals are recorded.

Approval count rules:

- Small score changes under 10 points require 1 approval.
- Score changes of 10+ points require approval.
- Score changes of 30+ points require 2 approvals.
- Marking a target Dangerous or Critical requires 2 approvals.
- Marking a target Trusted from HighRisk or Dangerous requires 2 approvals.
- Owner approvals must still be audit logged.

The MVP maps score ranges to these rules. A requested score of 20 or lower is treated as Dangerous/Critical. Moving from 40 or lower to 81 or higher is treated as Trusted-from-risky recovery.

## Audit Logging

HIP audit logs serious admin actions:

- Review item created
- Review item approved
- Review item rejected
- Appeal submitted
- Appeal approved
- Appeal rejected
- Reputation override requested
- Reputation override approved
- Reputation override rejected
- Manual reputation change applied

Audit entries include actor, action, target type, target ID, summary, timestamp, severity, and privacy-safe metadata.

## API Routes

Review queue:

- `GET /api/v1/admin/review`
- `GET /api/v1/admin/review/{id}`
- `POST /api/v1/admin/review`
- `POST /api/v1/admin/review/{id}/decision`
- `POST /api/v1/admin/review/{id}/approve`
- `POST /api/v1/admin/review/{id}/reject`
- `POST /api/v1/admin/review/{id}/needs-more-info`
- `POST /api/v1/admin/review/{id}/assign`

Generated safety review signals:

- `GET /api/v1/admin/review-queue`
- `GET /api/v1/admin/review-queue/{id}`
- `POST /api/v1/admin/review-queue/{id}/assign`
- `POST /api/v1/admin/review-queue/{id}/decision`
- `POST /api/v1/admin/review-queue/{id}/dismiss`

Appeals:

- `POST /api/v1/public/appeals`
- `GET /api/v1/consumer/appeals`
- `POST /api/v1/consumer/appeals`
- `GET /api/v1/admin/appeals`
- `GET /api/v1/admin/appeals/{id}`
- `POST /api/v1/admin/appeals/{id}/decision`
- `POST /api/v1/admin/appeals/{id}/approve`
- `POST /api/v1/admin/appeals/{id}/reject`
- `POST /api/v1/admin/appeals/{id}/needs-more-info`

Reputation overrides:

- `POST /api/v1/admin/reputation-overrides`
- `GET /api/v1/admin/reputation-overrides`
- `POST /api/v1/admin/reputation-overrides/{id}/approve`
- `POST /api/v1/admin/reputation-overrides/{id}/reject`

Audit logs:

- `GET /api/v1/admin/audit-logs`

## UI Routes

- `/admin/review`
- `/admin/review/{id}`
- `/admin/review-queue`
- `/admin/appeals`
- `/admin/appeals/{id}`
- `/admin/reputation-overrides`
- `/admin/audit-logs`
- `/consumer/appeals`

## Known Limitations

- Development-only role enforcement; no production authentication yet.
- No durable audit retention.
- No full approval workflow for generated rule promotion yet.
- No appeal notification system.
- No database-backed reputation mutation yet.
- Admin review decisions are recorded as evidence and audit history, but they do not silently override scoring in the MVP.
