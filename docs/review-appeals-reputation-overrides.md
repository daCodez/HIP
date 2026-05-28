# HIP Review Queue, Appeals, and Reputation Overrides

HIP must not blindly punish users, domains, keys, organizations, or content patterns. The review foundation gives admins a privacy-safe way to inspect serious decisions, process appeals, and approve risky reputation changes.

This is a dev/admin MVP. It uses in-memory storage and does not include production authentication. Production deployment must add authentication, authorization, durable storage, and tamper-resistant audit retention.

## Review Queue

Review items can represent:

- suspicious findings
- generated rules
- reputation overrides
- appeals
- false positives
- safety reports

Review items include target type, target ID, risk level, priority, status, evidence summary, privacy-safe evidence, recommended action, and decision details.

Supported actions:

- create review item
- list review items
- get review item
- assign review item
- approve
- reject
- request more info
- close

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

- `GET /api/admin/review`
- `GET /api/admin/review/{id}`
- `POST /api/admin/review`
- `POST /api/admin/review/{id}/approve`
- `POST /api/admin/review/{id}/reject`
- `POST /api/admin/review/{id}/needs-more-info`
- `POST /api/admin/review/{id}/assign`

Appeals:

- `POST /api/public/appeals`
- `GET /api/admin/appeals`
- `POST /api/admin/appeals/{id}/approve`
- `POST /api/admin/appeals/{id}/reject`
- `POST /api/admin/appeals/{id}/needs-more-info`

Reputation overrides:

- `POST /api/admin/reputation-overrides`
- `GET /api/admin/reputation-overrides`
- `POST /api/admin/reputation-overrides/{id}/approve`
- `POST /api/admin/reputation-overrides/{id}/reject`

Audit logs:

- `GET /api/admin/audit-logs`

## UI Routes

- `/admin/review`
- `/admin/appeals`
- `/admin/reputation-overrides`
- `/admin/audit-logs`

## Known Limitations

- In-memory only.
- No production authentication or role enforcement.
- No durable audit retention.
- No full approval workflow for generated rule promotion yet.
- No appeal notification system.
- No database-backed reputation mutation yet.
