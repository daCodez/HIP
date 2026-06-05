# Admin Scan Result Details

HIP admin scan details let reviewers inspect why a stored browser plugin scan received its score without exposing private page content.

Route:

- UI: `/admin/scans/{scanId}`
- API: `GET /api/v1/admin/scans/{scanId}`

## What The Page Shows

- Domain
- URL hash
- Target type
- Scanned time
- Final status
- Site Safety status
- DomainTrustScore
- PageTrustScore
- ContentRiskScore
- FinalHipScore
- ConfidenceLevel
- Summary
- Reasons
- Warnings
- Positive and negative signals
- Matched built-in/admin rules
- Provider evidence summaries
- Weighted feedback evidence, when available
- Related admin review status, when available

## Privacy Rules

The details page must not show:

- Raw page body text
- Form values
- Passwords
- Tokens
- Cookies
- Private messages
- Email content
- Unrelated browsing history
- Raw full URLs unless a future explicit storage policy allows them

The page can show:

- Domain
- URL hash
- Scores
- Status labels
- Rule IDs and names
- Provider names and normalized summaries
- Weighted feedback totals
- Review state and privacy-safe summaries

## Re-Evaluation Behavior

Stored browser plugin scan results currently keep a URL hash and privacy-safe counts. When a raw URL is not stored, HIP re-evaluates Site Safety details using a safe domain URL plus stored counts and labels.

This means the page explains the stored scan and current rules, but it may not perfectly recreate the exact original page path until explicit full-URL storage or richer privacy-safe page fingerprints are added.

## Review Actions

The MVP details page is read-only. Review decisions should be made in the Review Queue so all decisions remain audited and privacy-safe.

Future work can add action buttons for:

- Send to review
- Mark false positive
- Confirm suspicious/high risk/dangerous
- Dismiss

Those actions should call existing review queue services and create audit log entries.
