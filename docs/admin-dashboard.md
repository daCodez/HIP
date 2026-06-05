# HIP Admin Dashboard

The Admin Dashboard is available at `/admin`. It gives authorized HIP admins a privacy-safe overview of system activity.

## Cards

The MVP dashboard now uses stored browser plugin scan results as the first real scan data source: `BrowserPluginScanResults`.

Scan cards show:

- total scans
- scans today
- trusted results
- limited trust results
- suspicious results
- high-risk results
- dangerous results
- domains scanned
- links scanned
- risky links found
- suspicious links found
- dangerous links found
- scans in the last 24 hours
- scans in the last 7 days
- average HIP score
- latest scan age

Operational cards still show:

- risky findings
- open review items
- pending review items across manual and generated queues
- high-severity review items
- oldest open review age in hours
- pending appeals
- pending reputation overrides
- active rules
- active built-in rules
- active admin rules
- watch mode rules
- watch-only admin rules
- simulation rules
- disabled rules
- feedback received
- Looks Safe feedback
- Looks Suspicious feedback
- Report Issue feedback
- suspicious feedback spikes
- self-healing candidates
- dangerous domains
- external provider errors
- API health

If no stored browser scan data exists, the dashboard shows:

`No scan data yet. Run the browser plugin on a test page to generate real data.`

No fake scan counts are generated.

Feedback cards use persisted weighted trust feedback. Feedback is evidence, not voting; the dashboard only shows counts and spike indicators, never page text or reporter identity. External provider error counts are currently marked `Not connected yet` because provider error history is not persisted into a dashboard-ready store.

## Recent Activity

Recent activity includes privacy-safe summaries for:

- browser plugin scans
- risk findings
- review items
- generated admin review signals
- weighted feedback
- audit logs
- generated rule candidates
- reputation changes

The dashboard must not display full private chat logs, private message bodies, raw private evidence, real user names by default, original risky URLs, or sender hashes.

Browser scan summaries may display only domain, score, risk level, counts, last checked date, and reason summaries. They must not show page text, form values, passwords, tokens, private messages, full browsing history, or raw scan payloads.

## Risky Domains and Recent Scans

The dashboard includes:

- Top Risky Domains: sorted by dangerous links first, then total risky links.
- Recent Scans: newest stored browser plugin scans first.

Both sections are domain-level summaries only.

## Quick Links

The dashboard links to:

- Rules
- Self-Healing
- Review Queue
- Appeals
- Reputation Overrides
- Audit Logs
- Public Lookup
- Badge Docs
- Browser Plugin Docs

## Role Access

`/admin` and `/api/v1/admin/dashboard/summary` require `CanViewAdminDashboard`.

Allowed roles:

- Owner
- Admin
- Moderator
- Support
- ReadOnly

Support can view the dashboard as an operational overview. Rule management, override approval, and other actions remain protected by narrower policies.

## API

- `GET /api/v1/admin/dashboard/summary`
- `GET /api/v1/admin/dashboard/risky-domains`
- `GET /api/v1/admin/dashboard/recent-scans`

The summary response returns dashboard cards, recent activity summaries, API health, generation timestamp, data source, no-data state, top risky domains, and recent scans.

## Generating Test Scan Data

1. Run HIP API/Web locally.
2. Load the browser extension from `clients/browser-extension`.
3. Visit a test page with a few links.
4. Open the extension popup and confirm `Last submitted` shows success.
5. Refresh `/admin` and verify cards reflect the stored scan result.

## Known Limitations

- Some review/appeal/override services still use scoped in-memory state.
- Scan history currently comes from browser plugin scan-result persistence.
- There is no charting or time-window filtering yet.
- Production authentication is still required before deployment.
