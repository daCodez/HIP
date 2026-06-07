# HIP Admin Dashboard

The Admin Dashboard is available at `/admin`. It gives authorized HIP admins a privacy-safe overview of system activity.

## Cards

The MVP dashboard now uses stored browser plugin scan results as the first real scan data source: `BrowserPluginScanResults`.

Scan cards show:

- total scans
- scans today
- trusted results
- mostly trusted results
- limited trust results
- unknown results
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

Feedback cards use persisted weighted trust feedback. Feedback is evidence, not voting; the dashboard only shows counts and spike indicators, never page text or reporter identity.

External provider error counts use real dashboard-ready evidence only:

- privacy-safe provider error counters stored with browser scan metadata
- generated admin review signals from `ExternalProvider`

If neither source has provider data yet, the card shows `Not connected yet`. If provider metadata is present and no failures are known, the card shows `Connected`. Provider threat hits are shown in Recent Threats; provider failures are counted as provider errors.

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

## Recent Threats

The dashboard now has a dedicated `Recent Threats` section. This is intentionally separate from `Recent Activity`.

Recent Threats shows only real HIP evidence that needs attention, such as:

- Dangerous or HighRisk browser Site Safety scans
- Suspicious scans with warning, redirect, download, phishing, malware, or risky-link signals
- trusted or mostly trusted domains where page/content signals are risky
- HighRisk, Dangerous, or Critical privacy-safe finding reports
- open or high-priority review items
- generated admin review signals such as unknown login pages, external provider threat hits, suspicious redirects, risky downloads, or provider conflicts
- admin rule signals, including high-impact rule triggers and Dangerous override review signals
- repeated suspicious weighted feedback

Normal clean pages, Trusted scans with no risk signals, and LimitedTrustData scans with no warnings do not appear in Recent Threats.

If no threat evidence exists, the UI shows:

`No recent threats found.`

Rows are sorted newest first and show:

- domain
- severity
- status
- final HIP score when available
- source
- short privacy-safe reason
- created time

Recent Threats must not display full URLs, page body text, form values, passwords, tokens, cookies, private messages, unrelated browsing history, raw reports, or reporter private identity. URL hashes and related scan/review/rule IDs may be included in the API response for admin correlation.

## Risky Domains and Recent Scans

The dashboard includes:

- Top Risky Domains: sorted by dangerous links first, then total risky links.
- Recent Scans: newest stored browser plugin scans first.

Recent Scans shows:

- domain
- status
- final score
- domain trust score, when the scan stored one
- page trust score, when the scan stored one
- content risk score, when the scan stored one
- confidence
- short reason
- scanned time
- source
- plugin version, when supplied by the browser extension

If no scan rows are available, the page shows `No scans yet.` If the dashboard service is present but scan history is not connected, the empty state says `Scan history not connected yet.`

Both sections are privacy-safe summaries only. They do not show page text, form values, passwords, tokens, cookies, private messages, browsing history, or raw full URLs.

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

The summary response returns dashboard cards, recent activity summaries, recent threats, API health, generation timestamp, data source, no-data state, top risky domains, and recent scans.

## Refresh Behavior

The Admin Dashboard does not auto-refresh in the MVP. This avoids hidden request loops while live scan storage and provider evidence are still being exercised during development.

The `/admin` page includes a manual `Refresh` button. During refresh:

- the button shows `Refreshing...`
- the button is disabled so duplicate requests are not spammed
- the dashboard shows a loading state on first load
- the page records a `Last updated` timestamp after a successful refresh
- refresh failures show a safe generic message without stack traces, secrets, raw URLs, or private scan data
- empty scan history continues to show `No scan data yet` instead of fake metrics

If auto-refresh is added later, it should use a conservative interval, stop when the dashboard is not visible, and keep the same privacy and duplicate-request protections.

## Live Data Flow

The dashboard does not run scans itself. It reads already-stored, privacy-safe outputs from HIP services:

1. Browser plugin scan results provide scan totals, status counts, link counts, recent scans, and risky domain aggregates.
2. Risk finding reports provide high-risk finding counts and recent finding activity.
3. Manual and generated review queues provide pending review counts, high-severity review counts, and review-triggered threat rows.
4. Weighted feedback provides feedback counts and repeated suspicious feedback signals.
5. Built-in, trust, and admin rule repositories provide active/watch/simulation/disabled rule counts.
6. Self-healing candidates provide generated rule candidate counts.
7. Provider metadata and generated external-provider review signals provide provider error counts and provider threat rows.

Missing sources are shown as `No Data`, `Not connected yet`, or `Placeholder`. HIP must never invent fake rows or counts to make the dashboard look active.

## Generating Test Scan Data

1. Run HIP API/Web locally.
2. Load the browser extension from `clients/browser-extension`.
3. Visit a test page with a few links.
4. Open the extension popup and confirm `Last submitted` shows success.
5. Open `/admin`.
6. Click `Refresh`.
7. Verify `Last updated` changes and cards reflect the stored scan result.
8. Verify Recent Scans shows the visited domain, status, final score, layered scores if available, confidence, short reason, scanned time, source, and plugin version.
9. If no scans exist yet, verify the dashboard shows `No scan data yet` and `No scans yet` instead of fake activity.
10. Trigger a risky link, login/payment warning, provider review signal, or repeated suspicious feedback in development data.
11. Click `Refresh` on `/admin` and verify the item appears in Recent Threats while normal clean pages remain absent.

## Known Limitations

- Some review/appeal/override services still use scoped in-memory state.
- Scan history currently comes from browser plugin scan-result persistence.
- There is no charting or time-window filtering yet.
- Production authentication is still required before deployment.
