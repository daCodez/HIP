# HIP Admin Dashboard

The Admin Dashboard is available at `/admin`. It gives authorized HIP admins a privacy-safe overview of system activity.

## Cards

The MVP dashboard shows:

- total scans
- risky findings
- blocked/routed safety links
- open review items
- pending appeals
- pending reputation overrides
- active rules
- watch mode rules
- self-healing candidates
- dangerous domains
- API health

Counts use real HIP services and repositories where available. The safety-routed link count is currently an estimate based on HighRisk, Dangerous, and Critical findings.

## Recent Activity

Recent activity includes privacy-safe summaries for:

- risk findings
- review items
- audit logs
- generated rule candidates
- reputation changes

The dashboard must not display full private chat logs, private message bodies, raw private evidence, real user names by default, original risky URLs, or sender hashes.

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

`GET /api/v1/admin/dashboard/summary`

Returns dashboard cards, recent activity summaries, API health, and generation timestamp.

## Known Limitations

- Some review/appeal/override services still use scoped in-memory state.
- Safety-routed links are estimated from risk level until full safety-route telemetry exists.
- There is no charting or time-window filtering yet.
- Production authentication is still required before deployment.
