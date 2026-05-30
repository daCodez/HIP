# HIP Safety Page MVP

The HIP safety page is a protection component used by HIP clients such as the browser plugin and Second Life HUD. HIP remains the product; clients route risky links to `/safety` so users can review risk before continuing.

## Routes

- UI: `/safety?url={encodedUrl}&source=browser`
- UI: `/safety?url={encodedUrl}&source=sl-hud`
- API: `POST /api/v1/safety/evaluate`
- API: `POST /api/v1/safety/report-safe`
- API: `POST /api/v1/safety/report-dangerous`

## Risk Behavior

- Safe: allow
- Unknown: caution label
- Suspicious: warning plus safety page
- Dangerous: strong warning; continue is strongly discouraged
- Critical: block continue by default

For the MVP, `HighRisk` is displayed as `Suspicious` for user-facing safety language.

## Continue Rules

- Unknown: continue allowed
- Suspicious: continue allowed with warning
- Dangerous: continue allowed but strongly discouraged
- Critical: continue blocked by default

The safety page never automatically redirects to a user-provided URL. Continuing requires an explicit click.

## Privacy

Safety evaluation only processes the URL and minimal source context. It must not collect full chat logs, form contents, unrelated browsing history, private messages, or page body text.

## Known Limitations

- Final destination resolution is not implemented yet.
- Risk scoring uses MVP placeholder patterns until connected to rules, reputation, and live lookup data.
- Report-safe/report-dangerous endpoints acknowledge reports for MVP review but do not yet persist a full workflow.
