# HIP Browser Plugin MVP

HIP is the trust and origin verification protocol/platform. The browser plugin is one HIP client that consumes HIP APIs for website scoring and link risk signals.

The MVP supports current website scoring, page link scanning, attention-only link badges, safety-page routing for high-risk links, privacy-safe risk finding reports, and popup score summaries.

The browser plugin uses versioned v1 endpoints:

- `POST /api/v1/browser/score-site`
- `POST /api/v1/browser/scan-links`
- `POST /api/v1/public/risk-findings`

Normal safe links do not receive badges. HIP shows labels only when attention is useful: `Unknown`, `Caution`, `Suspicious`, `Dangerous`, or `Verified`.

The plugin may send the current URL/domain, href URLs needed for link scoring, URL hashes in risk reports, risk reason summaries, scan mode, and source client.

The plugin must not send page body text, form values, passwords, usernames, email text, message bodies, or private chat content.

Manual test: run `dotnet run --project src/HIP.Web/HIP.Web.csproj --launch-profile https`, load `clients/browser-extension` as an unpacked Chromium extension, visit a test page, and confirm the popup score plus attention-only link badges.

Known limitations: link analysis is mostly domain-based with a shortener heuristic, risk reports use a placeholder HIP signature, and file content, AI page analysis, full social parsing, and webmail parsing are deferred.
