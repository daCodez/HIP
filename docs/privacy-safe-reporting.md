# HIP Privacy-Safe Reporting

HIP clients can report suspicious findings without sending full private chats, private page content, form contents, or personal data.

The primary ingestion route is:

`POST /api/v1/public/risk-findings`

## What HIP Collects

Risk finding reports may include:

- source client
- platform
- target type
- domain
- URL hash
- optional original URL
- optional sender hash
- risk level
- risk reason
- detection timestamp
- reporter trust level
- short privacy-safe evidence summary
- HIP signature placeholder

If an original URL is supplied, it is treated as sensitive and is not returned in the ingestion response.

## What HIP Must Not Collect By Default

HIP reports must not require:

- full chat logs
- private messages
- form contents
- full page body
- real user names
- unrelated user data
- personal data

Reports marked as containing private content are rejected by the ingestion service.

## Browser Plugin Reporting

The browser plugin reports suspicious or dangerous link domains with:

- source client: `BrowserPlugin`
- platform: `Web`
- target link domain
- URL hash
- risk level
- reason
- timestamp
- privacy-safe evidence facts

It does not send the page body, form contents, or private messages.

## Second Life HUD Reporting Plan

The Second Life HUD should report only:

- risky URL/domain
- sender hash if needed
- platform: `SecondLife`
- reason
- risk level
- timestamp

It must not send full private IM logs by default.

The MVP SL HUD endpoints are:

- `POST /api/v1/sl-hud/activate`
- `POST /api/v1/sl-hud/report-finding`

## Review Queue Connection

High-risk, Dangerous, and Critical reports create review items automatically. Lower-risk reports can be stored without forcing admin review.

## Self-Healing Connection

Accepted reports can be converted into privacy-safe suspicious findings for self-healing pattern detection. The self-healing path receives hashes, domains, risk reasons, platform, timestamps, and anonymized evidence only.

## Known Limitations

- In-memory report storage only.
- HIP signatures are placeholders.
- No rate limiting or reporter identity trust enforcement yet.
- Original URL retention policy is not implemented yet.
- No production queue or database persistence yet.
