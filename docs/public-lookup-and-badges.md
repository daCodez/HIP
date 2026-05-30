# Public Lookup and Live Badges

HIP is the Human Identity Protocol. TCP connects devices. TLS encrypts the connection. HIP verifies trust, origin, reputation, and risk.

## Public Lookup

Public lookup lets anyone check public trust data for a domain without exposing private user data.

Routes:

- `/lookup`
- `/lookup/{domain}`
- `/lookup/domain/{domain}`
- `/api/v1/public/lookup/{domain}`
- `/api/v1/public/lookup/domain/{domain}`
- `POST /api/v1/public/lookup`

Public lookup can show:

- domain
- HIP score
- status
- public verification state
- signed identity status
- known public risks
- plain-English reasons
- recommended action
- last checked date
- separate score breakdown
- signed identity placeholders for future DNS TXT and `.well-known/hip.json` verification

Public lookup must not expose private chat logs, private reports, user identities, private sender names, private scan history, or raw user-submitted evidence.

## Website Scoring MVP

HIP website scoring currently uses MVP/demo logic until it is connected to real reputation, rules, AI-assisted analysis, and threat intelligence.

Current score bands:

- `0-20` = Dangerous
- `21-40` = High Risk
- `41-60` = Unknown / Caution
- `61-80` = Probably Safe
- `81-100` = Trusted

Current recommended actions:

- `Allow`
- `ShowCaution`
- `ShowWarning`
- `RouteToSafetyPage`
- `Block`

MVP placeholder signals include:

- malformed or missing domains are rejected
- suspicious test domains such as `danger-example.com` are treated as dangerous
- shortened domains are treated with caution
- normal unknown domains return a cautious/probably-safe MVP result
- `verified` test domains return placeholder signed identity fields

HIP must not claim real-world safety until live reputation, rule simulation, verified identity data, and threat feeds are connected.

## Verified Does Not Mean Safe

A verified identity does not automatically mean safe. It means HIP knows who signed or owns the domain or content. The trust score still matters.

Future signed website support is expected to use DNS TXT and `.well-known/hip.json` verification. The public lookup response already includes placeholders for signed identity status, verification method, verified organization, and signature status.

## Live Trust Badges

HIP badges are live data widgets, not static images. A badge must always show the score and status so a site cannot hide a low trust score behind a generic "verified" label.

Badge API:

- `/api/v1/public/badge/domain/{domain}`

The response always includes:

- domain
- score
- status
- verified domain state
- last checked UTC
- public lookup URL
- badge text
- badge variant

## Embed Example

```html
<div
  class="hip-trust-badge"
  data-domain="example.com">
</div>
<script src="https://hip.example.com/hip-badge.js"></script>
```

For local development:

```html
<div
  class="hip-trust-badge"
  data-domain="example.com"
  data-api-base="https://localhost:7053">
</div>
<script src="https://localhost:7053/hip-badge.js"></script>
```

## Anti-Fake Foundation

The badge API returns the domain it verified. The badge script compares the requested domain with the current page hostname where possible. If they do not match, it renders:

`HIP Badge Domain Mismatch`

Every badge links to the official public HIP lookup page.

## Known Limitations

- Badge responses are not cryptographically signed yet.
- Domain matching is exact after removing a leading `www.`.
- Badge data currently uses in-memory/mock scoring.
- A future browser plugin check should detect fake, hidden, or altered badges.

## Future Signed Badge Responses

The badge response model includes a signature placeholder so HIP can later sign badge payloads. Clients should eventually verify the signature before trusting rendered badge data.
