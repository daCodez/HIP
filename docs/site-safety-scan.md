# HIP Site Safety Scan MVP

HIP Site Safety Scan is a page-level risk layer used by HIP clients before a user trusts a website, link, form, or download.

TCP connects devices. TLS encrypts the connection. HIP verifies trust, origin, reputation, and risk.

## What It Does

The MVP scan accepts a public HTTP or HTTPS URL plus optional privacy-safe observations from HIP clients. It returns:

- malware risk score
- phishing risk score
- redirect risk score
- script risk score
- download risk score
- form risk score
- reputation risk score
- overall safety risk score
- status
- plain-English summary
- reasons, warnings, positive signals, and negative signals
- confidence level
- impact on `DomainTrustScore`, `PageTrustScore`, `ContentRiskScore`, and final HIP score

## Status Labels

- `Clean`: no obvious malware/phishing found and HIP has enough supporting trust data.
- `LimitedData`: no obvious malware/phishing found, but HIP does not have enough trust data to call the site trusted.
- `Unknown`: reserved for future scanners when risk cannot be categorized.
- `Suspicious`: review recommended.
- `HighRisk`: strong warning and safety routing recommended.
- `Dangerous`: avoid the page.
- `ScanFailed`: HIP could not complete the scan safely and no trust boost is applied.

## API Route

Current version:

```http
POST /api/v1/site-safety/scan
```

Example request:

```json
{
  "url": "https://example.com/login",
  "observedSignals": {
    "downloadLinks": ["https://example.com/setup.exe"],
    "hasLoginForm": true,
    "hasPasswordField": true,
    "inlineScriptCount": 4,
    "externalScriptUrls": ["https://cdn.example.com/app.js"],
    "trustDataAvailable": false
  }
}
```

## Privacy Rules

The scanner must not receive or store:

- page body text
- script contents
- form values
- passwords
- tokens
- private messages
- full chat logs

The browser plugin sends only structural facts such as counts, source URLs, download-link URLs for extension checks, and whether login fields exist.

## Security Rules

The MVP scanner does not:

- execute scripts
- download or run files
- submit forms
- crawl full websites
- follow unlimited redirects
- scan localhost, loopback, private network, or link-local hosts

The validator blocks non-public targets to reduce SSRF risk.

## Download Risk

Executable-like extensions create high risk:

`.exe`, `.dll`, `.bat`, `.cmd`, `.scr`, `.ps1`, `.vbs`, `.js`, `.jar`, `.apk`, `.msi`

Archive-like extensions require review but are not automatically dangerous:

`.zip`, `.rar`, `.7z`, `.iso`

## Scoring Behavior

Clean site-safety findings provide only a small trust improvement. Unknown or limited-data sites do not receive a trust boost. A clean scan with no reputation or identity data returns `LimitedData`, not `Trusted`.

Site Safety affects:

- `DomainTrustScore`
- `PageTrustScore`
- `ContentRiskScore`
- final HIP score

It does not replace domain reputation, identity verification, signed content verification, or rule-engine decisions.

## Browser Plugin Display

The browser plugin popup shows:

- Site Safety status
- malware risk
- phishing risk
- redirect risk
- download risk
- script risk
- plain-English scan summary

The plugin still avoids collecting page text and form contents.

## Known MVP Limits

- No real malware sandboxing is performed.
- No external threat-intelligence feeds are connected yet.
- Redirects are scored from observed client facts, not crawled server-side.
- Recent scan caching is short-lived and in-process only.
- Site Safety is one signal in the final HIP decision, not the whole decision.
