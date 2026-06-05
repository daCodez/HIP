# HIP Scoring

HIP uses a hybrid scoring model:

- deterministic rules
- weighted formula
- AI-assisted analysis later

HIP does not use one flat internal trust score. The final HIP score is `0-100`, but it is derived from separate domain, page, and content scores.

## Ranges

- `0-9`: Dangerous
- `10-24`: HighRisk
- `25-39`: Suspicious
- `40-49`: Unknown
- `50-69`: LimitedTrustData
- `70-84`: MostlyTrusted
- `85-100`: Trusted

## Score Categories

- DomainTrustScore
- PageTrustScore
- ContentRiskScore
- Sender Score
- Link Score
- Device/Key Score
- Organization Score
- Final HIP Score

`DomainTrustScore` describes the root domain's overall trust. `PageTrustScore` describes the exact URL. `ContentRiskScore` describes page content, links, forms, downloads, scripts, and visible behavior. `FinalHipScore` is the user-facing score derived from those layers.

Domain trust does not automatically make every page safe. A trusted domain can host risky user-generated content, a clean page scan does not make an unknown domain trusted, and downloads must never inherit full trust from the parent domain.

Every score must include a plain-English explanation. A valid signature contributes to origin and integrity confidence, but it does not automatically make content safe.

## Accuracy Goals

HIP scoring is intentionally conservative. The core scoring rule is:

- Trust must be earned.
- Risk must be proven.
- Unknown must stay unknown.
- No bad signals found does not mean trusted.
- A clean scan does not mean trusted.
- HTTPS does not mean trusted.

The scanner must avoid both over-trusting unknown sites and over-penalizing known domains without clear page or content evidence. A domain such as `github.com` can have strong domain trust, while a specific repository, release asset, or download page still needs page and content review. Conversely, an unknown site with HTTPS and no obvious warnings should usually remain `LimitedTrustData` or `Unknown` until HIP has stronger public trust evidence.

HIP may use a small built-in known-domain baseline for well-known public domains such as `github.com`, `microsoft.com`, `google.com`, `apple.com`, and `wikipedia.org`. That baseline earns `DomainTrustScore` only. It does not make a page trusted by itself, and it does not suppress download, form, redirect, script, phishing, malware, or user-generated-content checks.

Known domains with user-generated surfaces receive separate page scoring. For example, a GitHub homepage can have high domain and page trust, while a repository, release asset, or download page is capped at the page layer and lowered further when executable downloads or scam labels are present.

## Layered Score Contract

Every user-facing scoring result should expose these fields:

- `DomainTrustScore`: root-domain trust signals, such as known reputation, verification, and public history.
- `PageTrustScore`: exact URL trust signals, including redirects, URL shape, forms, page-specific history, and page reputation.
- `ContentRiskScore`: content and behavior signals, including downloads, scripts, forms, suspicious link patterns, and privacy-safe risk labels.
- `FinalHipScore`: the final score shown to the user after the separate layers are combined.
- `Status`: final status label.
- `ConfidenceLevel`: how much evidence HIP has and whether evidence conflicts.
- `Reasons`: plain-English reasons for the score.
- `Warnings`: clear warnings when risk exists.

The final score must never hide the separate scores. If a trusted domain hosts risky page content, HIP should explain the mixed result, for example: "The parent domain has strong trust signals, but this specific page or content may need review."

## Accuracy Test Scenarios

The scoring accuracy regression suite covers these behaviors:

- GitHub homepage keeps high domain trust and does not become high risk without strong evidence.
- GitHub repository pages do not inherit full trust from the parent domain.
- Trusted domains with risky repository or download content score lower at the page/content layer.
- Unknown clean sites do not score `Trusted` or `MostlyTrusted`.
- HTTPS-only sites receive only a small transport-safety signal.
- Login and payment fields on limited-trust sites raise form risk.
- Executable downloads raise download risk strongly.
- Archive downloads add review warnings without automatically becoming `Dangerous`.
- Scam, urgency, and impersonation labels raise phishing risk using privacy-safe labels.
- Known phishing and malware indicators force dangerous status with clear warnings.
- Suspicious redirects and shortened URLs raise redirect risk.
- External provider timeouts do not crash scoring or create trust.
- Clean external scanner results do not make unknown domains trusted.
- Strong TLS grades provide only a small boost.
- Weak TLS lowers confidence.
- Google Web Risk-style and VirusTotal-style threat hits can force high-risk or dangerous results.
- Conflicting external evidence lowers confidence and creates a review warning.
- Anonymous feedback has weak impact.
- Trusted and admin feedback has stronger impact.
- Many low-trust reports do not instantly make a target dangerous.
- Disabled, simulation, and watch-only admin rules do not affect final scores.
- Enforced approved admin rules can affect final scores.
- Dangerous admin overrides require approved high-impact rule behavior.
- Results are explainable and do not expose private raw content.

## Privacy Accuracy

Scoring tests confirm HIP does not require or return raw private content. Scoring inputs and outputs should avoid:

- raw page text
- passwords
- typed form values
- cookies
- tokens
- private messages
- unrelated browsing history

Allowed scoring evidence includes:

- domain
- URL hash
- counts
- boolean flags
- matched risk labels
- provider summaries
- scores
- reasons
- warnings

Browser-observed signals should describe what was observed, such as "password field present" or "executable download link count," without sending field values or page body text.

## Manual Test Steps

1. Start the HIP API and web app locally.
2. Load the browser extension unpacked from `clients/browser-extension`.
3. Visit a known high-trust domain such as `github.com`.
4. Confirm the popup shows high domain trust but does not claim every page is fully trusted.
5. Visit or create a page with executable links and confirm page/content risk lowers the final score.
6. Visit an unknown HTTPS site and confirm it remains `LimitedTrustData` or `Unknown`.
7. Test a login or payment form and confirm the popup explains the form risk without collecting form values.
8. Test a shortened or suspicious redirect link and confirm it routes through the safety page when risk is meaningful.
9. Review public lookup for the scanned domain and confirm it shows public-safe summaries only.
10. Run `dotnet test tests/HIP.Tests/HIP.Tests.csproj --filter "FullyQualifiedName~HipScoringAccuracyTests"`.

## MVP Limitations

- External providers are still configuration-driven and disabled unless explicitly enabled.
- Clean external scanner results do not prove trust; they only reduce specific known-risk concerns.
- TLS quality is a security-confidence signal, not an identity or safety guarantee.
- Browser plugin scans are privacy-safe summaries, not full content analysis.
- Current scoring uses deterministic rules and placeholders where production reputation, identity, and provider data are not yet available.
- Admin-created rules are structured and guarded, but the full production approval workflow is still evolving.
