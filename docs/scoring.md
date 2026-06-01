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
