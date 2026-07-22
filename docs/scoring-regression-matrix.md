# HIP scoring regression matrix

Last verified: 2026-07-20

HIP-0306 locks every mandatory scenario from section 25.2 of the master plan to
the authoritative formal scoring pipeline. The fixtures use synthetic,
privacy-safe facts and make no network calls.

The exact numeric values below are compatibility expectations for model
`hip-0301-v1`. Higher domain, page, and final values mean more trust; higher
content-risk values mean more risk. Confidence remains separate from score.

| Mandatory scenario | Domain | Page | Content risk | Final | Presentation |
|---|---:|---:|---:|---:|---|
| Trusted domain homepage | 95 | 82 | 0 | 93 | Trusted |
| Trusted domain user-generated page | 95 | 76 | 0 | 69 | Limited Trust Data |
| Unknown clean HTTPS site | 58 | 60 | 40 | 59 | Limited Trust Data |
| Unknown login page | 58 | 52 | 30 | 60 | Limited Trust Data |
| Unknown payment page | 58 | 45 | 45 | 53 | Limited Trust Data |
| Executable download | 80 | 58 | 30 | 39 | Suspicious |
| Archive download | 70 | 65 | 25 | 70 | Mostly Trusted |
| Shortened URL | 60 | 55 | 25 | 64 | Limited Trust Data |
| Obfuscated URL | 60 | 50 | 35 | 59 | Limited Trust Data |
| Known phishing hit | 90 | 35 | 80 | 9 | Dangerous |
| Known malware hit | 90 | 30 | 90 | 9 | Dangerous |
| Provider timeout | 75 | 65 | 20 | 74 | Limited Trust Data; low confidence |
| Conflicting providers | 90 | 90 | 10 | 90 | Unknown; conflicted confidence |
| Verified signature with risky content | 90 | 45 | 80 | 52 | Limited Trust Data |
| Many anonymous reports | 40 | 45 | 55 | 43 | Unknown |
| Trusted reviewer report | 61 | 60 | 40 | 60 | Limited Trust Data |

The remaining lifecycle scenarios assert behavior rather than inventing a
second scoring formula:

- Disabled and watch-only rules do not change the formal score.
- An approved active rule changes the score and publishes a stable rule reason.
- A critical override is rejected without approval.
- An approved critical override aligns the `Dangerous` label with a score no
  greater than 9 and uses its own reason code; it is not mislabeled as malware.

Run the focused compatibility gate with:

```powershell
dotnet test tests/HIP.Tests/HIP.Tests.csproj --filter FullyQualifiedName~HipMandatoryScoringRegressionTests
```

Changes to these expectations require a scoring-model version decision, updated
explainability, and an explicit client compatibility review.
