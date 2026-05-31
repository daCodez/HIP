# HIP AI Risk Analysis MVP

HIP uses AI as an assistant inside a hybrid trust system. Rules, weighted scoring, simulation, review, and reputation remain authoritative. AI output must not directly punish users, domains, device keys, organizations, or senders.

## Current MVP

The current implementation adds `IHipAiRiskAnalyzer` with a deterministic development provider named `DevelopmentHipAiRiskAnalyzer`.

It supports:

- URL risk analysis
- short content-context risk analysis
- JSON rule suggestion
- plain-English reasons
- confidence scoring
- review and simulation requirements for high-impact suggestions

The provider is intentionally marked as a development placeholder. It is not production AI and does not call an external AI service.

## API Routes

All routes are versioned and protected by admin rule-management authorization:

- `POST /api/v1/ai/analyze-url`
- `POST /api/v1/ai/analyze-content`
- `POST /api/v1/ai/suggest-rule`

## Privacy Rules

Allowed inputs:

- risky URL or domain
- short risk reason summary
- short suspicious snippet when explicitly supplied
- platform/source
- existing rule signals

Not allowed:

- full private chat logs
- harmless unrelated messages
- unrelated page body text
- form contents
- passwords
- tokens
- secrets

The MVP rejects oversized summaries/snippets and obvious private or secret content markers.

## Output

Analysis responses include:

- risk level
- confidence
- plain-English reasons
- detected patterns
- recommended action
- whether review is required
- whether a rule should be suggested
- placeholder/provider metadata

## Rule Suggestions

AI-suggested rules are JSON `TrustRule` objects underneath.

Rules generated from high-impact results:

- require simulation
- require approval
- start in watch mode
- include review/safety-page actions

Low-impact suggestions may recommend active mode, but still require simulation before trust decisions rely on them.

## Known Limitations

- No production AI provider is configured.
- No private data inspection is supported.
- Pattern detection is deterministic and conservative.
- Suggested rules are not auto-saved or auto-enabled.
- Future providers should plug in behind `IHipAiRiskAnalyzer` and keep the same privacy and review boundaries.
