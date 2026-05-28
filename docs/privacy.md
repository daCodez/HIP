# HIP Privacy

HIP is privacy-first by default.

Default reporting should not send or store full private chat logs. Reports should use the minimum data needed to evaluate risk.

## Default Report Data

- risky URL
- domain
- URL hash
- sender hash if needed
- platform
- risk reason
- timestamp
- HIP signature

## Retention Direction

- Normal risky findings: about 90 days.
- Confirmed dangerous patterns: long-term.
- User-linked or private data: shortest possible.

Reporter trust can weight feedback, but privacy boundaries must remain explicit.
