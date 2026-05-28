# HIP Self-Healing Rule Detection

HIP self-healing is the foundation for turning repeated privacy-safe suspicious findings into simulated rule candidates.

The MVP does not use AI, private chat logs, or production persistence. It groups repeated findings, generates conservative JSON rules, runs simulation automatically, and classifies whether a candidate can be active or must remain in watch mode pending approval.

## Flow

1. Privacy-safe suspicious findings are submitted.
2. The pattern detector groups similar findings by finding type, domain, platform, and risk level.
3. The rule candidate generator creates a HIP JSON rule from each cluster.
4. Simulation runs automatically for every generated rule.
5. The confidence score comes from simulation results.
6. High-impact rules require approval and start in Watch mode.
7. Low-risk safe-action rules may become Active.
8. Rollback metadata is attached to every candidate.

## Finding Privacy Limits

Self-healing findings may include:

- risky domain
- URL hash
- platform
- risk level
- reason
- timestamp
- source type
- reporter trust level
- anonymized evidence

Findings must not require full private chat messages, real user names, raw private conversations, or personal information by default.

## Rule Candidate Generation

Generated rules include:

- rule ID
- name and description
- enabled state
- mode
- severity
- conditions
- actions
- approval requirement
- simulation requirement
- created-by metadata
- confidence score
- version

`createdBy` is set to `HIP Self-Healing Engine`. `simulationRequired` is always true.

## Approval Rules

Low-risk candidates that only add a reason or mark for simulation may become Active.

High-risk, Dangerous, and Critical candidates require approval. Critical candidates are always forced into Watch mode and must not auto-enforce.

## Rollback Foundation

Every generated candidate includes a rollback plan with:

- affected rule ID
- previous rule version if known
- rollback reason
- rollback capability
- creation timestamp

The current MVP stores only metadata. Full rollback execution and UI review are future work.

## Admin Routes

- UI: `/admin/self-healing`
- Detect patterns: `POST /api/admin/self-healing/detect-patterns`
- Generate rule from cluster: `POST /api/admin/self-healing/generate-rule`
- Analyze findings end-to-end: `POST /api/admin/self-healing/analyze-findings`

## Known Limitations

- No AI-assisted pattern detection yet.
- No production clustering or ML.
- No durable rule storage for generated candidates.
- No full approval workflow UI.
- No automatic rollback execution.
- Simulation uses generated privacy-safe test facts, not live traffic.

Future work can add AI-assisted pattern suggestions, signed generated rule metadata, persistent review queues, automated rollback metrics, and browser-extension badge checks for generated rule provenance.
