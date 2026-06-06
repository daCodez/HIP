# Admin Rule Builder MVP

The Admin Rule Builder is available at:

- `/admin/rules`
- `/admin/rules/new`
- `/admin/rules/{id}`

Admin rule editing is protected by the `CanManageRules` policy. In development, HIP uses the dev header auth foundation; production deployment still needs hardened account management and operational controls.

## How It Works

Admins can build a simple HIP rule with an `IF / AND / THEN` form:

- rule name
- description
- enabled state
- mode
- severity
- conditions
- actions
- requires approval
- simulation required

The right side shows a live JSON preview. Advanced mode allows raw JSON editing. Invalid JSON is rejected and cannot be saved.

The MVP form intentionally limits severity to `Low`, `Medium`, `High`, and `Critical`, and limits actions to:

- `setRiskLevel`
- `addReason`
- `routeToSafetyPage`
- `block`
- `allow`
- `requireReview`

## Rule JSON Schema

```json
{
  "ruleId": "new-domain-shortener-high-risk",
  "name": "New Domain With Shortened URL",
  "description": "Flags shortened links that resolve to new domains.",
  "enabled": true,
  "mode": "watch",
  "severity": "high",
  "conditions": [
    {
      "field": "domain.ageDays",
      "operator": "lessThan",
      "value": 30
    }
  ],
  "actions": [
    {
      "type": "setRiskLevel",
      "value": "High"
    }
  ],
  "requiresApproval": true,
  "simulationRequired": true,
  "createdBy": "admin",
  "createdReason": "Suspicious shortened URL pattern",
  "approvalStatus": "Pending",
  "confidenceScore": 0,
  "version": 1
}
```

## Simulation

The MVP uses anonymized default test cases when no explicit cases are supplied:

- safe old domain
- new domain with shortener
- obfuscated URL
- known risky URL
- low reputation sender
- valid signed identity
- invalid or missing signature

Simulation returns pass/fail counts, detection rate, false-positive risk, false-negative risk, speed impact placeholder, privacy impact placeholder, confidence score, recommended action, and failed case details.

The page shows the simulation result, confidence score, false-positive risk, false-negative risk, recommended action, and recommended mode. Auto-generated or high-impact rules should simulate before enforcement.

## Site Safety Rule Simulation

The `/admin/rules` page also includes a Site Safety rule simulation panel for admin-managed Site Safety rules. This uses stored structured rules and privacy-safe sample inputs only. It does not call external scanners, does not execute raw code, and does not send or display page text, passwords, tokens, cookies, form values, private messages, or chat logs.

Simulation output shows:

- whether the rule matched
- matched conditions
- failed conditions
- risk score impact
- trust score impact
- status impact
- warnings added
- reasons added
- confidence impact
- whether approval is required
- whether admin review would be triggered
- recommended mode

Simulation and watch-only rules can be inspected by admins but do not affect live user-facing scores. Disabled and archived rules can still show condition diagnostics, but they are not treated as active and return no live score impact.

## Approval Foundation

High-impact rules require approval:

- Critical severity
- Dangerous severity
- Active mode with HighRisk, Dangerous, or Critical severity

Watch mode can be used before approval.

## Storage

Rules are saved through `IRuleRepository`. Development may use in-memory storage or the SQLite-backed repository depending on the active host configuration.

## Known Limitations

- Production-grade account management is not complete yet.
- Some button behavior is MVP-level; Copy JSON currently tells admins to select the preview text.
- No approval workflow UI yet.
- No rule audit trail yet.
- No AI rule generation yet.
