# Admin Rule Builder MVP

The Admin Rule Builder is available at `/admin/rules`.

This is a development-only MVP. Authentication, durable storage, full approval workflows, and audit logging are future work.

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

## Rule JSON Schema

```json
{
  "ruleId": "new-domain-shortener-high-risk",
  "name": "New Domain With Shortened URL",
  "description": "Flags shortened links that resolve to new domains.",
  "enabled": true,
  "mode": "Watch",
  "severity": "HighRisk",
  "conditions": [
    {
      "field": "domain.ageDays",
      "operator": "LessThan",
      "value": 30
    }
  ],
  "actions": [
    {
      "type": "SetRiskLevel",
      "value": "HighRisk"
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

## Approval Foundation

High-impact rules require approval:

- Critical severity
- Dangerous severity
- Active mode with HighRisk, Dangerous, or Critical severity

Watch mode can be used before approval.

## Storage

Rules are saved in memory through `IRuleRepository` and `InMemoryRuleRepository`. The interface is ready for database-backed storage later.

## Known Limitations

- No authentication or authorization yet.
- Saved rules reset when the process restarts.
- No approval workflow UI yet.
- No rule audit trail yet.
- No AI rule generation yet.
