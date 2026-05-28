# HIP Rules Engine

HIP rules are JSON underneath. Early rules should be simple and auditable:

```json
{
  "id": "shortener-new-domain",
  "conditions": [
    { "field": "link.usesShortener", "operator": "equals", "value": true },
    { "field": "destination.domainAgeDays", "operator": "lessThan", "value": 30 }
  ],
  "action": {
    "type": "adjustScore",
    "category": "Link",
    "points": -25,
    "reason": "This link is risky because it uses a shortener and redirects to a new domain."
  }
}
```

## Self-Healing Flow

1. New pattern detected.
2. Auto-generated rule created.
3. Simulation runs automatically.
4. Confidence score is calculated from simulation results.
5. False-positive risk is calculated.
6. Rule is classified.
7. Low-risk rule may auto-enforce.
8. High-impact rule enters watch mode.
9. Admin approval if needed.
10. Rollback if rule causes issues.
