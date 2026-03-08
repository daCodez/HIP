# HIP Simulator Policy Suggestions

- Rule: Sim.wrong-field-type.Auto
- Category: invalid
- When: eventType == 'login.attempt'
- Then: Challenge
- Severity: Medium
- Notes: Generated from uncovered simulator scenario. Review for false positives before enabling.
- Signals needed: failedAttempts
- Tests:
 - Pass: login.attempt with actor u
 - Fail: different event type than login.attempt

- Rule: Sim.unsupported-enum-value.Auto
- Category: invalid
- When: eventType == 'login.attempt'
- Then: Challenge
- Severity: Medium
- Notes: Generated from uncovered simulator scenario. Review for false positives before enabling.
- Signals needed: ipRisk
- Tests:
 - Pass: login.attempt with actor u
 - Fail: different event type than login.attempt

