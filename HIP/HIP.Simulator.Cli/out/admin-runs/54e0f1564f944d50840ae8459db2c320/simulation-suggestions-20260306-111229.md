# HIP Simulator Policy Suggestions

- Rule: Sim.password_reset_spike.Auto
- Category: uncovered
- When: eventType == 'password_reset_spike'
- Then: Challenge
- Severity: Medium
- Notes: Generated from uncovered simulator scenario. Review for false positives before enabling.
- Signals needed: indicator
- Tests:
 - Pass: password_reset_spike with actor user-2
 - Fail: different event type than password_reset_spike

- Rule: Sim.unusual_data_export.Auto
- Category: uncovered
- When: eventType == 'unusual_data_export'
- Then: Challenge
- Severity: Medium
- Notes: Generated from uncovered simulator scenario. Review for false positives before enabling.
- Signals needed: indicator
- Tests:
 - Pass: unusual_data_export with actor user-2
 - Fail: different event type than unusual_data_export

- Rule: Sim.suspicious_device_fingerprint_change.Auto
- Category: uncovered
- When: eventType == 'suspicious_device_fingerprint_change'
- Then: Challenge
- Severity: Medium
- Notes: Generated from uncovered simulator scenario. Review for false positives before enabling.
- Signals needed: indicator
- Tests:
 - Pass: suspicious_device_fingerprint_change with actor user-2
 - Fail: different event type than suspicious_device_fingerprint_change

- Rule: Sim.mfa_method_removed.Auto
- Category: uncovered
- When: eventType == 'mfa_method_removed'
- Then: Challenge
- Severity: Medium
- Notes: Generated from uncovered simulator scenario. Review for false positives before enabling.
- Signals needed: indicator
- Tests:
 - Pass: mfa_method_removed with actor user-2
 - Fail: different event type than mfa_method_removed

- Rule: Sim.inbox_forwarding_rule_created.Auto
- Category: uncovered
- When: eventType == 'inbox_forwarding_rule_created'
- Then: Challenge
- Severity: Medium
- Notes: Generated from uncovered simulator scenario. Review for false positives before enabling.
- Signals needed: indicator
- Tests:
 - Pass: inbox_forwarding_rule_created with actor user-2
 - Fail: different event type than inbox_forwarding_rule_created

- Rule: Sim.token_used_from_two_ips.Auto
- Category: uncovered
- When: eventType == 'token_used_from_two_ips'
- Then: Challenge
- Severity: Medium
- Notes: Generated from uncovered simulator scenario. Review for false positives before enabling.
- Signals needed: indicator
- Tests:
 - Pass: token_used_from_two_ips with actor user-2
 - Fail: different event type than token_used_from_two_ips

- Rule: Sim.api_key_created.Auto
- Category: uncovered
- When: eventType == 'api_key_created'
- Then: Challenge
- Severity: Medium
- Notes: Generated from uncovered simulator scenario. Review for false positives before enabling.
- Signals needed: indicator
- Tests:
 - Pass: api_key_created with actor user-2
 - Fail: different event type than api_key_created

- Rule: Sim.recovery_email_changed.Auto
- Category: uncovered
- When: eventType == 'recovery_email_changed'
- Then: Challenge
- Severity: Medium
- Notes: Generated from uncovered simulator scenario. Review for false positives before enabling.
- Signals needed: indicator
- Tests:
 - Pass: recovery_email_changed with actor user-2
 - Fail: different event type than recovery_email_changed

- Rule: Sim.unknown_event_type.Auto
- Category: uncovered
- When: eventType == 'unknown_event_type'
- Then: Challenge
- Severity: Medium
- Notes: Generated from uncovered simulator scenario. Review for false positives before enabling.
- Signals needed: indicator
- Tests:
 - Pass: unknown_event_type with actor user-2
 - Fail: different event type than unknown_event_type

- Rule: Sim.oauth_consent_grant.Auto
- Category: uncovered
- When: eventType == 'oauth_consent_grant'
- Then: Challenge
- Severity: Medium
- Notes: Generated from uncovered simulator scenario. Review for false positives before enabling.
- Signals needed: indicator
- Tests:
 - Pass: oauth_consent_grant with actor user-2
 - Fail: different event type than oauth_consent_grant

