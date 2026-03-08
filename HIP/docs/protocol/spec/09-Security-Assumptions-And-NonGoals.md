# HIP Protocol v1 — Security Assumptions and Non-goals

## Assumptions
- TLS is enabled and validated
- Key resolver source is trusted
- System clocks are synchronized within configured skew
- Implementations protect private keys

## Non-goals
- Endpoint malware defense
- Full SOC/EDR replacement
- Blockchain dependency for operation
- Automatic key custody management

## Explicitly not protected by HIP alone
- Compromised trusted endpoint after successful authentication
- Data misuse by authorized principal
- Insider abuse without policy controls
