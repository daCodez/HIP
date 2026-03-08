# HIP Protocol v1 — Trust Model

Trust decision inputs:
1. Identity authenticity (key ownership)
2. Envelope integrity and freshness
3. Device trust hints (optional)
4. Reputation assertions (optional)
5. Policy engine decision

Default trust posture: **fail closed**.

## Trust states
- Allow
- Challenge
- Warn
- RateLimit
- Quarantine
- Block

## Trust evidence artifact
- HipTrustReceipt is signed by verifier and can be validated independently.

## Assumptions
- TLS present
- Public keys discoverable via trusted key resolver
- Clock skew bounded by configuration
