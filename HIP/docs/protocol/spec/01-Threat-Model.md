# HIP Protocol v1 — Threat Model

## In-scope threats
- Replay attack (captured request reused)
- Sender identity spoofing
- Message tampering
- Receipt forgery
- Version downgrade/confusion
- Malformed envelope parsing abuse
- Header stripping/tampering by intermediaries
- Key compromise (detection/revocation behavior)
- Clock skew abuse

## Threat handling summary
- Replay: nonce uniqueness + timestamp freshness + replay store
- Spoofing: cryptographic signature verification against sender key
- Tampering: signed canonical payload with payload hash
- Receipt forgery: verifier-signed receipt verification
- Version confusion: strict supported-version allowlist
- Malformed input: fail-closed validation
- Header tampering: signed fields include security headers in canonical payload
- Compromised key: revocation check before trust grant

## Out of scope
- Insecure private key storage in client systems
- Compromised host runtime after verification
- Human phishing awareness
- Transport confidentiality without TLS
