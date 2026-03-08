# HIP Protocol v1 — Trust Receipt Spec

HipTrustReceipt is a verifier-signed artifact proving a trust decision.

## Minimum verification checks
1. Required fields present
2. Version supported
3. UTC timestamp format valid
4. Canonical serialization deterministic
5. Signature valid using verifier public key

## Recommended checks list values
- signature
- nonce
- timestamp
- revocation
- policy
- reputation

## Security notes
- Receipts are integrity artifacts, not secrets.
- Do not include private keys or raw secrets.
