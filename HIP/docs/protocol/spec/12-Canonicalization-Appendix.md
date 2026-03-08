# HIP Protocol v1 — Canonicalization Appendix

Status: Normative for HIP v1 signatures

This appendix defines deterministic canonical serialization used before signing/verifying HIP envelopes and trust receipts.

## A. Global rules

1. Encoding: UTF-8
2. Format: JSON object, minified (no insignificant whitespace)
3. Field names: lowercase
4. Field order: fixed, exactly as listed in this appendix
5. Timestamps: UTC, round-trip format (`O`), e.g. `2026-03-06T20:00:00.0000000Z`
6. Null handling: omit null/empty optional fields
7. Arrays: preserve array element order
8. Extension object keys: lowercase and sorted lexicographically (ordinal)

If sender and verifier canonicalize differently, signature verification must fail.

## B. Envelope canonical object

Canonical field order for `HipMessageEnvelope`:

1. `hipversion`
2. `messagetype`
3. `senderhipid`
4. `receiverhipid` (optional)
5. `timestamputc`
6. `nonce`
7. `payloadhash`
8. `correlationid`
9. `deviceid` (optional)
10. `trustclaims` (optional array)
11. `extensions` (optional object)

### B.1 trustclaims element order
Each trust claim object field order:
1. `claimtype`
2. `claimvalue`
3. `source`
4. `timestamputc`

### B.2 extensions order
- Extension keys are lowercased.
- Extension keys are written in lexicographic ordinal order.

## C. Receipt canonical object

Canonical field order for `HipTrustReceipt`:

1. `receiptid`
2. `hipversion`
3. `interactiontype`
4. `senderhipid`
5. `receiverhipid` (optional)
6. `timestamputc`
7. `messagehash`
8. `deviceid` (optional)
9. `checks` (array)
10. `decision`
11. `appliedpolicyids` (array)
12. `reputationsnapshot` (optional)

## D. Canonical examples

### D.1 Envelope canonical string

```json
{"hipversion":"1.0","messagetype":"ProtectedHttpRequest","senderhipid":"key-sender","receiverhipid":"receiver-a","timestamputc":"2026-03-06T20:00:00.0000000Z","nonce":"nonce-123","payloadhash":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","correlationid":"corr-123"}
```

### D.2 Receipt canonical string

```json
{"receiptid":"receipt-123","hipversion":"1.0","interactiontype":"ProtectedHttpRequest","senderhipid":"key-sender","timestamputc":"2026-03-06T20:00:00.0000000Z","messagehash":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","checks":["signature","nonce","timestamp"],"decision":"Allow","appliedpolicyids":["policy-1"],"reputationsnapshot":80}
```

## E. Verification conformance guidance

Implementations should verify against fixture vectors in:
- `HIP.Protocol.Tests/Conformance/conformance-vector-hmac.json`
- `HIP.Protocol.Tests/Conformance/conformance-vector-receipt-hmac.json`
- `HIP.Protocol.Tests/Conformance/conformance-vector-ed25519-rfc8032.json`

Any change to canonicalization rules requires a protocol compatibility review and vector refresh.
