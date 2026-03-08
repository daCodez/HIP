# HIP Protocol v1 — HTTP Transport Mapping

HIP over HTTP/TLS in v1.

## Request headers
- HIP-Version
- HIP-MessageType
- HIP-Sender
- HIP-Receiver (optional)
- HIP-Timestamp (UTC)
- HIP-Nonce
- HIP-PayloadHash
- HIP-Signature
- HIP-CorrelationId
- HIP-Device (optional)

## Signed field set
Receiver verifies signature over canonical envelope payload containing required signed fields.

## Response/receipt mapping
- HIP-Receipt-Id
- HIP-Receipt-Signature
- Optional receipt object in response JSON

## Notes
- Header stripping/tampering detection relies on signed canonical content.
- Body-envelope mapping is allowed for non-header-friendly transports.
