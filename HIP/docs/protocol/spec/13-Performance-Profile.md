# HIP Protocol v1 — Performance Profile (Fast-by-default)

HIP verification must remain low-latency and predictable.

## Targets (reference implementation guidance)
- Envelope verify (no I/O): sub-millisecond typical on modern CPU
- Receipt verify (no I/O): sub-millisecond typical
- Replay lookup: O(1) expected in configured replay store

## Fast-path principles
1. Verify required fields once, early
2. Avoid re-parsing payload repeatedly
3. Canonicalize once per verify path
4. Use payload hash instead of payload duplication
5. Keep nonce store operations constant-time average
6. Keep key lookup O(1) average
7. Use fail-closed short-circuit on first hard failure
8. Do not perform blocking I/O in hot path when avoidable

## Deployment guidance
- Use in-memory replay store for single-node dev/test
- Use distributed cache for multi-node production
- Keep clock skew tight (default 300s; lower for trusted environments)
- Rotate keys proactively to reduce revocation burst risk

## Progressive adoption levels (performance-aware)
- Level 1: Verify if present (minimal overhead)
- Level 2: Require HIP on selected endpoints
- Level 3: Require HIP + policy decision checks
- Level 4: Require HIP + signed trust receipt on critical actions

## Observability metrics to track
- verification latency p50/p95/p99
- replay rejections per endpoint
- signature failure rate
- unsupported version rate
- receipt issuance latency

## Caution
Do not trade correctness for speed in cryptographic verification or replay checks.
