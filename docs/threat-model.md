# HIP Threat Model (Draft)

## Assets
- Agent identity bindings
- Reputation state and trust decisions
- Signed message envelopes
- Token pairs (access/refresh)

## Primary Threats
1. Prompt-injection and policy override attempts
2. Secret-exfiltration requests
3. Replay of valid signed messages
4. Delayed/stale message reuse
5. Tool abuse from low-trust identities

## Current Controls
- Policy evaluation endpoint with allow/review/block
- Pre-dispatch trust guard hook
- Signed-message verification (ECDSA)
- Replay cache (message ID one-time consume)
- Timestamp freshness checks
- Risk-tier tool access gating by reputation
- Security counters and admin visibility

## Residual Risks
- In-memory replay cache resets on process restart
- In-memory token store not shared across nodes
- Pattern-based injection detector may miss novel payloads

## Next Hardening Steps
- Persist replay nonce history in shared store (Redis/DB)
- Replace opaque in-memory tokens with signed JWT + key rotation
- Add stricter protocol schema for tool intents
- Add anomaly alerts on security counter spikes
