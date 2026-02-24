# HIP

## Dev: verify crypto config wiring

With `HIP.ApiService` running in **Development**, use this to confirm key-path resolution and file discovery:

```bash
curl -s "http://127.0.0.1:5101/api/admin/crypto-config?keyId=hip-system" | jq
```

Expected important fields in response:

- `provider` should be `ECDsa`
- `privateKeyStorePath` / `publicKeyStorePath` should match your configured directories
- `privateKeyPath` should resolve to `<privateKeyStorePath>/hip-system.key`
- `publicKeyPath` should resolve to `<publicKeyStorePath>/hip-system.pub`
- `privateKeyExists` and `publicKeyExists` should both be `true`

> Note: `/api/admin/crypto-config` is mapped only in Development.

## Dev: sign/verify with a rotated key id

You can sign as `from=hip-system` while using versioned key files (e.g. `hip-system-v2.key/.pub`) via `keyId`.

```bash
SIGNED=$(curl -s -X POST http://127.0.0.1:5101/api/messages/sign \
  -H "Content-Type: application/json" \
  -d '{"from":"hip-system","to":"target","body":"hello","keyId":"hip-system-v2"}')

echo "$SIGNED" | jq

echo "$SIGNED" | jq -c '.message' | \
  curl -s -X POST http://127.0.0.1:5101/api/messages/verify \
    -H "Content-Type: application/json" \
    -d @- | jq
```

## Dev: Aspire multi-node smoke profile

Run HIP with two API replicas:

```bash
cd /home/jarvis_bot/.openclaw/workspace/HIP
HIP_API_REPLICAS=2 dotnet run --project HIP.AppHost
```

Quick smoke checks:

```bash
# service health through web/dashboard flow
curl -s http://100.67.76.107:5102 > /dev/null

# API endpoint still healthy under replicated apphost
curl -s http://100.67.76.107:5101/api/status | jq
```

Notes:
- `HIP_API_REPLICAS=1` (default) = single-node profile
- `HIP_API_REPLICAS=2`+ = multi-node `hip-api` behind Aspire service discovery

## Jarvis integration: identity + trust endpoints

### Get trust context for an agent identity

```bash
curl -s http://127.0.0.1:5101/api/jarvis/context/hip-system | jq
```

Response includes:
- `identityExists`
- `reputationScore`
- `trustLevel` (`low|medium|high`)
- `canUseSensitiveTools`
- `memoryRoute` (`trusted|constrained`)

### Evaluate tool access by risk tier

```bash
curl -s -X POST http://127.0.0.1:5101/api/jarvis/tool-access \
  -H "Content-Type: application/json" \
  -d '{"identityId":"hip-system","toolName":"nodes.camera_snap","riskLevel":"high"}' | jq
```

Risk thresholds:
- `low` >= 20
- `medium` >= 50
- `high` >= 80

### Evaluate prompt-injection policy + trust bound execution

```bash
curl -s -X POST http://127.0.0.1:5101/api/jarvis/policy/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "identityId":"hip-system",
    "userText":"Check status and summarize health",
    "contextNote":"jarvis-runtime",
    "toolName":"status",
    "riskLevel":"low"
  }' | jq
```

Output fields:
- `decision` (`allow|review|block`)
- `risk` (`low|medium|high`)
- `reasons[]`
- `sanitizedText`
- `toolAccessAllowed`
- `toolAccessReason`

### Retry / replay guidance for clients

To avoid false-positive replay/stale failures:
- use unique message IDs per signed request
- if a request times out, retry with a **new** message ID and new signature
- keep sender clocks NTP-synced (freshness window is short)
- avoid delayed queue replay beyond freshness TTL

Server behavior:
- repeated message IDs -> `replay_detected`
- stale/future timestamps -> `message_expired`

### Jarvis token lifecycle (access + refresh)

Issue token pair:

```bash
curl -s -X POST http://127.0.0.1:5101/api/jarvis/token/issue \
  -H "Content-Type: application/json" \
  -d '{"identityId":"hip-system"}' | jq
```

Validate access token:

```bash
curl -s -X POST http://127.0.0.1:5101/api/jarvis/token/validate \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"atk_..."}' | jq
```

Refresh token pair:

```bash
curl -s -X POST http://127.0.0.1:5101/api/jarvis/token/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"rtk_..."}' | jq
```

### Runtime hook wiring (Jarvis pre-dispatch)

A workspace hook is included at:

- `hooks/hip-trust-guard/HOOK.md`
- `hooks/hip-trust-guard/handler.ts`

Enable and restart gateway:

```bash
openclaw hooks enable hip-trust-guard
openclaw gateway restart
```

Optional env vars for hook runtime:
- `HIP_API_BASE` (default `http://127.0.0.1:5101`)
- `HIP_IDENTITY_DEFAULT` (default `hip-system`)
- `HIP_GUARD_VERBOSE=1` for allow/review notices

