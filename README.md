# HIP

**Human Identity Protocol (HIP)**

**Trust infrastructure for internet actions.**
**Value in one line:** HIP helps prevent unsafe actions by verifying identity, scoring trust, and enforcing clear policy decisions before execution.

HIP is an overlay trust layer that sits on top of existing protocols (like HTTP/HTTPS), so systems can add trust controls without replacing core transport.

HIP helps systems answer three critical questions before execution:
**Who sent this? Can I trust it? Should this be allowed?**

## TL;DR

HIP adds a practical trust layer with:
- signed identity verification
- reputation + trust context
- policy decisions (`allow` / `review` / `block`)
- token/proof flows for safer runtime actions

Start here: **[Quick start (5 minutes)](#quick-start-5-minutes)**.

---

## Core pillars

1. **Identity assurance**  
   Verify who is actually making requests (signatures + identity context).

2. **Trust + reputation intelligence**  
   Score trust signals over time, including recipient/user feedback.

3. **Policy-based decisioning**  
   Enforce `allow / review / block` with explainable, auditable rules.

4. **Abuse resistance**  
   Reduce spam, flooding, replay, and oversized payload abuse.

5. **Adaptive defense (human + AI)**  
   Improve over time with participatory feedback and AI-assisted risk signals.

---

## Who this is for

- **Non-technical readers:** a clear view of how HIP adds trust and guardrails.
- **Technical evaluators:** APIs for identity, reputation, policy, signatures, and token lifecycle.
- **Contributors/builders:** local run/test flow plus .NET SDK integration.

---

## Why HIP was developed

Modern systems can perform powerful actions, but trust checks are often inconsistent or added too late.

HIP makes trust and safety first-class, especially in agent-style workflows where mistakes are costly.

It helps teams:
- verify who is making a request
- make safer allow/review/block decisions
- reduce abuse and accidental misuse
- centralize trust logic instead of duplicating it across apps

### Common problems HIP is designed to solve

- **Unverified requests**: Systems trust input without strong proof of sender identity.
- **Inconsistent trust decisions**: Different services apply different (or no) risk checks.
- **Unsafe tool execution**: Sensitive actions are triggered without enough policy gating.
- **Replay/stale message risks**: Old or duplicated signed messages can be reused maliciously.
- **Abuse/flood pressure**: APIs are exposed to accidental spikes or deliberate request floods.
- **Scattered safety logic**: Teams duplicate auth/trust checks across services, causing drift.

### Threats HIP helps reduce

HIP is not a magic shield, but it materially lowers risk for:
- **Spam and automated abuse** (rate limits + identity checks + policy gates)
- **DDoS-style flooding** (throttling + payload controls)
- **Phishing-style impersonation** (signature/identity verification)
- **Deepfake-driven social engineering** (trust checks before sensitive actions)

HIP helps systems trust **proof and policy**, not just convincing-looking input.
It raises the cost of malicious behavior and improves detection.

It also supports participatory defense: recipients can rate messages (legitimate/suspicious/malicious), and that feedback can improve reputation signals over time.

### Real-world example

A support agent can trigger actions like:
- viewing sensitive customer data
- issuing account recovery links
- performing high-risk admin operations

Without HIP, those actions might run if a request simply *looks* valid.
With HIP in front, the system can require identity proof, evaluate trust score/risk level, and return:
- `allow` for routine low-risk actions
- `review` when context looks suspicious
- `block` when policy or trust thresholds fail

Result: fewer unsafe actions, clearer decision trails, and more confidence in automation.

---

## How HIP works (simple)

1. A client sends a signed message or authenticated request.
2. HIP validates identity + cryptographic proof.
3. HIP evaluates trust/reputation + risk policy.
4. HIP returns a decision (`allow`, `review`, `block`) and structured reason data.

---

## Quick start (5 minutes)

From the project root:

```bash
cd /home/jarvis_bot/.openclaw/workspace/HIP
```

### 1) Start the API

```bash
dotnet run --project HIP.ApiService
```

### 2) Check health/status

```bash
curl -s http://127.0.0.1:5101/api/status | jq
```

### 3) Try trust context

```bash
curl -s http://127.0.0.1:5101/api/jarvis/context/hip-system | jq
```

---

## Plugin architecture foundation (new)

HIP now includes a plugin foundation for future modular extension:
- shared contracts in `HIP.Plugins.Abstractions`
- plugin manifest model (`id`, `version`, `capabilities`)
- runtime registry (`IHipPluginRegistry`) wired into startup and endpoint mapping

Current state: foundation is enabled, with core plugins loaded by default:
- `core.audit.database`
- `core.policy.default`

No external plugins are loaded by default.

Optional built-in policy pack:
- Enable `core.policy.strict` in `HIP:Plugins:Enabled` to raise policy thresholds (low=60, medium=90, high=95).

Optional reputation feedback plugin:
- Enable `core.reputation.feedback` in `HIP:Plugins:Enabled`.
- Submit feedback: `POST /api/plugins/reputation/feedback`
- View 24h stats: `GET /api/plugins/reputation/feedback/stats`

Optional OIDC identity plugin:
- Enable `core.identity.oidc` in `HIP:Plugins:Enabled`.
- Resolve mapping: `POST /api/plugins/identity/oidc/resolve`
- Sync mapping: `POST /api/plugins/identity/oidc/sync`
- Plugin info: `GET /api/plugins/identity/oidc/info`

Enable plugins via config:

```json
{
  "HIP": {
    "Plugins": {
      "Enabled": ["sample"],
      "AutoDiscover": true,
      "Allowlist": ["sample"],
      "Directory": "plugins"
    }
  }
}
```

Notes:
- `Enabled` explicitly enables known plugin IDs.
- `AutoDiscover=true` scans loaded assemblies and optional plugin directory.
- `Allowlist` constrains which discovered plugins can load.

Discovery endpoint:
- `GET /api/plugins` returns active plugin manifests.
- `GET /api/plugins/nav` returns plugin-contributed navigation items.
- `GET /api/plugins/policy/current` returns current default policy-pack thresholds.

Policy tuning config (default policy plugin):
- `HIP:Policy:LowRiskRequiredScore` (default 20)
- `HIP:Policy:MediumRiskRequiredScore` (default 50)
- `HIP:Policy:HighRiskRequiredScore` (default 80)

---

## Roadmap: AI-assisted trust

As HIP evolves, AI can be added as a decision-support layer (not a black-box replacement for policy).

Planned direction:
- **Anomaly detection**: flag unusual behavior patterns (velocity spikes, unusual request shapes, identity drift).
- **Phishing/deepfake risk signals**: add model-assisted confidence signals for suspicious content/workflows.
- **Human-in-the-loop thresholds**: route borderline/high-impact cases to review instead of auto-allow.

Design principle: AI can inform decisions, but final enforcement remains policy-driven, explainable, and auditable.

---

## SDK (for .NET apps)

A starter client library exists at `HIP.Sdk/`.

- SDK docs: `HIP.Sdk/README.md`
- Supported calls:
  - `GetStatusAsync()`
  - `GetIdentityAsync(id)`
  - `GetReputationAsync(identityId)`
  - `GetAuditEventsAsync(query, identityId)` (admin/privileged)

Example:

```csharp
using HIP.Sdk;

builder.Services.AddHipSdkClient(o => o.BaseUrl = "http://127.0.0.1:5101");

var client = app.Services.GetRequiredService<IHipSdkClient>();
var status = await client.GetStatusAsync();
```

SDK demo:

```bash
cd /home/jarvis_bot/.openclaw/workspace/HIP
# Terminal A
dotnet run --project HIP.ApiService

# Terminal B
dotnet run --project HIP.Sdk.Demo -- http://127.0.0.1:5101 hip-system
```

---

## Internal endpoint exposure (important)

Some endpoints are internal/privileged integration surfaces (for example Jarvis/admin routes).

Exposure control:
- `HIP:ExposeInternalApis=true|false`
- Default behavior: enabled in Development, disabled outside Development unless explicitly turned on.

This keeps the public API surface clean while preserving internal tooling for trusted environments.

---

## API behavior and safety limits (plain English)

### Too many requests (`429`)
If a client sends requests too quickly, HIP throttles traffic.

Example response:

```json
{
  "code": "rateLimit.exceeded",
  "reason": "too many requests",
  "retryAfterSeconds": 12
}
```

If `retryAfterSeconds` is present, wait that long before retrying.

### Request body too large (`413`)
HIP enforces payload size limits globally, and stricter limits on some write endpoints.

Example response:

```json
{
  "code": "payload.tooLarge",
  "reason": "request payload exceeds configured endpoint limit"
}
```

---

## Developer reference

Everything below is more technical and intended for implementation/testing.

### Dev: verify crypto config wiring

With `HIP.ApiService` running in **Development**, confirm key-path resolution and file discovery:

```bash
curl -s "http://127.0.0.1:5101/api/admin/crypto-config?keyId=hip-system" | jq
```

Expected key fields:
- `provider` should be `ECDsa`
- `privateKeyStorePath` / `publicKeyStorePath` should match configured directories
- `privateKeyPath` should resolve to `<privateKeyStorePath>/hip-system.key`
- `publicKeyPath` should resolve to `<publicKeyStorePath>/hip-system.pub`
- `privateKeyExists` and `publicKeyExists` should both be `true`

> `/api/admin/crypto-config` is mapped only in Development.

### Dev: sign/verify with a rotated key id

You can sign as `from=hip-system` while using versioned key files (for example `hip-system-v2.key/.pub`) via `keyId`.

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

### Dev: Aspire multi-node smoke profile

Run HIP with two API replicas:

```bash
cd /home/jarvis_bot/.openclaw/workspace/HIP
HIP_API_REPLICAS=2 dotnet run --project HIP.AppHost
```

Smoke checks:

```bash
# service health through web/dashboard flow
curl -s http://100.67.76.107:5102 > /dev/null

# API endpoint healthy under replicated apphost
curl -s http://100.67.76.107:5101/api/status | jq
```

Notes:
- `HIP_API_REPLICAS=1` (default) = single-node profile
- `HIP_API_REPLICAS=2`+ = multi-node `hip-api` behind Aspire service discovery

### Jarvis integration: identity + trust endpoints

#### Get trust context for an agent identity

```bash
curl -s http://127.0.0.1:5101/api/jarvis/context/hip-system | jq
```

Response includes:
- `identityExists`
- `reputationScore`
- `trustLevel` (`low|medium|high`)
- `canUseSensitiveTools`
- `memoryRoute` (`trusted|constrained`)

#### Evaluate tool access by risk tier

```bash
curl -s -X POST http://127.0.0.1:5101/api/jarvis/tool-access \
  -H "Content-Type: application/json" \
  -d '{"identityId":"hip-system","toolName":"nodes.camera_snap","riskLevel":"high"}' | jq
```

Risk thresholds:
- `low` >= 20
- `medium` >= 50
- `high` >= 80

#### Evaluate prompt-injection policy + trust-bound execution

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

### Quick copy/paste checks

```bash
# 429 check: send many identity lookups quickly
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:5101/api/identity/test-$i"
done
```

```bash
# 413 check: send an oversized message body
python3 - <<'PY' | curl -s -X POST http://127.0.0.1:5101/api/messages/sign \
  -H "Content-Type: application/json" -d @- | jq
import json
print(json.dumps({"from":"a","to":"b","body":"x"*(150*1024)}))
PY
```

### Retry / replay guidance for clients

To avoid false replay/stale failures:
- use unique message IDs per signed request
- if a request times out, retry with a **new** message ID and new signature
- keep sender clocks NTP-synced (freshness window is short)
- avoid delayed queue replay beyond freshness TTL

Server behavior:
- repeated message IDs -> `replay_detected`
- stale/future timestamps -> `message_expired`

### Jarvis token lifecycle (access + refresh)

Token binding fields:
- `identityId`
- `audience`
- `deviceId` (optional but recommended)
- `keyId` + `keyVersion` (for soft revoke via rotation)

Issue token pair:

```bash
curl -s -X POST http://127.0.0.1:5101/api/jarvis/token/issue \
  -H "Content-Type: application/json" \
  -d '{"identityId":"hip-system","audience":"jarvis-runtime","deviceId":"device-1"}' | jq
```

Validate access token:

```bash
curl -s -X POST http://127.0.0.1:5101/api/jarvis/token/validate \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"v1...","audience":"jarvis-runtime","deviceId":"device-1"}' | jq
```

Refresh token pair:

```bash
curl -s -X POST http://127.0.0.1:5101/api/jarvis/token/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"rtk_..."}' | jq
```

Fast revoke session/token:

```bash
curl -s -X POST http://127.0.0.1:5101/api/jarvis/token/revoke \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"atk_...","refreshToken":"rtk_..."}' | jq
```

Or revoke all active tokens for an identity:

```bash
curl -s -X POST http://127.0.0.1:5101/api/jarvis/token/revoke \
  -H "Content-Type: application/json" \
  -d '{"identityId":"hip-system"}' | jq
```

### One-time proof token for sensitive actions

Issue proof token:

```bash
curl -s -X POST http://127.0.0.1:5101/api/jarvis/proof/issue \
  -H "Content-Type: application/json" \
  -d '{"identityId":"hip-system","audience":"jarvis-runtime","deviceId":"device-1","action":"tool:camera","ttlSeconds":60}' | jq
```

Consume proof token once:

```bash
curl -s -X POST http://127.0.0.1:5101/api/jarvis/proof/consume \
  -H "Content-Type: application/json" \
  -d '{"proofToken":"v1...","expectedAction":"tool:camera","audience":"jarvis-runtime","deviceId":"device-1"}' | jq
```

Note: key rotation policy supports emergency soft revoke by bumping minimum accepted key version.

### Runtime hook wiring (Jarvis pre-dispatch)

Workspace hook:
- `hooks/hip-trust-guard/HOOK.md`
- `hooks/hip-trust-guard/handler.ts`

Enable and restart gateway:

```bash
openclaw hooks enable hip-trust-guard
openclaw gateway restart
```

Optional runtime env vars:
- `HIP_API_BASE` (default `http://127.0.0.1:5101`)
- `HIP_IDENTITY_DEFAULT` (default `hip-system`)
- `HIP_GUARD_VERBOSE=1` for allow/review notices
