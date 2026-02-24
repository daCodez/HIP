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
