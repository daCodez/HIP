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
