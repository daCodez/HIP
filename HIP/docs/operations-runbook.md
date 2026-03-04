# HIP Operations Runbook (Stable Baseline)

Use this for day-to-day ops on the stabilized setup.

## Services
- `hip-apphost.service` (user service): runs HIP AppHost + Aspire + HIP.ApiService + HIP.Web
- `hip-api-forward.service` (user service): forwards `127.0.0.1:5101` -> `127.0.0.1:44985`

## Stable Ports
- HIP API: `127.0.0.1:44985`
- HIP Web: `127.0.0.1:45727`
- API forward: `127.0.0.1:5101`
- Aspire dashboard: dynamic login URL in `~/.aspire/cli/logs/apphost-*.log`

## Common Commands
```bash
systemctl --user status hip-apphost.service --no-pager -n 20
systemctl --user restart hip-apphost.service

systemctl --user status hip-api-forward.service --no-pager -n 20
systemctl --user restart hip-api-forward.service
```

## Health Checks
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5101/health
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:44985/swagger/index.html
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:45727/
```

## If Something Breaks
1. Restart apphost:
   ```bash
   systemctl --user restart hip-apphost.service
   ```
2. Restart forwarder:
   ```bash
   systemctl --user restart hip-api-forward.service
   ```
3. Re-run smoke checks:
   ```bash
   ./scripts/smoke.sh
   ```
4. If still failing, inspect:
   ```bash
   systemctl --user status hip-apphost.service --no-pager -n 80
   systemctl --user status hip-api-forward.service --no-pager -n 40
   ```
