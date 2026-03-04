# HIP UI Stack Policy

Status: active

## Primary UI System
- TabBlazor (Tabler-based) is the primary Admin UI framework.

## Notes
- `HIP.Admin` has been migrated to the TabBlazor server starter structure.
- `/admin` remains served through YARP front door (`:8443/admin`).
- Keep styling/components within TabBlazor conventions to avoid multi-framework conflicts.

## Guardrails
- Prefer incremental, reversible changes.
- Backup before UI stack changes.
- Validate `/admin` rendering after each step.
