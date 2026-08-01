# Sandbox container isolation evidence — 2026-08-01

## Target and artifact

- Target: Hostinger private staging Docker 29.5.2 host
- Proof script: `eng/sandbox/verify-container-isolation.sh`
- Script SHA-256: `a8d410092e632f71b120bbeef8157b0f2060b35dfe40e7033983bf21c2459a32`
- Proof image: pinned Caddy 2.10 Alpine image at digest
  `sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d`

## Enforced and inspected controls

- Network mode: `none`
- Root filesystem: read-only
- Temporary filesystem: 16 MiB, writable, `noexec`, `nosuid`, `nodev`
- Linux capabilities: all dropped
- Privilege escalation: `no-new-privileges=true`
- Runtime user: `65532:65532`
- PID limit: 32
- CPU limit: 0.5
- Memory and memory-swap limits: 256 MiB
- Container log driver: none

The live fixture confirmed that writing to the root filesystem failed, executing
a file from `/tmp` failed, and an HTTPS network attempt failed. The exact
temporary container was removed and a post-run inventory confirmed no proof
container remained.

## Result and boundary

The target-platform container isolation controls for HIP-0902 pass. This does
not close HIP-0903: production browser execution remains disabled because HIP
does not yet have a pinned browser-runner image connected through a per-job
egress broker that can verify the browser's connected IP against the
pre-authorized DNS result. The secure behavior remains fail-closed rather than
granting a browser ambient Internet access.
