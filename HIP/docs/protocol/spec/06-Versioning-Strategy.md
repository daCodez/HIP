# HIP Protocol v1 — Versioning Strategy

- Protocol version string: `1.0`
- Receiver keeps supported-version allowlist
- Unsupported major/minor -> UnsupportedVersion
- Optional extensions allowed if unknown-extension policy permits
- Mandatory fields remain stable for v1

## Compatibility rules
- Additive optional fields are forward-compatible
- Removing/changing semantics of signed required fields requires major version bump
