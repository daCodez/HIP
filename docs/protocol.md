# HIP Protocol

HIP is an open trust protocol and product layer above TCP and TLS.

## Protocol Responsibilities

- identity verification
- origin verification
- signed content verification
- signed result verification
- reputation lookup
- risk scoring
- safety routing
- public lookup
- live trust badges

## Signing Direction

HIP should support signed websites, apps, files, images, emails, social posts, API responses, and downloads.

Quantum-resistant signing is required from day one. The initial implementation should model signature metadata separately from concrete cryptographic providers so production signing algorithms can be selected and audited deliberately.

## Website Verification

Initial verification methods:

- DNS TXT
- `.well-known/hip.json`

Future methods:

- HTML file upload
- meta tag
