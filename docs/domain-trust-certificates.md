# HIP Domain Trust Certificates

A HIP Domain Trust Certificate is a signed, public record that a canonical domain completed a defined HIP verification policy. It does not replace the website's TLS certificate, and it is not a guarantee that the site or every page is safe.

HIP keeps three decisions separate:

- The HIP score describes current domain, page, and content risk evidence.
- The HIP Domain Trust Certificate records completed identity, control, and policy checks.
- The HIP badge displays the certificate's current level and lifecycle state together with the separate HIP risk score.

A high score does not issue a certificate. A valid signature proves HIP origin and document integrity; it does not establish safety or reputation by itself.

## Levels

- **HIP Registered** means HIP verified domain control. It makes no site-safety claim.
- **HIP Verified** requires DNS control, HTTPS website control, identity or organization details, an initial security review, no unresolved critical findings, and the versioned certificate policy to pass.
- **HIP Monitored** requires Verified conditions to remain satisfied, an active certificate, current monitoring evidence, the configured minimum score, and no unresolved critical findings.

The implemented policy identifier is `hip-domain-certificate-v1`. Policy values live in the strongly typed `DomainCertificatePolicy` model rather than UI or badge code.

## Owner enrollment

The owner portal is `/consumer/certificates`.

1. Add a public registrable domain. HIP canonicalizes case and international names, removes URL components, and rejects IP, localhost, private/internal, malformed, and public-suffix-only values.
2. Publish the generated TXT record at `_hip.<domain>`. The challenge is single-use, expires, has a bounded attempt count, and is stored as a digest rather than plaintext.
3. Ask HIP to check DNS. Successful ownership verification is persisted with an audit event.
4. Publish the exact HTTPS control document at `https://<domain>/.well-known/hip.json` when the website-verification step is requested. HIP does not fetch arbitrary owner-supplied paths.
5. Complete the permitted public identity fields. Private contacts, internal notes, raw scans, provider payloads, and challenge values do not belong in the public certificate.
6. Submit the application from the authenticated owner account. HIP binds the fixed authority and accuracy declarations to the enrollment, verified domain, selected identity fields, policy version, and a SHA-256 attestation digest.
7. An authorized HIP reviewer approves, requests changes, or denies the application with a required privacy-safe reason. The reviewer identity, decision, attestation digest, and timestamp are permanently audited.
8. Only an approved application may run the server-owned security review. When the evidence is eligible, HIP signs, self-verifies, and atomically stores the certificate and issuance event. Review-required and ineligible decisions remain non-issued.

The HTTPS fetcher uses HTTPS only, bounded redirects, safe ports, response limits, strict timeouts, registrable-domain redirect checks, and address validation before and after connection to resist SSRF and DNS rebinding.

## Monitoring and score progression

After an active Verified certificate exists, the authenticated owner can opt in to continuous monitoring. HIP immediately runs a server-owned scan of the fixed HTTPS origin and, when storage or evidence providers are temporarily unavailable, records bounded retry state without publishing a monitoring claim. The background coordinator checks due enrollments hourly; each successful domain check schedules the next check 24 hours later. Failures use bounded exponential backoff up to 24 hours.

Completed account, DNS, website-control, and identity checks provide authenticated non-safety trust context to the existing scoring pipeline. That context removes the missing-trust-data cap; it does not add a safety claim, suppress a negative finding, or offset malware, phishing, TLS, redirect, download, script, or policy risk. HIP persists the server-produced domain, page, content-safety, and final score components together and rejects incomplete, out-of-range, or internally inconsistent score metadata during public projection.

The V1 Monitored level requires a current active certificate, monitoring enabled, evidence no older than seven days, a current score of at least 70, and no unresolved critical findings. A successful immediate or scheduled check updates the owner dashboard, public evidence confidence, and browser popup. The public numeric score remains withheld when authenticated evidence coverage is insufficient; identity status remains independently visible.

## Lifecycle and operations

Certificate states are Draft, PendingVerification, PendingReview, Active, Suspended, Revoked, Expired, and RenewalRequired. Enrollment states are distinct and follow their own explicit transition rules.

- Suspension is reversible and requires a privacy-safe reason.
- Reinstatement is permitted only from Suspended and is audited.
- Revocation is permanent in the current lifecycle and requires a reason plus recent privileged authentication.
- Expiry is derived from the signed expiry even if an older stored row still says Active.
- Renewal must recheck domain control, HTTPS control, identity, current policy, critical findings, signing configuration, and monitoring freshness. Automatic renewal is not wired in the current owner workflow; operators must not promise it until the renewal coordinator and reminders are implemented.

Certificate and event history is not hard-deleted. Production backup, export, and formal retention durations remain an operations decision; until then, certificate events are treated as permanent audit evidence. Public responses contain only the signed public fields and lifecycle status.

Administrators use `/admin/certificates`. Suspend, reinstate, and revoke actions are policy-authorized, concurrency-safe, require reasons, and produce permanent lifecycle events. Certificate metrics on `/admin` come from persisted current enrollment/certificate projections; unavailable reads display as unavailable, not zero.

## Public verification

- Human page: `/certificate/{certificateId}`
- Machine-readable certificate: `GET /api/v1/public/certificates/{certificateId}`
- Domain-bound badge data: `GET /api/v1/public/badge/domain/{domain}`
- Badge signature verification: `POST /api/v1/public/badge/verify`

The public certificate service re-verifies the stored signature against current authoritative key state on every projection. It reports signature status, effective lifecycle status, validity, and `isActive` separately. Missing, unverifiable, suspended, revoked, and expired records fail closed.

Public routes are rate limited. Active responses may be cached briefly; non-active or unverifiable responses use conservative cache behavior. Clients must recheck current state and must not treat an old local badge as active evidence.

## Badge installation

Use the exact canonical hostname shown in the owner portal:

```html
<div data-hip-badge="example.com"></div>
<script
  src="https://hip.example.com/api/v1/badge/example.com/script"
  async>
</script>
```

The generated script compares the current page hostname with the requested certificate domain, retrieves live HIP data, checks the short-lived signed badge document, binds every displayed certificate field to the signed payload, and calls HIP's verification endpoint. It displays certificate level/state separately from risk score, links to the public certificate, supports dark color schemes, respects reduced motion, and renders an unavailable or mismatch state on failure.

The shared `/hip-badge.js` alternative supports `.hip-trust-badge` elements and an explicit `data-api-base` for local development. Prefer the generated domain-specific script for normal installation.

A screenshot or copied visual can always imitate a badge. Copied markup cannot create a valid HIP certificate claim because the live response must be signed, current, and bound to the page's exact hostname. Do not hide the verified domain, lifecycle state, or separate risk score.

Recommended Content Security Policy directives should allow scripts and connections only to the operator's selected HIP origin, for example:

```text
script-src 'self' https://hip.example.com; connect-src 'self' https://hip.example.com
```

HIP badge requests contain the requested public domain only. The badge does not send page text, form values, visitor identifiers, cookies, or browsing history to HIP.

## Browser extension verification

The browser extension never trusts page-controlled badge markup as proof. It:

1. retrieves the domain badge directly from HIP;
2. submits the short-lived signed badge document to HIP's verification endpoint;
3. compares the certificate presentation fields with the signed badge payload;
4. retrieves the referenced public certificate directly from HIP;
5. confirms certificate ID, exact domain, level, state, signature status, expiry, public URL, and active flag; and
6. displays certificate state separately from the HIP risk score.

This is server-authoritative online verification, not offline cryptographic verification inside the extension. The existing automatic Site Safety scan remains independent.

## Signing and key rotation

Certificate payloads use deterministic RFC 8785 canonicalization. The signer boundary exposes public authority/key/algorithm metadata and a hash-signing operation; private key material must remain in managed custody and never enter the database, API, logs, or certificate document. Issuance verifies the resulting signature before persistence and uses a fail-closed authority/key allowlist.

The default application registration uses an unavailable managed signer and an empty certificate-authority allowlist. A deployment must replace both with an approved managed signer, register its public key in authoritative key lifecycle storage, and explicitly authorize the authority/key pair. Without those steps, issuance and live signed badges remain unavailable by design.

Key rotation adds a new managed key and public lifecycle record before authorization, switches issuance only after verification succeeds, retains old public keys while certificates remain verifiable, and revokes a compromised key through the existing key lifecycle. Rotation must never copy private material into application configuration.

The provider model supports ML-DSA-65 verification and an explicitly configured SoftHSM PKCS #11 starter signer. This provides post-quantum algorithm interoperability, but SoftHSM remains software-backed custody on the application host and is not quantum-resistant by itself. HIP does not describe that deployment as a hardware HSM, independently managed custody, or an audited production trust root. Those stronger claims require an audited provider, managed key custody integration, interoperability evidence, and deployment evidence.

## Development with .NET Aspire

From the repository root:

```powershell
dotnet run --project src/HIP.AppHost/HIP.AppHost.csproj
```

Aspire orchestrates the HIP hosts and PostgreSQL resources configured by `HIP.AppHost`. Use the dashboard-provided endpoints rather than assuming fixed ports. Development authentication and local origins remain Development-only controls.

A successful Aspire start proves orchestration and health wiring, not production signer readiness. To exercise issuance, configure an approved development-only managed signer and matching authoritative public key/allowlist through the host's composition root or secret-backed provider. Never commit private keys or challenge values.

## Current implementation boundary

The repository has enrollment, DNS and HTTPS verification services, policy evaluation, signed issuance/persistence abstractions, public verification, owner/admin/public pages, audited suspend/reinstate/revoke controls, owner opt-in and recurring authenticated monitoring, certificate-bound live badges, extension verification, and real dashboard projections.

Still required before a production launch: an audited managed signer deployment, authorized key bootstrap/rotation runbook, owner-facing renewal coordinator and reminders, broader end-to-end browser/UI automation, production retention/export decisions, and environment-specific load/monitoring evidence. These gaps do not justify weakening the fail-closed behavior or making unsupported compliance or quantum-resistance claims.
