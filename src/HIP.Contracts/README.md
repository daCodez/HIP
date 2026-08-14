# HIP.Contracts

`HIP.Contracts` contains dependency-free public data contracts that HIP can
share without exposing proprietary scoring, detection, entitlement, or
certificate-issuance logic.

This component is licensed under Apache License 2.0. That license applies only
to the contents of `HIP.Contracts`; it does not apply to the rest of the HIP
repository, hosted services, clients, badge artwork, or brand assets. The
component has not yet been published to a package registry.

The candidate NuGet identity is `HumanInteractiveProtocol.Contracts` version
`0.1.0`. Packaging remains disabled unless the explicit
`HipContractsLicenseApproved=true` build property is supplied. See
`PUBLIC-API.md` for the reviewed compatibility surface and `TRADEMARKS.md` for
the separate brand boundary.

Public contracts may describe stored results and evidence already approved for
disclosure. Implementations that calculate scores, select providers, apply
private thresholds, or issue certificates must remain outside this assembly.

The plugin SDK surface is limited to privacy-safe manifests, runtime status,
feature metadata, and provider declaration interfaces. HIP retains control of
plugin discovery, validation, configuration, secrets, plan evaluation, billing,
provider selection, scoring, evidence collection, and certificate issuance.

The DNS provider surface supports only bounded public A and AAAA lookups, public answers, and resolver-reported
DNSSEC validation state. HIP-aware trust enrichment, wire parsing, caching, rate limiting, resolver configuration,
authoritative DNS management, query history, scoring, and provider selection remain outside this assembly.

The browser surface contains privacy-safe score and link-classification request and response shapes plus stable public
evidence-presentation values. URL validation, scoring, evidence interpretation, safety routing, persistence, provenance,
submission authorization, and browser service implementations remain outside this assembly.

The device surface contains bounded registration inputs, the server-issued canonical challenge, the public-safe
registered-device projection, its cryptographic assurance state, and the version-one registered-device request-proof
wire recipe. It accepts public verification material but never private keys. Challenge construction, proof acceptance,
timestamp tolerance, device lookup, signature verification, replay-state storage, registration limits, owner binding,
persistence, authorization, revocation commands, and audit transitions remain outside this assembly.

The protocol surface exposes verification-only signature capabilities and
public-key fingerprinting. It deliberately excludes private-key inputs,
signing operations, provider factories, runtime allowlists, managed-key
lifecycle, certificate issuance, and hosted identity policy.

Signed-document callers can submit dependency-free protocol metadata and
interpret fail-closed verification outcomes. HIP's adapter retains control of
authoritative identity lookup, managed public-key history, canonicalization,
provider selection, replay policy, and all hosted verification state.

The public wire-envelope surface preserves HIP's version-one JSON property
names, protocol-text enum values, strict parsing, and bounded payload rules.
It exposes only interchange data and serialization. Domain validation,
canonical signing-payload construction, replay decisions, signing authority,
provider selection, and reputation interpretation remain outside this assembly.

The shared protocol vocabulary includes content type, identity subject type,
verification method, verification status, public risk status, device platform and revocation status,
report platform, source client, privacy-safe report intent, observed DNSSEC status, and public certificate level and status. These enums
retain their existing `HIP.Domain` CLR namespaces and numeric values for source
and wire compatibility. The rest of `HIP.Domain`, including mappings,
aggregates, lifecycle state, scoring, and operational policy, is not licensed
or distributed by this package.
