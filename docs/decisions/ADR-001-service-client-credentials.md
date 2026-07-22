# ADR-001: Use owner-bound static service-client credentials

## Status

Accepted

## Date

2026-07-20

## Context

HIP needs a non-browser authentication boundary for integrations that cannot use
the human OIDC and Web-session flow. The boundary must preserve least privilege,
owner isolation, explicit expiry, rotation, terminal revocation, concurrency-safe
persistence, and non-disclosing failures. Credential verification is deliberately
expensive, so unauthenticated traffic must be bounded before key-derivation work.

A service credential proves possession of a shared bearer secret. It does not
prove that its operator or granted domains are safe, reputable, or trustworthy.
The design must keep that distinction explicit.

## Decision

HIP uses a versioned static credential with the wire form
`<clientId>.<secret>` and the authentication header
`Authorization: HIP-Service <clientId>.<secret>`.

- `clientId` is `hipc_v1_` plus canonical unpadded base64url for 16 random
  bytes. `secret` is `hips_v1_` plus canonical unpadded base64url for 32 random
  bytes.
- Each registration belongs to one server-derived, HMAC-scoped owner and has
  exactly one supported scope plus one to sixteen exact canonical domain grants.
- The supported scopes are `domain-verification:check` and
  `site-safety:external-evidence:check`. They cannot be combined or widened by
  wildcard or suffix matching.
- Creation, listing, rotation, and revocation are owner-bound. Only Owner and
  Admin roles may manage registrations; mutations require recent MFA-backed
  authentication and cookie antiforgery protection at the HTTP boundary.
- The raw secret is returned only by create or rotate. Normal responses and
  lists expose only public lifecycle metadata, and one-time responses are
  marked no-store.
- HIP persists only a client-bound PBKDF2-HMAC-SHA256 verifier using 600,000
  iterations, a random 16-byte salt, and a 32-byte derived key. The verifier is
  stored inside the encrypted aggregate.
- Rotation retains the client ID, owner, scope, domain grants, and original
  expiry while atomically replacing the verifier and invalidating the previous
  secret. Revocation is terminal. Both use aggregate-version compare-and-swap.
- Lifecycle transitions and their privacy-safe audit facts commit atomically.
- The standalone API host uses an exclusive scheme router. Any `Authorization`
  header selects `HIP-Service`; it never falls back to Web cookies or the
  Development administrator scheme. Authentication failures are stable `401`
  challenges, while an authenticated client with the wrong scope or resource
  receives `403`.
- Every apparent attempt consumes Redis-backed source-wide and
  source-plus-client budgets before lookup or PBKDF2. Unknown canonical client
  IDs still perform verification against one process-start dummy verifier to
  reduce existence and timing disclosure. Redis failure has no local fallback
  and fails closed.
- Authentication re-reads the registration after secret verification and
  accepts it only if its security-relevant state is unchanged.
- Privacy-HMAC rotation retains a bounded current-plus-legacy key ring. New
  registrations use the current owner partition; management merges exact
  ordinal pages across derived legacy partitions, while global client-ID
  bindings keep authentication independent of the current privacy key.
- List cursors disclose only the last client ID plus an owner-bound HMAC tag.
  They reveal no owner scope, reject tampering and cross-owner reuse, and may be
  invalidated deliberately when the current privacy key changes.
- Audit, logs, traces, and metrics exclude raw credentials, verifiers, domain
  lists, source addresses, authorization values, and raw owner identifiers.

## Alternatives Considered

### Reuse HIP Web session cookies

Rejected. Cookies represent human browser sessions, carry browser-specific CSRF
and redirect behavior, and would couple API integrations to the Web host. The
standalone API must not treat a Web session as a client credential.

### Use one broad API key or multi-scope registration

Rejected. A broad key increases compromise impact and weakens resource
authorization. One exact scope and exact domain grants make the authorized
operation explainable and independently revocable.

### Store reversible secrets or use a fast digest

Rejected. Reversible storage would make a database or key compromise disclose
usable credentials. A fast digest makes offline guessing unnecessarily cheap.
The selected client-bound PBKDF2 verifier raises offline cost while still
allowing server-side verification.

### Issue self-contained JWT access tokens

Rejected for this package. Self-contained tokens complicate immediate rotation
and terminal revocation and can preserve stale grants until expiry. The
authoritative registration read and post-verification re-read give HIP immediate
lifecycle enforcement.

### Require mutual TLS or signed requests immediately

Deferred. Those approaches can provide stronger sender constraint or replay
resistance but add certificate/key provisioning and client complexity beyond
HIP-0205. The versioned credential and scheme leave room for a future migration.
Static credentials remain replayable bearer material and must be protected and
rotated accordingly.

## Consequences

- Integrations receive a simple, explicit authentication contract independent
  of human sessions.
- Scope, exact-domain, owner, expiry, rotation, and revocation decisions remain
  authoritative server-side and take effect immediately.
- HIP cannot recover a lost raw secret. Operators must rotate the registration
  and securely distribute the replacement.
- Operators must retain each former privacy HMAC key until registrations in its
  owner partition are retired or no longer require management. At most eight
  configured former-key entries are accepted and exact repeats are deduplicated,
  bounding list fan-out.
- Redis is a required security dependency for shared pre-verification work
  limits. Loss of Redis availability denies service-client authentication
  rather than allowing unbounded PBKDF2 work.
- The KDF protects stored verifiers but does not stop replay of a stolen raw
  credential. HTTPS, secret-manager storage, short operational lifetimes,
  monitoring, rotation, and revocation remain required.
- A future sender-constrained or signed-request scheme will require a versioned
  migration rather than silently changing `HIP-Service` semantics.
