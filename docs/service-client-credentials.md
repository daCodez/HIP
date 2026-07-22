# HIP Service-Client Credentials

HIP-0205 provides owner-bound credentials for non-browser integrations calling
the standalone `HIP.ApiService` host. These credentials are distinct from HIP
Web sessions and consumer device keys. A successful credential check authorizes
one operation against explicitly granted domains; it does not establish that a
client, operator, domain, or result is safe, reputable, or trustworthy.

## Credential Format

The one-time credential returned at creation or rotation has two opaque,
case-sensitive parts:

```text
<clientId>.<secret>
```

- Client IDs use `hipc_v1_` followed by the canonical unpadded base64url
  encoding of 16 random bytes.
- Secrets use `hips_v1_` followed by the canonical unpadded base64url encoding
  of 32 random bytes.

Send the complete value in the standard authorization header. The
authentication-scheme token follows HTTP's case-insensitive scheme syntax, but
HIP emits and documents the canonical `HIP-Service` spelling and treats both
credential portions as case-sensitive:

```http
Authorization: HIP-Service <clientId>.<secret>
```

Do not put a credential in a URL, query string, log message, error report, or
client-side analytics event. Use HTTPS for every request. `HIP-Service` is a
static bearer credential: anyone who obtains it can replay it until it expires,
is rotated, or is revoked. PBKDF2 protects the verifier at rest; it cannot make
a stolen raw bearer credential safe.

## Least-Privilege Grants

A registration contains exactly one supported scope and between one and sixteen
unique canonical domain grants. Scope names and domain matching are ordinal and
case-sensitive after the request domain has been normalized. Wildcards, suffix
matching, multiple scopes, and unknown scopes are rejected.

| Exact scope | Authorized operation |
|---|---|
| `domain-verification:check` | Check domain-control evidence for an exact granted domain. |
| `site-safety:external-evidence:check` | Request the external-evidence check for an exact granted domain. |

Domain control and external evidence remain inputs to HIP. Neither a domain
grant nor successful domain verification is a safety or trust verdict.

The standalone API exposes both scoped operations:

- `POST /api/v1/domain-verification/check` requires
  `domain-verification:check` and a grant matching the normalized request domain
  before DNS work begins.
- `POST /api/v1/site-safety/external-evidence/check` requires
  `site-safety:external-evidence:check` and a grant matching the normalized
  request URL domain before provider settings are loaded or evidence collection
  begins.

Existing privileged administrator access remains compatible with the separate
administrator semantics for each operation.

## Standalone API Authentication Boundary

`HIP.ApiService` routes authentication by request shape:

- Any request containing an `Authorization` header is pinned to the
  `HIP-Service` scheme. It cannot fall back to Development headers, another
  scheme, or a HIP Web cookie.
- A request without `Authorization` can use the loopback-only Development
  administrator scheme only when the host is running in `Development`.
- Outside Development there is no header or cookie fallback. `X-HIP-Admin-Role`,
  `X-HIP-Admin-User`, Web session cookies, and ad hoc API-key headers are not
  service-client credentials.

Missing, malformed, unknown, incorrect, expired, revoked, rotated, or
temporarily unverifiable credentials receive the same non-disclosing `401`
challenge with `WWW-Authenticate: HIP-Service`. A valid credential that lacks
the required exact scope or domain grant receives `403`. Authentication and
authorization responses never redirect to a browser login page.

Before accepting a credential, the handler:

1. strictly bounds and parses the version-one wire format;
2. reserves a distributed pre-verification work budget;
3. performs the same deliberately slow verification work for an unknown
   canonical client ID by using a process-start dummy verifier;
4. checks the stored lifecycle state and exclusive expiry boundary;
5. re-reads the registration after verification and requires the credential,
   aggregate, status, scope, grants, and expiry state to remain unchanged; and
6. emits only service-client claims for the exact client ID, owner scope,
   credential version, scope, and domain grants.

Service-client identities do not receive human administrator roles or actor
claims.

## Registration and Administration

The Admin **API & Developer** page at `/admin/api` lists and manages only the
registrations belonging to the authenticated HIP actor. Owner scope is derived
server-side from the unique `hip_actor_id` through a versioned HMAC; callers
cannot choose or override it. Cross-owner lookups and mutations are
non-disclosing.

The Web management API is rooted at `/api/v1/admin/service-clients`:

| Method and path | Policy and behavior |
|---|---|
| `GET /` | `CanViewServiceClients`; returns a bounded owner-scoped page and an opaque continuation cursor. |
| `POST /` | `CanManageServiceClients` plus `RecentPrivilegedAuthentication`; creates a registration and returns its full credential once. |
| `POST /{clientId}/credentials/rotate` | The same mutation policies; atomically replaces the verifier at the supplied aggregate version and returns the replacement credential once. |
| `POST /{clientId}/revoke` | The same mutation policies; terminally revokes the registration at the supplied aggregate version. |

Only Owner and Admin roles receive the view or manage permissions. Production
mutations therefore require MFA-backed recent authentication. Cookie-authenticated
management requests also require antiforgery validation. Mutation bodies and
rates are bounded, and the actor is reauthorized immediately before the
lifecycle operation. The HTTP endpoints and interactive `/admin/api` page both
enter the same lifecycle boundary, which reserves one combined create, rotate,
or revoke budget for the exact actor before credential generation, PBKDF2, or
repository access. The default shared budget is ten mutations per actor in one
minute.

That management budget uses the same atomic Redis fixed-window store as the
authentication work limiter, but a separate versioned HMAC domain and key
prefix. Redis never receives the actor identifier. There is no process-local
fallback: unavailable or invalid distributed state returns the stable
service-unavailable outcome without mutation work. Exhausted budgets return
`429` to HTTP callers and the same bounded retry-later message to the Blazor UI.
The route-specific HTTP limiter remains an independent edge control; one HTTP
request enters the shared lifecycle budget exactly once.

Management-budget options are under:

```text
HipSecurity:ServiceClientManagementMutations
```

The window can be one second through one hour, and the actor mutation limit
must be positive and no greater than 10,000.

List and ordinary lifecycle responses exclude the raw secret, full credential,
credential verifier, and owner-scope value. Create and rotation responses use
`Cache-Control: no-store, no-cache`; the full credential is held only long
enough to display it once. Dismissing it or leaving the page removes the UI's
copy. HIP cannot recover it later.

## Lifecycle

- Creation accepts a lifetime from 1 through 365 days; the default is 90 days.
- Expiry is an exclusive server-owned UTC boundary. At or after that instant,
  authentication and credential rotation fail closed.
- Rotation preserves the original expiry, scope, domain grants, client ID, and
  owner. It increments both the credential and aggregate versions. The previous
  secret stops authenticating after the atomic update succeeds.
- Revocation is terminal. A revoked client cannot rotate or become active again.
- Rotation and revocation require the current aggregate version. Concurrent or
  stale changes receive a conflict; exactly one competing transition can win.

Create, rotate, and revoke commit the encrypted registration and its audit fact
atomically. A global immutable client-ID binding prevents the same identifier
from being registered to another owner.

### Privacy HMAC Key Rotation

Changing `HipSecurity:PrivacyHashingKey` changes the server-derived owner
partition for future registrations. During a planned rotation, configure the
former key through the secret-provider-backed array
`HipSecurity:LegacyPrivacyHashingKeys`. HIP accepts at most eight configured
former-key entries and deduplicates exact repeats; outside Development every
value must meet the same non-placeholder key requirements as the current key.
Privacy-hashing keys, including legacy keys, must remain separate from current
and legacy record-encryption keys.

New registrations always use the current privacy key. Owner management derives
the current partition followed by the configured legacy partitions. Listing
queries each partition after the same client ID, merges the bounded results in
exact ordinal client-ID order, and returns one global page. Rotation and
revocation accept an existing registration from any derived owner partition;
they preserve that registration's original owner scope. Authentication remains
available throughout because its global client-ID binding already points to the
stored owner partition and does not rederive it from the current privacy key.

Continuation cursors use a versioned client-ID payload authenticated against
the current derived owner scope. They contain no owner-scope value and reject
tampering or cross-owner reuse. A current privacy-key change intentionally
invalidates previously issued list cursors; restart listing without a cursor.

Do not remove a former privacy key while service-client registrations in its
owner partition still require listing, rotation, or revocation. Retire or
replace those integrations first, then remove the legacy key from deployment
configuration. Never place current or former privacy keys in source control,
logs, public APIs, or cursor payloads.

## Verifier Protection

HIP never persists the raw secret. It stores only this canonical verifier inside
the encrypted service-client aggregate:

```text
pbkdf2-sha256-v1$600000$<16-byte-salt-base64url>$<32-byte-derived-key-base64url>
```

The derived key uses PBKDF2-HMAC-SHA256 with 600,000 iterations. The input is
domain-separated and binds the secret to the exact client ID:

```text
HIP-Service-Credential-v1\0<clientId>\0<secret>
```

Verification parses only the exact versioned form and uses a fixed-time compare.
Changing the client ID therefore invalidates an otherwise matching secret.

## Pre-Verification Rate Limiting

PBKDF2 is intentionally expensive, so every apparent authentication attempt
must reserve two Redis-backed fixed-window budgets before lookup or derivation:

- 120 total attempts per exact source in the default one-minute window; and
- 30 attempts per exact source plus apparent client ID in that window.

Both successful and failed attempts consume the budgets. The broader source
budget prevents an attacker from multiplying work by cycling fabricated client
IDs. Redis keys contain versioned HMAC digests rather than raw source identities
or client IDs. Counter increment and first expiry are one atomic Redis operation.
Endpoint-specific rate limits remain separate.

There is no process-local fallback. Invalid counter state, Redis failure, or
cancellation fails authentication closed before PBKDF2 work or protected route
execution. Production instances therefore require reliable shared Redis and a
configured privacy-HMAC key.

Runtime options are under:

```text
HipSecurity:ServiceClientAuthenticationAttempts
```

The window can be one second through one hour, and configured limits must be
positive, bounded, with the source-plus-client limit no greater than the source
limit.

## Audit, Telemetry, and Incident Response

Lifecycle audits use the opaque client ID as the target and record only the
action, actor, exact scope, domain-grant count, versions, timestamps, and
severity. They do not contain the raw secret, full credential, verifier, domain
list, request content, authorization header, or source address.

Authentication and lifecycle telemetry uses bounded outcome, operation, and
scope labels only. Do not add client IDs, owner identifiers, domains, IP
addresses, header values, or credential material as metric dimensions, trace
tags, or log properties. The shared HTTP instrumentation masks authorization
and other credential-bearing headers.

Treat an exposed credential as compromised:

1. revoke it immediately, or rotate it when the integration can receive the
   replacement securely;
2. update the integration through a secret manager rather than source control;
3. review the privacy-safe lifecycle and authentication-outcome telemetry; and
4. do not extend the original expiry as part of rotation.

For the design rationale and rejected alternatives, see
[`ADR-001: Use owner-bound static service-client credentials`](decisions/ADR-001-service-client-credentials.md).
