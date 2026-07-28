# HIP Authentication

HIP Web uses separate authentication stacks for local development and deployed
environments. Production authentication is provider-neutral OpenID Connect
(OIDC); HIP does not own, receive, or store the user's production password.

## Environment Boundary

- `Development` registers only `HipDevHeader`. Its loopback request guard,
  local password provider, and development cookies remain available for local
  testing. The provider supports bounded configured accounts and an explicit
  `AllowTestPersonas` mode: different local test emails derive different stable
  actor IDs but start unprivileged, while repeated use of one email preserves
  identity across browser sessions.
- Every other environment registers only the encrypted HIP session cookie, an
  OIDC confidential client, and a challenge router. Development headers and
  cookies cannot authenticate there.
- Browser pages challenge through OIDC. Requests under `/api` receive 401 or
  403 without a login or identity-provider redirect.

## Production OIDC

The host uses authorization-code flow with PKCE, HTTPS metadata, the minimal
`openid` scope, strict issuer/audience/signature/lifetime validation, and a
one-minute clock skew. Tokens are not saved into the HIP session. External
claims are reduced after validation:

- the exact `iss` and `sub` pair is hashed into a privacy-safe stable
  `hip_actor_id`;
- the same value supplies `hip_consumer_id` and the name identifier;
- email and display name do not establish ownership and are discarded;
- only exact configured external role values become canonical HIP roles.

Unknown roles are ignored. Missing, blank, duplicate, or excessive identity
claims fail closed.

## Privileged MFA and Step-Up

Outside Development, every Owner and Administrator policy requires HIP-owned
MFA evidence derived from the validated OIDC identity token. HIP never copies
raw provider assurance claims into its session. It instead emits one canonical
`hip_mfa=true` claim and one canonical `hip_auth_time` Unix timestamp after
validating bounded `amr`, `acr`, and `auth_time` values.

MFA recognition is deliberately provider-specific:

- `AcceptStandardMfaAmr=true` accepts only the exact, case-sensitive RFC 8176
  `mfa` authentication-method reference; or
- `TrustedMfaAcrValues` accepts only exact assurance-context values explicitly
  approved for the deployed identity provider.

Unknown or malformed assurance data never grants MFA. A privileged initial
session also needs a valid `auth_time` within the absolute session lifetime.
High-impact mutations additionally require authentication no older than
`RecentAuthenticationLifetime`.

The `/step-up` page provides an explicit confirmation action instead of an
automatic redirect loop. Its antiforgery-protected, rate-limited POST sends
`prompt=login`, `max_age=0`, and configured `acr_values`. Protected OIDC state
binds the response to the current HIP actor and original absolute expiry, so a
successful step-up cannot extend the hard session lifetime. Provider tokens and
provider error details are not stored or displayed. API authorization failures
remain 401 or 403 responses and never become HTML redirects.

## Session Security

The production cookie is `__Host-HIP.Session`, `Secure`, `HttpOnly`,
`SameSite=Lax`, path `/`, and has no domain attribute. HIP performs bounded idle
renewal itself and never renews beyond the original absolute expiry or the
validated identity token's expiry.

Data Protection keys must be stored in a durable directory shared by all HIP
Web replicas and encrypted with a currently valid RSA PKCS#12 certificate whose
key is at least 2048 bits. The certificate private key is loaded non-exportably
into ephemeral process key storage. Startup probes the key-ring directory for
read/write access and fails if authentication, certificate, or key-ring
configuration is incomplete.

## Standalone API Service Clients

HIP-0205 adds a separate non-browser authentication boundary to
`HIP.ApiService`. It does not extend the HIP Web cookie or turn a consumer device
key into an API credential.

Service clients send this canonical header (the credential portions are
case-sensitive):

```http
Authorization: HIP-Service <clientId>.<secret>
```

Any `Authorization` header pins the request to the `HIP-Service` scheme. There
is no cookie fallback, and outside Development there is no fallback to the
loopback administrator headers. Missing, malformed, unknown, incorrect,
expired, revoked, rotated, or unavailable credentials produce the same
non-disclosing `401` challenge. A verified client with the wrong exact scope or
domain grant receives `403`.

Each owner-bound registration has exactly one scope—either
`domain-verification:check` or
`site-safety:external-evidence:check`—and one to sixteen exact canonical domain
grants. Wildcards and suffix grants are not accepted. The server derives owner
scope from the authenticated administrative actor; service-client claims do not
grant human roles or actor identity.

Create and rotation return the full credential once in a no-store response.
HIP persists only a client-bound
`pbkdf2-sha256-v1$600000$<salt>$<derived-key>` verifier inside the encrypted
aggregate. Rotation preserves expiry and immediately invalidates the previous
secret; revocation is terminal. A Redis-backed, privacy-HMAC-keyed source and
source-plus-client budget runs before PBKDF2 and fails closed without a local
fallback.

These are static bearer credentials and can be replayed if stolen. HTTPS,
secret-manager storage, bounded lifetime, monitoring, rotation, and revocation
remain necessary. Credential possession, scope authorization, and domain
control do not prove safety or trustworthiness. See
[`service-client-credentials.md`](service-client-credentials.md) for the full
wire, lifecycle, administration, rate-limit, audit, and telemetry contract.

## Required Deployment Configuration

Use environment variables, a secret store, or another protected configuration
provider. Do not place either password below in source-controlled JSON.

```text
HipAuthentication__Authority=https://identity.example/tenant
HipAuthentication__ClientId=hip-web
HipAuthentication__ClientSecret=<secret>
HipAuthentication__RoleClaimType=roles
HipAuthentication__RoleMappings__hip-owner=Owner
HipAuthentication__RoleMappings__hip-admin=Admin
HipAuthentication__IdleSessionLifetime=00:30:00
HipAuthentication__AbsoluteSessionLifetime=08:00:00
HipAuthentication__AcceptStandardMfaAmr=true
HipAuthentication__TrustedMfaAcrValues__0=<optional exact provider assurance context>
HipAuthentication__RecentAuthenticationLifetime=00:10:00

HipSessionProtection__KeyRingDirectoryPath=<absolute shared directory>
HipSessionProtection__CertificatePath=<absolute secret-mounted .pfx or .p12>
HipSessionProtection__CertificatePassword=<secret>
HipSessionProtection__ApplicationName=HIP.Web
```

The configured identity provider must allow HIP's `/signin-oidc` callback and
`/signout-callback-oidc` signed-out callback over HTTPS. Reverse proxies must
forward the public scheme and host only through an explicitly trusted proxy
configuration.

Enable `AcceptStandardMfaAmr` only after confirming that the provider emits the
standard `mfa` value with the intended meaning. Otherwise, leave it false and
configure one or more reviewed exact `TrustedMfaAcrValues`. Provider policy must
be able to satisfy HIP's requested assurance and must issue a trustworthy
`auth_time`; all HIP Web replicas and the provider need synchronized clocks.
The assurance contract follows
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0-18.html)
and the registered
[authentication method reference values](https://www.rfc-editor.org/rfc/rfc8176.html).

Microsoft's current guidance for this design is the
[ASP.NET Core OIDC web authentication guide](https://learn.microsoft.com/aspnet/core/security/authentication/configure-oidc-web-authentication?view=aspnetcore-10.0)
and the
[Data Protection key storage guide](https://learn.microsoft.com/aspnet/core/security/data-protection/implementation/key-storage-providers?view=aspnetcore-10.0).

## Milestone Boundaries

HIP-0201 covers production user sign-in and Web sessions. HIP-0202 covers MFA
and privileged step-up authentication. HIP-0203 owns the exhaustive role/route
matrix. HIP-0204 adds consumer-owned device proof and revocation without turning
the Web session cookie into a client credential. HIP-0205 adds owner-bound
service-client registration, lifecycle, standalone API authentication, exact
scopes, and exact resource grants. HIP-0301 is the next work package and owns
formalizing the scoring pipeline; it must not move provider or credential
decisions into authentication. See
[`device-registration.md`](device-registration.md) for the HIP-0204 boundary.
