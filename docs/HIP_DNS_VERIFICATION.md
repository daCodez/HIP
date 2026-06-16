# HIP DNS Verification MVP

HIP uses DNS TXT verification to prove that a website operator controls a domain. This is an origin identity signal only. It does not prove that the site is safe, reputable, or free of risky content.

## TXT Record Format

Publish the verification token at `_hip.{domain}`:

```text
_hip.example.com TXT "hip-site-verification=abc123"
```

HIP checks the exact token after the `hip-site-verification=` prefix.

## Local CoreDNS

Aspire runs CoreDNS as a local development container named `hip-coredns` when `HIP_ASPIRE_ENABLE_COREDNS` is not set to `false`.

The local zone file is in `eng/coredns/hip.test.zone` and includes:

```text
_hip.good.test TXT "hip-site-verification=good-token"
_hip.bad.test TXT "hip-site-verification=wrong-token"
```

The API points DNS verification at `127.0.0.1:1053` over TCP during local Aspire runs.

## API Check

Use:

```http
POST /api/v1/domain-verification/check
Content-Type: application/json

{
  "domain": "good.test",
  "expectedToken": "good-token"
}
```

Expected statuses:

- `NotConfigured`: no HIP TXT record was found.
- `PendingVerification`: DNS could not be checked safely yet.
- `Verified`: the expected TXT record was found.
- `Invalid`: a HIP TXT record exists, but the token does not match.

## Security And Privacy

HIP logs the domain and status, but not the verification token. The token is accepted only for the ownership check and is not returned by the API.

DNS verification does not replace browser scanning, public lookup, provider evidence, rule evaluation, or the admin dashboard. It only establishes domain-control evidence that later HIP trust scoring can use.

## MVP Limits

- CoreDNS is for local development testing only.
- DNS verification is not yet persisted as a durable production identity record.
- DNS verification does not raise a site to Trusted by itself.
