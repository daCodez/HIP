# HIP-aware DNS provider milestone

HIP now has a provider boundary for public A and AAAA lookups and a bounded JSON DNS endpoint at:

```http
GET /dns-query?name=example.com&type=A
Accept: application/dns-json
```

The response contains conventional DNS-JSON question and answer fields plus a `hip` property containing the same public-safe trust summary used by the public domain lookup.

The same endpoint also supports RFC 8484 DNS wire format:

```http
GET /dns-query?dns={unpadded-base64url-dns-message}
Accept: application/dns-message
```

```http
POST /dns-query
Content-Type: application/dns-message
Accept: application/dns-message

{dns-message body}
```

Wire responses remain valid DNS messages. HIP evidence is carried separately in `X-HIP-Status`, `X-HIP-Score` when available, `X-HIP-Evidence-Coverage`, and `X-HIP-Authoritative` response headers. DNSSEC validation is carried by the standard AD bit and the `X-HIP-DNSSEC-Status` header. `X-HIP-Authoritative` is currently always `false` because HIP trust evidence is not authoritative DNS data.

JSON responses expose the same validation result in the standard `AD` field and a `dnssec` object. The status is `secure` only when the configured recursive resolver sets the authenticated-data bit. Unsigned or failed responses remain `indeterminate` until HIP is connected to a validating resolver that can provide a stronger insecure or bogus proof. This avoids treating a missing AD bit as proof of a DNSSEC failure.

## Security and privacy boundaries

- Only public host names and A or AAAA record types are accepted.
- DNS answers come from the configured `IDnsLookupProvider` implementation.
- DNSSEC records are requested from the upstream resolver and resolver-validated answers preserve the AD signal.
- HIP trust data remains separate from authoritative DNS data.
- A verified identity does not mean a site is safe.
- Verification challenge tokens, private page content, form values, cookies, and raw private URLs are never returned.
- The endpoint uses the existing public scan rate limit. The DNS provider keeps its own bounded resolver cache.
- GET wire responses use an HTTP freshness lifetime no greater than the smallest answer TTL. POST wire responses are not cached.

## Current provider

`DnsClientLookupProvider` uses DnsClient.NET and HIP's existing validated resolver configuration. The application depends only on `IDnsLookupProvider`, so a managed resolver, enterprise CoreDNS adapter, or another recursive provider can replace it without changing the public contract.

## Deliberately deferred

This is the provider and API foundation, not a complete public recursive DNS service. The following remain future milestones:

- deployment of a dedicated validating resolver with insecure and bogus classifications;
- DNS over TLS;
- UDP and TCP port 53 listeners;
- resolver-specific caching and abuse controls;
- high-availability resolver deployment and monitoring.
