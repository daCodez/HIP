# HIP-aware DNS provider milestone

HIP now has a provider boundary for public A and AAAA lookups and a bounded JSON DNS endpoint at:

```http
GET /dns-query?name=example.com&type=A
Accept: application/dns-json
```

The response contains conventional DNS-JSON question and answer fields plus a `hip` property containing the same public-safe trust summary used by the public domain lookup.

## Security and privacy boundaries

- Only public host names and A or AAAA record types are accepted.
- DNS answers come from the configured `IDnsLookupProvider` implementation.
- HIP trust data remains separate from authoritative DNS data.
- A verified identity does not mean a site is safe.
- Verification challenge tokens, private page content, form values, cookies, and raw private URLs are never returned.
- The endpoint uses the existing public scan rate limit and output-cache policy.

## Current provider

`DnsClientLookupProvider` uses DnsClient.NET and HIP's existing validated resolver configuration. The application depends only on `IDnsLookupProvider`, so a managed resolver, enterprise CoreDNS adapter, or another recursive provider can replace it without changing the public contract.

## Deliberately deferred

This is the provider and API foundation, not a complete public recursive DNS service. The following remain future milestones:

- RFC 8484 DNS wire-format GET and POST support;
- DNSSEC validation reporting;
- DNS over TLS;
- UDP and TCP port 53 listeners;
- resolver-specific caching and abuse controls;
- high-availability resolver deployment and monitoring.
