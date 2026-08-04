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

JSON responses expose the same validation result in the standard `AD` field and a `dnssec` object. HIP trusts DNSSEC status only from its explicitly configured validating resolver. Validated answers are `secure`, proven unsigned answers are `insecure`, DNSSEC validation failures with a standard Extended DNS Error are `bogus`, and other resolver failures remain `indeterminate`.

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

`DnsClientLookupProvider` uses DnsClient.NET and the private HIP-owned Unbound 1.25.2 resolver. Unbound is built from a pinned upstream revision, validates DNSSEC recursively from the root trust anchor, and is reachable only inside the deployment network. The application depends only on `IDnsLookupProvider`, so a managed resolver or another recursive provider can replace it without changing the public contract.

The resolver uses bounded caches, stale-answer protection, query minimization, minimal responses, DNSSEC hardening, per-client and recursion rate limits, and cumulative privacy-safe operational counters. Its container health check performs a real DNSSEC-validated root query instead of checking only that the process is running. Operators can inspect health and aggregate counters without logging queried names:

```sh
./deploy/vps/check-unbound.sh
```

## Deliberately deferred

This is the provider and API foundation, not a complete public recursive DNS service. The following remain future milestones:

- DNS over TLS;
- UDP and TCP port 53 listeners;
- a dedicated DNS front door with public-client abuse controls;
- high-availability resolver deployment and external alerting.
