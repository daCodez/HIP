# HIP authoritative DNS

## Current milestone

HIP now has an owner-only authoritative DNS control plane in the admin portal at `/dns`.

The first milestone supports complete-zone publication for:

- A
- AAAA
- CNAME
- MX
- TXT

Every zone must already have a HIP domain enrollment whose ownership check has passed. Publication also requires recent privileged authentication. HIP validates the full desired record set, stores encrypted desired and provider state, sends the normalized zone to a private PowerDNS Authoritative API, enables DNSSEC, retrieves the public DS records, and writes a privacy-safe audit entry.

## Management model

- The HIP admin portal is the control plane. Only an Owner can publish authoritative zones in this milestone.
- Consumer and browser-extension clients cannot change DNS records.
- PowerDNS is the authoritative data plane. Its HTTP API is available only on the private container network and requires a dedicated API key.
- Unbound remains the recursive resolver. It does not host public zones.
- dnsdist remains the encrypted resolver front door. Authoritative and recursive workloads are separate.

## Safety boundaries

- A zone cannot be published until HIP has verified control of the domain.
- Record names must remain inside the exact verified zone.
- Wildcard, SOA, NS, SRV, CAA, PTR, and custom record types are not accepted in this milestone.
- The zone apex cannot be a CNAME.
- CNAME records cannot coexist with another record at the same name.
- TTL values are bounded to 60 through 86400 seconds.
- A zone contains at most 100 managed records.
- AXFR and dynamic DNS updates are disabled.
- Query logging is disabled.
- Provider response bodies and API keys are never returned through admin errors.

## Delegation status

The authoritative container remains private during this milestone. This lets HIP safely create and test zones without claiming production nameserver availability.

Before public delegation:

1. Provision a second authoritative node on an independent server and network.
2. Publish `ns1.guardwithhip.com` and `ns2.guardwithhip.com` address records.
3. Register nameserver glue with the registrar when required.
4. Publish TCP and UDP port 53 on both authoritative nodes.
5. Validate authoritative answers, DNSSEC signatures, DS records, negative answers, TCP fallback, and recursion refusal from outside both networks.
6. Delegate one test zone before moving a production domain.

Showing two nameserver labels that point to one server would not provide real redundancy, so HIP does not present that as production-ready high availability.

## DNSSEC

PowerDNS online signing is enabled for each published zone and API rectification runs after changes. The admin page displays the resulting DS material. DNSSEC is not complete until the matching DS record is installed at the parent or registrar and independently validated.
