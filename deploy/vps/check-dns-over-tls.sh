#!/bin/sh
set -eu

container="${HIP_DNSDIST_CONTAINER:-hip-staging-dnsdist-1}"
host="${HIP_DNS_HOST:-dns.guardwithhip.com}"

published_ports="$(docker inspect "$container" --format '{{json .HostConfig.PortBindings}}')"
echo "$published_ports" | grep -q '853/tcp'

secure="$(docker exec "$container" kdig @127.0.0.1 -p 853 +tls +tls-hostname="$host" cloudflare.com A +dnssec)"
echo "$secure" | grep -q 'status: NOERROR'
echo "$secure" | grep -Eq 'Flags:.* ad'

bogus="$(docker exec "$container" kdig @127.0.0.1 -p 853 +tls +tls-hostname="$host" dnssec-failed.org A +dnssec)"
echo "$bogus" | grep -q 'status: SERVFAIL'

certificate="$(docker exec "$container" openssl s_client -connect 127.0.0.1:853 -servername "$host" -verify_hostname "$host" -verify_return_error </dev/null 2>&1)"
echo "$certificate" | grep -q 'Verify return code: 0 (ok)'

echo "HIP DNS-over-TLS is healthy, certificate-verified, DNSSEC-validating, and fail-closed."
