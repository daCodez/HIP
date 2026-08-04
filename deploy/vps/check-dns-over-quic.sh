#!/bin/sh
set -eu

container="${HIP_DNSDIST_CONTAINER:-hip-staging-dnsdist-1}"
host="${HIP_DNS_HOST:-dns.guardwithhip.com}"

case "$host" in
    *[!A-Za-z0-9.-]*|.*|*.)
        echo "Invalid HIP DNS host." >&2
        exit 2
        ;;
esac

published_ports="$(docker inspect "$container" --format '{{json .HostConfig.PortBindings}}')"
echo "$published_ports" | grep -q '853/udp'

docker exec "$container" dnsdist --version 2>&1 | grep -q 'dns-over-quic'

if ! secure="$(docker exec "$container" kdig @127.0.0.1 -p 853 +quic +tls-ca +tls-hostname="$host" cloudflare.com A +dnssec 2>&1)"; then
    echo "HIP DNS-over-QUIC secure-domain probe failed." >&2
    exit 1
fi
echo "$secure" | grep -q 'status: NOERROR'
echo "$secure" | grep -Eq 'Flags:.* ad'

if ! bogus="$(docker exec "$container" kdig @127.0.0.1 -p 853 +quic +tls-ca +tls-hostname="$host" dnssec-failed.org A +dnssec 2>&1)"; then
    echo "HIP DNS-over-QUIC bogus-domain probe failed to complete." >&2
    exit 1
fi
echo "$bogus" | grep -q 'status: SERVFAIL'

echo "HIP DNS-over-QUIC is healthy, certificate-verified, DNSSEC-validating, and fail-closed."
