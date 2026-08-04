#!/bin/sh
set -eu

container="${HIP_DNSDIST_CONTAINER:-hip-staging-dnsdist-1}"
host="${HIP_DNS_HOST:-dns.guardwithhip.com}"

post="$(docker exec "$container" kdig @"$host" +https=/dns-query +tls-hostname="$host" cloudflare.com A +dnssec)"
echo "$post" | grep -q 'HTTP/2-POST'
echo "$post" | grep -q 'status: NOERROR'
echo "$post" | grep -Eq 'Flags:.* ad'

get="$(docker exec "$container" kdig @"$host" +https=/dns-query +https-get +tls-hostname="$host" cloudflare.com A +dnssec)"
echo "$get" | grep -q 'HTTP/2-GET'
echo "$get" | grep -q 'status: NOERROR'
echo "$get" | grep -Eq 'Flags:.* ad'

bogus="$(docker exec "$container" kdig @"$host" +https=/dns-query +https-get +tls-hostname="$host" dnssec-failed.org A +dnssec)"
echo "$bogus" | grep -q 'status: SERVFAIL'

wrong_media_status="$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/octet-stream' \
    --data-binary 'not-a-dns-message' \
    "https://$host/dns-query")"
test "$wrong_media_status" = 415

echo "HIP DNS-over-HTTPS is healthy for GET and POST, certificate-verified, DNSSEC-validating, and fail-closed."
