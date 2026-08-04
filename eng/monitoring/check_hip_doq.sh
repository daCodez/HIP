#!/bin/sh
set -eu

host="${HIP_DNS_HOST:-dns.guardwithhip.com}"
case "$host" in
    *[!A-Za-z0-9.-]*|.*|*.)
        echo "Invalid HIP DNS host." >&2
        exit 2
        ;;
esac

if ! command -v kdig >/dev/null 2>&1; then
    echo "The DNS-over-QUIC probe requires kdig." >&2
    exit 2
fi

if ! secure="$(kdig "@$host" -p 853 +quic +tls-ca +tls-hostname="$host" cloudflare.com A +dnssec 2>&1)"; then
    echo "DNS-over-QUIC secure-domain probe failed." >&2
    exit 1
fi
echo "$secure" | grep -q 'status: NOERROR'
echo "$secure" | grep -Eq 'Flags:.* ad'

if ! bogus="$(kdig "@$host" -p 853 +quic +tls-ca +tls-hostname="$host" dnssec-failed.org A +dnssec 2>&1)"; then
    echo "DNS-over-QUIC bogus-domain probe failed to complete." >&2
    exit 1
fi
echo "$bogus" | grep -q 'status: SERVFAIL'

printf '%s\n' '{"name":"doq-secure-certificate-and-fail-closed","status":"pass"}'
