#!/bin/sh
set -eu

host="${HIP_DNS_HOST:-dns.guardwithhip.com}"
case "$host" in
    *[!A-Za-z0-9.-]*|.*|*.)
        echo "Invalid HIP DNS certificate host." >&2
        exit 2
        ;;
esac

caddy_data="${HIP_CADDY_DATA_PATH:-/var/lib/docker/volumes/hip-staging_caddy-data/_data}"
destination="${HIP_DNSDIST_TLS_PATH:-/opt/hip/shared/dnsdist-tls}"
source_directory="$caddy_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/$host"
source_certificate="$source_directory/$host.crt"
source_key="$source_directory/$host.key"

test -s "$source_certificate"
test -s "$source_key"
openssl x509 -in "$source_certificate" -noout -checkend 604800 >/dev/null

certificate_key_hash="$(openssl x509 -in "$source_certificate" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
private_key_hash="$(openssl pkey -in "$source_key" -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
if [ "$certificate_key_hash" != "$private_key_hash" ]; then
    echo "HIP DNS certificate and private key do not match." >&2
    exit 1
fi

install -d -o 953 -g 953 -m 0750 "$destination"
certificate_target="$destination/$host.crt"
key_target="$destination/$host.key"

if [ -f "$certificate_target" ] && [ -f "$key_target" ] &&
   cmp -s "$source_certificate" "$certificate_target" &&
   cmp -s "$source_key" "$key_target"; then
    exit 0
fi

install -o 953 -g 953 -m 0644 "$source_certificate" "$certificate_target.new"
install -o 953 -g 953 -m 0640 "$source_key" "$key_target.new"
mv -f "$certificate_target.new" "$certificate_target"
mv -f "$key_target.new" "$key_target"
