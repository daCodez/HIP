#!/bin/sh
set -eu

if [ "${HIP_POWERDNS_API_KEY:-}" = "" ] || [ "${#HIP_POWERDNS_API_KEY}" -lt 32 ]; then
    echo "HIP_POWERDNS_API_KEY must contain at least 32 characters." >&2
    exit 1
fi

umask 077
mkdir -p /run/pdns
printf 'api-key=%s\n' "$HIP_POWERDNS_API_KEY" > /run/pdns/10-api-key.conf

exec pdns_server --daemon=no --guardian=no --disable-syslog=yes
