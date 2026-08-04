#!/bin/sh
set -eu

container="${HIP_DNSDIST_CONTAINER:-hip-staging-dnsdist-1}"

health="$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')"
if [ "$health" != "healthy" ]; then
    echo "HIP DNS front door is not healthy: $health" >&2
    exit 1
fi

published_ports="$(docker inspect "$container" --format '{{json .NetworkSettings.Ports}}')"
case "$published_ports" in
    *':null'*) ;;
    *)
        echo "HIP DNS front door unexpectedly has a published host port." >&2
        exit 1
        ;;
esac

secure="$(docker exec "$container" dig @127.0.0.1 -p 5353 . SOA +dnssec +time=3 +tries=1)"
echo "$secure" | grep -q 'status: NOERROR'
echo "$secure" | grep -Eq 'flags:.* ad;'

bogus="$(docker exec "$container" dig @127.0.0.1 -p 5353 dnssec-failed.org A +dnssec +time=3 +tries=1)"
echo "$bogus" | grep -q 'status: SERVFAIL'

echo "HIP DNS front door is private, healthy, DNSSEC-validating, and fail-closed."
