#!/bin/sh
set -eu

container="${HIP_POWERDNS_CONTAINER:-hip-staging-powerdns-1}"

health="$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')"
if [ "$health" != "healthy" ]; then
    echo "HIP authoritative DNS is not healthy: $health" >&2
    exit 1
fi

published_ports="$(docker inspect "$container" --format '{{json .NetworkSettings.Ports}}')"
case "$published_ports" in
    *'"5300/tcp":null'*'"5300/udp":null'*) ;;
    *)
        echo "HIP authoritative DNS should remain private until nameserver glue and delegation are approved." >&2
        exit 1
        ;;
esac

docker exec "$container" pdns_control ping | grep -q 'PONG'
docker exec "$container" sh -c 'curl --fail --silent --show-error --max-time 5 -H "Accept: application/json" -H "X-API-Key: $HIP_POWERDNS_API_KEY" http://127.0.0.1:8081/api/v1/servers/localhost' \
    | grep -q '"daemon_type":"authoritative"'

refused="$(docker exec "$container" dig @127.0.0.1 -p 5300 cloudflare.com A +time=3 +tries=1)"
echo "$refused" | grep -q 'status: REFUSED'

echo "HIP authoritative DNS is private, healthy, API-authenticated, and recursion-disabled."
