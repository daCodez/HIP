#!/bin/sh
set -eu

container="${HIP_UNBOUND_CONTAINER:-hip-staging-unbound-1}"
config=/etc/unbound/unbound.conf

health="$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')"
if [ "$health" != "healthy" ]; then
    echo "HIP resolver is not healthy: $health" >&2
    exit 1
fi

published_ports="$(docker inspect "$container" --format '{{json .NetworkSettings.Ports}}')"
case "$published_ports" in
    *':null'*) ;;
    *)
        echo "HIP resolver unexpectedly has a published host port." >&2
        exit 1
        ;;
esac

docker exec "$container" unbound-control -c "$config" status
docker exec "$container" unbound-control -c "$config" stats_noreset \
    | grep -E '^(total\.num\.(queries|cachehits|cachemiss|recursivereplies|queries_ip_ratelimited)|total\.requestlist\.exceeded|num\.answer\.bogus)='
