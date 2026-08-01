#!/bin/sh
set -eu

image="${HIP_SANDBOX_PROOF_IMAGE:-caddy:2.10-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d}"
container_name="hip-sandbox-isolation-proof-$$"

case "$image" in
  *@sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "Sandbox proof image must be pinned by SHA-256 digest." >&2; exit 1 ;;
esac
case "$container_name" in
  hip-sandbox-isolation-proof-[0-9]*) ;;
  *) echo "Unsafe sandbox proof container name." >&2; exit 1 ;;
esac

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run -d \
  --name "$container_name" \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --pids-limit 32 \
  --cpus 0.5 \
  --memory 256m \
  --memory-swap 256m \
  --user 65532:65532 \
  --log-driver none \
  --entrypoint /bin/sh \
  "$image" \
  -c 'sleep 120' >/dev/null

test "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$container_name")" = "none"
test "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$container_name")" = "true"
test "$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$container_name")" = "32"
test "$(docker inspect -f '{{.HostConfig.NanoCpus}}' "$container_name")" = "500000000"
test "$(docker inspect -f '{{.HostConfig.Memory}}' "$container_name")" = "268435456"
test "$(docker inspect -f '{{.HostConfig.MemorySwap}}' "$container_name")" = "268435456"
test "$(docker inspect -f '{{.HostConfig.LogConfig.Type}}' "$container_name")" = "none"
test "$(docker inspect -f '{{json .HostConfig.CapDrop}}' "$container_name")" = '["ALL"]'
docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$container_name" | grep -q 'no-new-privileges'
docker inspect -f '{{index .HostConfig.Tmpfs "/tmp"}}' "$container_name" | grep -q 'noexec'
docker inspect -f '{{index .HostConfig.Tmpfs "/tmp"}}' "$container_name" | grep -q 'nosuid'
docker inspect -f '{{index .HostConfig.Tmpfs "/tmp"}}' "$container_name" | grep -q 'nodev'
test "$(docker exec "$container_name" id -u)" = "65532"

if docker exec "$container_name" sh -c 'touch /hip-root-write-must-fail' >/dev/null 2>&1; then
  echo "Read-only root filesystem proof failed." >&2
  exit 1
fi
docker exec "$container_name" sh -c 'printf "#!/bin/sh\nexit 0\n" > /tmp/proof.sh && chmod 700 /tmp/proof.sh'
if docker exec "$container_name" /tmp/proof.sh >/dev/null 2>&1; then
  echo "No-execute temporary filesystem proof failed." >&2
  exit 1
fi
if docker exec "$container_name" wget -q -T 2 -O /tmp/network-proof https://example.com >/dev/null 2>&1; then
  echo "Network isolation proof failed." >&2
  exit 1
fi

printf '%s\n' \
  'sandbox-isolation=passed' \
  "image=$image" \
  'network=none' \
  'rootfs=read-only' \
  'tmpfs=rw,noexec,nosuid,nodev,16m' \
  'capabilities=none' \
  'no-new-privileges=true' \
  'user=65532:65532' \
  'pids=32' \
  'cpu=0.5' \
  'memory=256m' \
  'network-attempt=blocked'
