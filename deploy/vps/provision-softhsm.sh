#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "$script_dir/../.." && pwd)"
compose_base="$script_dir/compose.private-staging.yml"
compose_production="$script_dir/compose.production.override.yml"

: "${HIP_SOFTHSM_TOKEN_PATH:?HIP_SOFTHSM_TOKEN_PATH is required}"
: "${HIP_SOFTHSM_USER_PIN_PATH:?HIP_SOFTHSM_USER_PIN_PATH is required}"
: "${HIP_SOFTHSM_SO_PIN_PATH:?HIP_SOFTHSM_SO_PIN_PATH is required}"

case "$HIP_SOFTHSM_TOKEN_PATH" in
    /*) ;;
    *) echo "HIP_SOFTHSM_TOKEN_PATH must be absolute." >&2; exit 1 ;;
esac

for pin_path in "$HIP_SOFTHSM_USER_PIN_PATH" "$HIP_SOFTHSM_SO_PIN_PATH"; do
    case "$pin_path" in
        /*) ;;
        *) echo "SoftHSM PIN paths must be absolute." >&2; exit 1 ;;
    esac
done

install -d -m 0700 -o 1654 -g 1654 "$HIP_SOFTHSM_TOKEN_PATH"
install -d -m 0700 -o 1654 -g 1654 "$HIP_SOFTHSM_TOKEN_PATH/tokens"
install -d -m 0700 "$(dirname -- "$HIP_SOFTHSM_USER_PIN_PATH")"
install -d -m 0700 "$(dirname -- "$HIP_SOFTHSM_SO_PIN_PATH")"

if [[ ! -s "$HIP_SOFTHSM_USER_PIN_PATH" ]]; then
    umask 077
    openssl rand -hex 16 > "$HIP_SOFTHSM_USER_PIN_PATH"
fi
if [[ ! -s "$HIP_SOFTHSM_SO_PIN_PATH" ]]; then
    umask 077
    openssl rand -hex 16 > "$HIP_SOFTHSM_SO_PIN_PATH"
fi

chown 1654:1654 "$HIP_SOFTHSM_USER_PIN_PATH" "$HIP_SOFTHSM_SO_PIN_PATH"
chmod 0400 "$HIP_SOFTHSM_USER_PIN_PATH"
chmod 0400 "$HIP_SOFTHSM_SO_PIN_PATH"

cd "$repository_root"
docker compose \
    -f "$compose_base" \
    -f "$compose_production" \
    run --rm --no-deps --user 1654:1654 \
    -v "$HIP_SOFTHSM_SO_PIN_PATH:/run/secrets/hip-softhsm-so-pin:ro" \
    --entrypoint /bin/sh \
    api -eu -c '
        if softhsm2-util --show-slots | grep -Eq "Label:[[:space:]]+hip-signing[[:space:]]*$"; then
            exit 0
        fi
        so_pin="$(tr -d "\r\n" < /run/secrets/hip-softhsm-so-pin)"
        user_pin="$(tr -d "\r\n" < /run/secrets/hip-softhsm-user-pin)"
        softhsm2-util --init-token --free --label hip-signing --so-pin "$so_pin" --pin "$user_pin" >/dev/null
        unset so_pin user_pin
    '

chown -R 1654:1654 "$HIP_SOFTHSM_TOKEN_PATH"
chmod 0700 "$HIP_SOFTHSM_TOKEN_PATH" "$HIP_SOFTHSM_TOKEN_PATH/tokens"
echo "SoftHSM token is initialized; HIP will provision the non-exportable ML-DSA-65 key on startup."
