#!/bin/sh
set -eu

config_path=/tmp/hip-federation-kcadm.config
realm=hip

cleanup() {
  rm -f "$config_path"
}
trap cleanup EXIT HUP INT TERM

: "${KC_BOOTSTRAP_ADMIN_USERNAME:?KC_BOOTSTRAP_ADMIN_USERNAME is required}"
: "${KC_BOOTSTRAP_ADMIN_PASSWORD:?KC_BOOTSTRAP_ADMIN_PASSWORD is required}"

/opt/keycloak/bin/kcadm.sh config credentials \
  --config "$config_path" \
  --server http://localhost:8080 \
  --realm master \
  --user "$KC_BOOTSTRAP_ADMIN_USERNAME" \
  --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null

upsert_provider() {
  alias_name="$1"
  provider_id="$2"
  client_id="$3"
  client_secret="$4"
  tenant="${5:-}"

  if /opt/keycloak/bin/kcadm.sh get \
      --config "$config_path" \
      "identity-provider/instances/$alias_name" \
      -r "$realm" >/dev/null 2>&1; then
    operation=update
    resource="identity-provider/instances/$alias_name"
  else
    operation=create
    resource=identity-provider/instances
  fi

  set -- \
    --config "$config_path" \
    "$resource" \
    -r "$realm" \
    -s "alias=$alias_name" \
    -s "providerId=$provider_id" \
    -s enabled=true \
    -s trustEmail=true \
    -s storeToken=false \
    -s addReadTokenRoleOnCreate=false \
    -s linkOnly=false \
    -s firstBrokerLoginFlowAlias="first broker login" \
    -s "config.clientId=$client_id" \
    -s "config.clientSecret=$client_secret" \
    -s config.syncMode=IMPORT

  if [ -n "$tenant" ]; then
    set -- "$@" -s "config.tenant=$tenant"
  fi

  /opt/keycloak/bin/kcadm.sh "$operation" "$@" >/dev/null
  echo "$alias_name=enabled"
}

configured=0

if [ -n "${HIP_GOOGLE_CLIENT_ID:-}" ] || [ -n "${HIP_GOOGLE_CLIENT_SECRET:-}" ]; then
  : "${HIP_GOOGLE_CLIENT_ID:?HIP_GOOGLE_CLIENT_ID and HIP_GOOGLE_CLIENT_SECRET must be supplied together}"
  : "${HIP_GOOGLE_CLIENT_SECRET:?HIP_GOOGLE_CLIENT_ID and HIP_GOOGLE_CLIENT_SECRET must be supplied together}"
  upsert_provider google google "$HIP_GOOGLE_CLIENT_ID" "$HIP_GOOGLE_CLIENT_SECRET"
  configured=1
fi

if [ -n "${HIP_MICROSOFT_CLIENT_ID:-}" ] || [ -n "${HIP_MICROSOFT_CLIENT_SECRET:-}" ]; then
  : "${HIP_MICROSOFT_CLIENT_ID:?HIP_MICROSOFT_CLIENT_ID and HIP_MICROSOFT_CLIENT_SECRET must be supplied together}"
  : "${HIP_MICROSOFT_CLIENT_SECRET:?HIP_MICROSOFT_CLIENT_ID and HIP_MICROSOFT_CLIENT_SECRET must be supplied together}"
  upsert_provider microsoft microsoft \
    "$HIP_MICROSOFT_CLIENT_ID" \
    "$HIP_MICROSOFT_CLIENT_SECRET" \
    "${HIP_MICROSOFT_TENANT:-common}"
  configured=1
fi

if [ "$configured" = 0 ]; then
  echo "providers=unchanged"
  echo "Supply a complete Google and/or Microsoft client credential pair."
fi
