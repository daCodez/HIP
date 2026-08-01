#!/bin/sh
set -eu

environment_file=/etc/hip/private-staging.env
session_directory=/etc/hip/session
keyring_directory=/var/lib/hip/consumer-session-keys
certificate_path="$session_directory/hip-session-protection.pfx"

if [ "$(id -u)" -ne 0 ]; then
    echo "This provisioning script must run as root." >&2
    exit 1
fi

if [ ! -f "$environment_file" ]; then
    echo "HIP's protected environment file is missing." >&2
    exit 1
fi

umask 077

random_secret() {
    openssl rand -hex 32
}

ensure_setting() {
    setting_name=$1
    setting_value=$2
    if ! grep -q "^${setting_name}=" "$environment_file"; then
        printf '%s=%s\n' "$setting_name" "$setting_value" >> "$environment_file"
    fi
}

ensure_setting HIP_IDENTITY_HOST identity.guardwithhip.com
ensure_setting KEYCLOAK_POSTGRES_DB hip_identity
ensure_setting KEYCLOAK_POSTGRES_USER hip_identity
ensure_setting KEYCLOAK_POSTGRES_PASSWORD "$(random_secret)"
ensure_setting KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME hip-bootstrap-admin
ensure_setting KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD "$(random_secret)"
ensure_setting HIP_OIDC_CLIENT_SECRET "$(random_secret)"
ensure_setting HIP_SESSION_CERTIFICATE_PASSWORD "$(random_secret)"
ensure_setting HIP_SESSION_CERTIFICATE_PATH "$certificate_path"
ensure_setting HIP_SESSION_KEYRING_PATH "$keyring_directory"

install -d -m 0750 -o root -g 1654 "$session_directory"
install -d -m 0700 -o 1654 -g 1654 "$keyring_directory"

if [ ! -f "$certificate_path" ]; then
    certificate_password=$(sed -n 's/^HIP_SESSION_CERTIFICATE_PASSWORD=//p' "$environment_file")
    temporary_directory=$(mktemp -d "$session_directory/.provision.XXXXXXXX")
    case "$temporary_directory" in
        "$session_directory"/.provision.*) ;;
        *)
            echo "Refusing an unexpected temporary path." >&2
            exit 1
            ;;
    esac
    trap 'rm -rf -- "$temporary_directory"' EXIT HUP INT TERM

    openssl req \
        -x509 \
        -newkey rsa:3072 \
        -sha256 \
        -nodes \
        -days 730 \
        -subj '/CN=HIP consumer session protection' \
        -keyout "$temporary_directory/session.key" \
        -out "$temporary_directory/session.crt" \
        >/dev/null 2>&1
    openssl pkcs12 \
        -export \
        -inkey "$temporary_directory/session.key" \
        -in "$temporary_directory/session.crt" \
        -passout "pass:$certificate_password" \
        -out "$temporary_directory/session.pfx" \
        >/dev/null 2>&1
    install -m 0640 -o root -g 1654 "$temporary_directory/session.pfx" "$certificate_path"
fi

chmod 0600 "$environment_file"
echo "HIP identity secrets and session protection are provisioned."
