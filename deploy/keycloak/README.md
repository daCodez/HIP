# HIP identity provider

Keycloak owns consumer credentials and federated sign-in. HIP accepts only the
OIDC subject, verified contact claims, authentication assurance, and explicitly
allowlisted HIP roles. Self-registration does not assign `hip-owner` or
`hip-admin`.

## Google and Microsoft sign-in

Create an OAuth/OpenID Connect application with the provider and register only
the corresponding callback:

- Google: `https://identity.guardwithhip.com/realms/hip/broker/google/endpoint`
- Microsoft: `https://identity.guardwithhip.com/realms/hip/broker/microsoft/endpoint`

Store the resulting credentials in the protected deployment environment, never
in this repository:

```text
HIP_GOOGLE_CLIENT_ID
HIP_GOOGLE_CLIENT_SECRET
HIP_MICROSOFT_CLIENT_ID
HIP_MICROSOFT_CLIENT_SECRET
HIP_MICROSOFT_TENANT
```

`HIP_MICROSOFT_TENANT` defaults to `common`. To enable a configured provider,
pass the selected variables into the running Keycloak container and execute:

```sh
/opt/keycloak/bin/hip-configure-federated-providers.sh
```

The script is idempotent, does not print credentials, uses Keycloak's reviewed
first-broker-login flow, imports only verified provider identity data, and does
not grant HIP administration roles.

## Consumer account security

Consumers manage authenticator apps, recovery options, and WebAuthn/passkeys in
the realm account console:

`https://identity.guardwithhip.com/realms/hip/account/`

Local email verification and password recovery must remain disabled until a
protected SMTP sender is configured and tested. Federated providers can assert
provider-verified email addresses without exposing their access tokens to HIP.
