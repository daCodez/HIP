# HIP VPS deployment

The files in this directory are the reviewable deployment source for the current
HIP VPS topology. `compose.private-staging.yml` is a staging baseline; its name
is deliberate and it must not be represented as a V1 production release until
the production-readiness gates in `docs/current-state-gap-map.md` are closed.

For a production candidate, merge the fail-closed environment and proxy
hardening in `compose.production.override.yml`:

```sh
docker compose \
  -f deploy/vps/compose.private-staging.yml \
  -f deploy/vps/compose.production.override.yml \
  config --quiet
```

The override removes Development authentication from every public application
process. It intentionally does not enable browser sandbox execution or a
development signing key; those features remain unavailable until their V1
isolation and managed-key gates are satisfied.

## Release provenance

HIP application, worker, identity, and infrastructure images are pinned to
reviewed image manifests. Application-built images also carry the standard OCI
source, revision, and version labels.

Generate those non-secret build values only from a clean Git checkout:

```sh
eval "$(sh deploy/vps/release-metadata.sh 1.0.0)"
export HIP_RELEASE_REVISION HIP_RELEASE_VERSION
```

The script refuses staged, modified, or untracked source. Do not bypass that
check by copying an assembled directory to the server. The deployed revision,
version, compose file, and protected environment file must identify one release
and must be retained together for rollback. Compose tags every HIP-built image
with the full release revision. Retain the current and previously approved
revision tags until the stabilization window and authenticated rollback checks
have passed; a floating `latest` tag is not a rollback artifact.

## Protected configuration

Runtime credentials and key material belong in the root-owned deployment
environment and mounted secret files, never in Git. Before a rollout:

1. confirm the environment file is mode `0600` and contains every required
   variable without printing the values;
2. validate the compose model with `docker compose config --quiet`;
3. back up PostgreSQL, the identity database, and the protected key metadata;
4. build every HIP-owned image from the same clean revision;
5. inspect image revision/version labels and container health before promotion;
6. retain the prior complete release until rollback and sign-in checks pass.

`provision-identity-secrets.sh` creates missing staging identity/session secrets
without writing them to standard output. Certificate signing is configured
separately through the managed-signer provider boundary described below.

## Managed signing launch gate

The VPS composition requires an explicit `HIP_SIGNING_ISSUER_ID` and
`HIP_SIGNING_KEY_ID` and selects the `SoftHsm` starter provider. The Production
consumer host enables the startup readiness gate; the production override
enables it for every public HIP host. A gated host fails startup unless the
token, PIN file, exact configured ML-DSA-65 key, explicit allowlists, platform
verifier, and durable public lifecycle state all agree.

The readiness check never requests private key material or persists a signed
document. The SoftHSM adapter additionally signs and verifies a fixed
non-document challenge so a broken PKCS #11 signing path fails before traffic is
accepted. It generates a non-exportable ML-DSA-65 key only when the explicitly
selected key is absent, serializes initial provisioning across HIP hosts, and
stores only the public key in HIP's database.

The same selected provider also supplies one non-exportable ML-DSA-65 key per
new website identity. HIP derives a stable, privacy-safe token label from the
identity and lifecycle key identifiers, persists only the public key, and never
returns provider-managed private material to the browser.

Set these host paths in the protected deployment environment:

```text
HIP_SOFTHSM_TOKEN_PATH=/opt/hip/shared/softhsm
HIP_SOFTHSM_USER_PIN_PATH=/opt/hip/shared/secrets/softhsm-user-pin
HIP_SOFTHSM_SO_PIN_PATH=/opt/hip/shared/secrets/softhsm-so-pin
```

After building the production images and before the first production `up`, run:

```sh
./deploy/vps/provision-softhsm.sh
```

The script is idempotent, does not print either PIN, initializes only a missing
`hip-signing` token, and leaves ML-DSA key generation to HIP's fail-closed
provider. Back up the token directory and Security Officer PIN separately before
issuance. Losing either the token data or all recovery material makes the signing
key unrecoverable.

SoftHSM is software-backed starter custody on the existing VPS. It must not be
described as a hardware HSM, independently managed custody, or an audited
production trust root. The `IManagedTrustReceiptSigner` boundary remains the
replacement point for a managed HSM or remote signing service; such a promotion
still requires rotation, revocation, access-control, audit-log, outage, and
recovery evidence. Do not weaken or disable the gate to promote a V1 release.

The HIP runtime images compile pinned OpenSSL 3.5 and SoftHSM source revisions
because the base distribution's OpenSSL 3.0 and the SoftHSM 2.7.0 release do not
provide the required PKCS #11 ML-DSA implementation. Both revisions are verified
during the image build, and the build fails unless SoftHSM reports ML-DSA support.
