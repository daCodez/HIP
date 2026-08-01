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
without writing them to standard output. It does not provide HIP's managed V1
certificate-signing key custody; that separate launch dependency must remain
fail-closed until an audited managed signer is configured.
