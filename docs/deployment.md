# HIP Staging and Production Deployment Runbook

This runbook is the controlled path for staging, production, migration, verification, and rollback. Commands and platform syntax vary by deployment target; use immutable artifacts and the target platform's supported secret, database, network, and workload controls.

## Release blockers

Do not deploy to production while any of these are unresolved: non-green required CI checks; unreviewed schema change; missing backup/restore evidence; demo encryption or hashing keys; development authentication; placeholder/development signing represented as production trust; unpinned images; unknown rollback artifact; missing monitoring/alerts; missing incident commander; or live sandbox execution without proven isolation and SSRF/egress controls.

## Required approvals and evidence

- release identifier, commit, SBOM/provenance, and immutable image digests;
- code/security review and acceptance of residual risks in `threat-model.md`;
- staging test evidence, load evidence, database migration review, backup checkpoint, restore-drill date, and rollback rehearsal;
- two-person approval for critical rule, signing, identity, authorization, migration, or key-lifecycle changes;
- named deployer, observer, incident commander, maintenance window, and communication channel.

## Secrets and configuration

Set `DOTNET_ENVIRONMENT=Production` and use PostgreSQL plus Redis through protected connection settings. Configure `HipAuthentication` authority, client ID/secret, role mappings, MFA assurance, idle/absolute session lifetimes, and recent-authentication lifetime as documented in `authentication.md`. Configure strong current record-encryption and privacy-hashing keys through the secret store; legacy keys are read-only rotation inputs and must be bounded and removed after migration evidence. Configure signing keys/providers, external provider keys, OTLP export, allowed origins/hosts, rate limits, and public base URLs through deployment configuration.

Never place secret values in source, image layers, manifests, command arguments, logs, screenshots, tickets, or backup metadata. Workload identity or mounted secret files are preferred. Verify secret presence and version identifiers without printing values. Production must reject missing/demo keys and development authentication.

## Staging deployment

1. Resolve the exact commit and image digests; scan artifacts and dependencies.
2. Confirm staging isolation, DNS, TLS, PostgreSQL, Redis, secret versions, OIDC redirect URIs, provider allowlists, and OTLP destination.
3. Take and verify the pre-migration backup checkpoint.
4. Run reviewed EF migrations as a separate least-privilege job. Application startup must not use `EnsureCreated` or mutate production schema implicitly.
5. Deploy API, Web, provider worker, and sandbox control-plane worker with minimum privileges. Keep browser sandbox execution disabled unless the pinned runner and broker have passed live isolation tests.
6. Verify health/dependency telemetry, Swagger exposure policy, public lookup, signed identity, browser fast score, owner isolation, admin authorization, queue lease processing, license activation, and audit events.
7. Run focused smoke and load scenarios; observe latency, errors, saturation, connection pools, Redis, queue depth, dead letters, and provider failures through a representative soak window.
8. Record evidence and approve promotion. Do not promote a mutable staging tag; promote the same digests.

## Production deployment

1. Announce the change window and freeze unrelated privileged changes.
2. Confirm database backup/checkpoint, restore path, old application digests, old compatible configuration, and the rollback decision owner.
3. Apply backward-compatible schema expansion first. Deploy application instances gradually while monitoring health and error budgets.
4. Verify one instance before widening traffic. Keep old instances until compatibility and session behavior are proven.
5. Run non-mutating smoke checks, then a controlled authenticated operation and confirm its audit event. Never use synthetic feedback writes against shared production data.
6. Observe at least the agreed stabilization window. Close the change only after metrics, queues, providers, auth, and database behavior remain within gates.

## Rollback

Rollback is a new controlled deployment of the previously approved immutable artifacts and compatible configuration; never rewrite Git history or database records. Stop rollout and contain traffic when authentication/authorization fails, data corruption is suspected, secrets leak, migrations fail, error/latency gates breach, queues grow without recovery, or security monitoring detects active abuse.

If the old application is compatible with the expanded schema, route back to the prior digest and retain the schema. Use a reviewed compensating migration only when required. Never restore an old database over the current production database as an ordinary application rollback. For corruption or destructive migration, enter incident response, preserve evidence, stop writes, and restore to a separately verified target before an approved cutover.

After rollback, verify health, authentication, public lookup, owner isolation, queue processing, and audit continuity; revoke any exposed credentials; record the decision and open follow-up work. Do not automatically retry the failed release.

## Post-deployment record

Record timestamps, actors/approvers, commit and digests, configuration/key version identifiers, migration versions, backup reference, smoke/load results, telemetry links, deviations, rollback status, and incident/follow-up IDs. Store the record in the operations audit system without secret values.
