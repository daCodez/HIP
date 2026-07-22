# HIP Incident Response Runbook

## Priorities

Protect people and private data, stop unauthorized trust decisions, preserve evidence, contain access, restore a known-good service, communicate accurately, and learn without deleting audit history. Do not describe a signature as proof of safety and do not claim post-quantum protection the deployed provider has not demonstrated.

## Severity

- SEV-1: active key/credential compromise, cross-owner or admin authorization bypass, material private-data exposure, signing integrity failure, destructive database event, sandbox escape, or widespread false trust decisions.
- SEV-2: contained credential misuse, provider compromise, sustained public/API outage, queue loss/dead-letter surge, serious poisoning campaign, or restore/rollback failure.
- SEV-3: limited degradation, isolated abuse, bounded provider failure, or control weakness without confirmed exploitation.

Any responder may escalate. The incident commander owns severity, timeline, decisions, and handoffs; security leads containment/evidence; operations owns traffic/workloads/data recovery; product/support owns user impact and approved communications. One person must not both execute and independently approve a critical recovery action.

## First 15 minutes

1. Open an incident record with UTC start time, reporter, symptoms, affected surfaces, and current severity.
2. Assign incident commander, security, operations, communications, and scribe roles.
3. Preserve logs, traces, audit records, image/config digests, database/queue state, and relevant provider metadata. Do not copy secrets or raw private payloads into the incident channel.
4. Stop the bleeding with the smallest reversible control: disable a provider or sandbox runner, revoke a credential, suspend a license/client, block a route at the edge, pause workers, or shift traffic to a known-good artifact.
5. Confirm whether trust scores, signatures, identity, owner isolation, or private data may be incorrect; when uncertain, fail to limited/unknown trust rather than safe.

## Investigation and containment

- Credential/session compromise: revoke the exact credential/session, rotate affected secrets through the secret manager, invalidate descendants, inspect replay/audit evidence, and broaden only if scope is uncertain.
- Signing/encryption/hash key compromise: stop affected signing or writes, preserve key identifiers and timelines, activate the approved replacement, retain legacy decryption only when required, re-sign/reissue where valid, and publish trust-impact guidance.
- Authorization or owner-isolation failure: disable the affected route, preserve request/audit identifiers, test adjacent resource types, and assume data exposure until access logs and object scope prove otherwise.
- Public poisoning or unsafe scores: freeze affected ingestion/automation, downgrade disputed output to limited trust, preserve normalized evidence, quarantine reporters/providers/rules, and require human review before replay.
- SSRF, sandbox escape, or malicious provider: disable execution, isolate workloads/network, revoke workload credentials, preserve container/image/network evidence, and rebuild from a trusted digest rather than reusing the instance.
- Database/Redis/queue incident: stop unsafe writes, capture state/checkpoint, use lease/dead-letter evidence, restore to an isolated target, verify decryption and counts, then perform an approved cutover.

## Communications

State confirmed facts, uncertainty, affected users/surfaces, safe user actions, and next update time. Never publish exploitable detail, secret material, private evidence, or unsupported attribution. Legal/privacy leads determine notification duties and deadlines. Correct prior trust statements promptly if HIP displayed inaccurate status.

## Recovery

Recovery requires independent approval, known-good immutable artifacts, verified secret versions, migration compatibility, health and authorization smoke tests, owner-isolation checks, queue/provider observation, and confirmation that monitoring detects recurrence. Restore traffic gradually. Keep enhanced monitoring through the agreed window and retain containment until evidence supports removal.

## Closure and post-incident review

Document timeline, impact, root and contributing causes, detection gaps, actions, evidence locations, communications, recovery proof, and residual risk. Assign owners and dates for corrective work. Add a regression test or operational detection for the failure mode. Review credential/key rotation, data retention, user notification, threat model, deployment gates, and runbooks. Closure requires security and service-owner approval; unresolved critical risk remains tracked with an expiry.

## Practice schedule

Run tabletop exercises at least twice yearly and after material architecture changes. Include credential theft, cross-owner access, signing-key compromise, poisoned evidence, provider outage, sandbox escape, database restore, and rollback. Record measured detection, containment, recovery, RPO, and RTO rather than marking a checklist complete without evidence.
