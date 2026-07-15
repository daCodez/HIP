# HIP Repository Agent Guide

HIP is the Human Identity Protocol. Treat changes as production-oriented protocol and platform work, not as throwaway prototype work.

## Before Making Changes

1. Inspect the repository status and read the relevant documentation, source files, and tests.
2. Preserve existing and uncommitted user work. Do not discard, stage, commit, or rewrite unrelated changes.
3. Make the smallest coherent change that satisfies the request, and keep it testable.
4. Get user approval before destructive or difficult-to-reverse actions, including:
   - deleting substantial files or data;
   - resetting or rewriting Git history;
   - overwriting user work;
   - applying migrations that may lose data; or
   - changing external or production systems.
5. Explain material security, privacy, compatibility, or data-migration risk before taking the risky action.

## Working and Handoff Expectations

- For substantial work, provide concise progress updates at meaningful milestones.
- Run the most relevant tests and checks for the changed behavior. If a relevant check cannot be run, say why.
- Review the final diff for accidental or unrelated changes.
- In the final handoff, summarize:
  - files changed and why;
  - tests and checks run;
  - known limitations or remaining risks.

## Engineering Direction

- HIP is an application-layer trust protocol and platform. TCP provides connectivity, TLS protects transport, and HIP adds identity, origin, integrity, reputation, and risk evidence.
- HIP is the main product. Browser extensions, Second Life HUDs, and other integrations are HIP clients.
- Keep architecture clean, security-first, privacy-first, and testable.
- Prefer small domain concepts and explainable decisions over opaque scoring logic.
- A valid signature proves origin and integrity; it does not by itself prove safety or trustworthiness.
- Preserve cryptographic agility so HIP can migrate to audited post-quantum algorithms and providers.
- Do not describe the current development signing provider as production-safe or post-quantum-ready unless the implementation and evidence support that claim.
- Treat all client, network, provider, scan, and user-supplied data as untrusted.
- Collect and retain only the minimum privacy-safe data required for the feature.
- Keep secrets, credentials, private page contents, raw user content, and sensitive identifiers out of logs, public APIs, and test fixtures.

## Architecture and Compatibility

- Keep domain rules independent from UI, persistence, hosting, and third-party provider details.
- Preserve versioned public API and client contracts unless the task explicitly includes a migration or breaking change.
- Keep providers as evidence sources; providers must not directly decide the final HIP score.
- Keep browser extensions, Second Life HUDs, and other clients thin. Shared trust and scoring behavior belongs in HIP services and domain logic.
- Use **browser extension** for the client name. Retain existing `BrowserPlugin` identifiers only where changing them would break a public or compatibility-sensitive contract.

## Current Priorities

Do not copy a changing roadmap into this file. Determine current scope from the user's request, the current implementation, and the maintained project reference documents under `docs/project-reference/`. Verify that a referenced plan still matches the code before treating it as current.
