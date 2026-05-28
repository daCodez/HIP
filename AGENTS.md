# HIP Agent Safety Protocol

This repository is the foundation for HIP, the Human Identity Protocol. HIP is not a throwaway prototype; treat changes as production-oriented protocol and platform work.

## Required Safety Steps

Before making changes:

1. Create a Git repository if one does not exist.
2. Create an initial checkpoint commit after the first clean project setup.
3. Do not delete, overwrite, reset, regenerate, or replace files without a clear reason.
4. Make small, testable changes.
5. After each major step, summarize:
   - files changed
   - why each file changed
   - tests run
   - remaining risks

If a risky change is needed, explain it first.

## Engineering Direction

- HIP sits above TCP and TLS: TCP connects, TLS encrypts, HIP verifies trust.
- HIP is the main product. Browser extensions, Second Life HUDs, and other integrations are clients.
- Keep architecture clean, security-first, privacy-first, and testable.
- Prefer small domain concepts with clear explanations over opaque scoring logic.
- A valid signature proves origin and integrity; it does not automatically prove safety.
- Quantum-resistant signing is a first-class design requirement from day one.

## Current Build Priority

1. Solution foundation
2. Core domain models
3. Scoring model
4. Reputation model
5. JSON rules engine
6. Rule simulation engine
7. Public lookup API
8. Live trust badge API
9. Safety page
10. Browser plugin MVP
11. Admin rule builder
12. Second Life HUD
