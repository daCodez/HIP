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


<!-- headroom:rtk-instructions -->
# RTK (Rust Token Killer) - Token-Optimized Commands

When running shell commands, **always prefix with `rtk`**. This reduces context
usage by 60-90% with zero behavior change. If rtk has no filter for a command,
it passes through unchanged — so it is always safe to use.

## Key Commands
```bash
# Git (59-80% savings)
rtk git status          rtk git diff            rtk git log

# Files & Search (60-75% savings)
rtk ls <path>           rtk read <file>         rtk grep <pattern>
rtk find <pattern>      rtk diff <file>

# Test (90-99% savings) — shows failures only
rtk pytest tests/       rtk cargo test          rtk test <cmd>

# Build & Lint (80-90% savings) — shows errors only
rtk tsc                 rtk lint                rtk cargo build
rtk prettier --check    rtk mypy                rtk ruff check

# Analysis (70-90% savings)
rtk err <cmd>           rtk log <file>          rtk json <file>
rtk summary <cmd>       rtk deps                rtk env

# GitHub (26-87% savings)
rtk gh pr view <n>      rtk gh run list         rtk gh issue list

# Infrastructure (85% savings)
rtk docker ps           rtk kubectl get         rtk docker logs <c>

# Package managers (70-90% savings)
rtk pip list            rtk pnpm install        rtk npm run <script>
```

## Rules
- In command chains, prefix each segment: `rtk git add . && rtk git commit -m "msg"`
- For debugging, use raw command without rtk prefix
- `rtk proxy <cmd>` runs command without filtering but tracks usage
<!-- /headroom:rtk-instructions -->
