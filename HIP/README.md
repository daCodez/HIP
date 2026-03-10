# 🛡️ Human-Interactive Protocol (HIP)
## Protocol Specification & Vision Statement

## 🔒 License
This project is licensed under the **Apache License 2.0**.

You are free to use, modify, and distribute this protocol implementation for commercial and non-commercial purposes, provided that you include proper attribution and retain the original license.

Contributions are welcome and encouraged under the same terms.
For full details, see the `LICENSE` file in the root of the repository.

---

## 🔍 Vision
The internet has become a battleground of spam, fraud, impersonation, and bot-driven abuse.

Traditional protocols like HTTP, SMTP, and DNS were never designed with identity verification, reputation, or trust built in.

The **Human-Interactive Protocol (HIP)** reimagines online communication by introducing identity-bound, intent-verified, reputation-enforced interactions.

HIP aims to create a safer, smarter internet where users prove who they are, what their intent is, and whether they can be trusted — **before sensitive actions are allowed**.

---

## 🛡️ Mission
To eliminate spam, fraud, and impersonation across internet communications by providing a protocol-level trust layer for messages, forms, API requests, and more.

HIP is:
- ✅ Human-first
- ✅ Identity-secure
- ✅ Privacy-preserving
- ✅ Decentralized-optional
- ✅ Developer-friendly

---

## 👁️ Core Components

### ✨ 1. Verified Identity
Each HIP message is signed with a cryptographic key tied to a verified identity (email, wallet, domain, etc.).

Identities may be optionally registered and validated on-chain using smart contracts or decentralized identifiers (DIDs).

### ⏱️ 2. Intent Tokens
Communications can be wrapped with unique tokens proving sender intent.

These tokens are signed and can be stored/validated to prevent replay attacks and spoofing.

### 🪨 3. Proof-of-Humanity (Optional)
For unknown parties or high-risk contexts, HIP can require a human verification challenge (CAPTCHA, biometric check, social verification, etc.).

### ⬆️ 4. Reputation Layer
A scoring system rates senders based on interaction history, feedback, and abuse detection signals.

Trusted users face less friction.
Abusive behavior triggers stricter controls.

### 💳 5. Optional Cost Layers
HIP can apply proof-of-work or micro-fees to deter mass abuse and spam.

These controls are risk-adjusted and configurable.

### 📁 6. Fraud & Spoofing Defense
Spoofed senders, phishing attempts, replay abuse, and bot patterns are flagged and blocked using identity + policy checks.

---

## ⚖️ Guiding Principles
- Decentralized by design, but compatible with centralized systems
- Free for trusted users; costly only for abusers
- Modular integration with SMTP, HTTP, messaging, and APIs
- Transparent, auditable, and privacy-respecting
- Open source and community-driven

---

## ⚡ Immediate Use Cases
- Email and contact forms
- API requests and webhook protection
- Financial service messaging
- Social media DMs and comments
- E-commerce purchase requests

---

## 🌐 Long-Term Vision
HIP becomes a global trust protocol used by governments, businesses, apps, and users to ensure online interactions are safe, human-verified, and fraud-resistant.

Just like HTTPS became the default for privacy, HIP aims to become the default for trust.

---

## 🧩 Dashboard Widget Notes
HIP includes a simple built-in widget plugin (`core.widget.richard`) that renders a "Richard" widget on the main dashboard for UI verification.

## 📘 Also Read
- `README.humans.md` for plain-English operator guidance
- `scripts/preflight.sh` for deployment preflight checks
- `HIP.Security.README.md` for HIP security simulation scaffold structure and commands

## Simulator Phase 1: Live API Mode (new)

HIP Simulator now supports a third execution mode:
- `application`
- `protocol`
- `live-api`

### Live API mode intent
Use Live API mode to compare simulator-expected outcomes against behavior from a running HIP API system.

### CLI usage
```bash
# Run specific scenario in live API mode
cd /home/jarvis_bot/.openclaw/workspace/HIP

dotnet run --project HIP.Simulator.Cli/HIP.Simulator.Cli.csproj -- run \
  --mode live-api \
  --scenario live-login-impossible-travel \
  --live-base-url http://127.0.0.1:5101
```

Optional:
- `--live-dry-run` to skip outbound live call and still produce comparison structure.

### Scenario contract additions
Scenarios can now include optional live validation fields:
- `expectedHttpStatus`
- `expectedAuditEvent`
- `expectedReputationImpact`

A sample live scenario was added at:
- `HIP.Simulator.Cli/scenarios/authentication/live-login-impossible-travel.json`

## Scenario Generator v1 (template-driven)

New CLI command:

```bash
dotnet run --project HIP.Simulator.Cli/HIP.Simulator.Cli.csproj -- generate-scenarios \
  --templates HIP.Simulator.Cli/threat-templates \
  --campaign auth-attacks \
  --output HIP.Simulator.Cli/scenarios/generated \
  --max 5000 \
  --seed 42
```

Notes:
- Uses template parameter combinations + seeded shuffle.
- Supports campaign scoping (`--campaign <id>` or `all`).
- Output scenarios are simulator-compatible JSON and can be validated with `validate-scenarios`.

Included v1 core templates (10):
- auth brute force
- credential stuffing
- session hijack
- token replay
- messaging spam burst
- phishing link
- device spoofing
- bot automation login
- API flood
- multi-stage takeover chain

### Scenario Generator v1.1 (weighted profiles + taxonomy map)

New generator option:
- `--traffic-profile <balanced|normal-heavy|suspicious-heavy|attack-heavy>`

This sets weighted scenario classes and expected outcomes:
- `normal` -> expected `Allow` / `Info`
- `suspicious` -> expected `Challenge` / `Medium`
- `attack` -> template-defined expected action/severity

Taxonomy mapping file added:
- `HIP.Simulator.Cli/threat-templates/taxonomy-map.json`

Use this map to roll up coverage and drift by framework tags (MITRE/OWASP/NIST).

### Framework coverage rollups in reports

Simulation reports now include framework-level coverage in `Coverage.FrameworkCoverage` when a taxonomy map is available.

Auto-discovery checks:
- `<input>/../../threat-templates/taxonomy-map.json`
- `<input>/../threat-templates/taxonomy-map.json`
- `<input>/taxonomy-map.json`

Each rollup row includes:
- `Framework` (MITRE/OWASP/NIST)
- `Control`
- `Total`
- `Covered`
- `Uncovered`
- `Invalid`
