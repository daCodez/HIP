# HIP (Human-Friendly Guide)

This file explains HIP in plain English.

## What HIP is
HIP is a **safety gate** in front of actions.

Before an action is allowed, HIP asks 3 simple questions:
1. **Who is asking?** (identity)
2. **How much do we trust them right now?** (reputation)
3. **Is this action risky?** (policy)

Then HIP returns one of 3 outcomes:
- **allow** = go ahead
- **review** = pause and check
- **block** = do not run

---

## Why this exists
Without HIP, a system can run unsafe actions too easily.
HIP reduces that risk by making decisions explainable and consistent.

---

## The “decision trace” (the receipt)
Every policy decision now includes a small receipt called `decisionTrace`.

It tells you:
- if identity was found
- reputation score and factors
- policy code + version used
- final reason for allow/review/block

Think of it like a checkout receipt for security decisions.

Example (simplified):
```json
{
  "decision": "block",
  "policyCode": "policy.uncertainContext",
  "policyVersion": "default-v1",
  "decisionTrace": {
    "identityExists": false,
    "reputationScore": 14,
    "toolAccessReason": "uncertain_context"
  }
}
```

Matching audit event (simplified):
```text
eventType=jarvis.policy.evaluate
outcome=block
reasonCode=policy.uncertainContext
detail=decision=block;risk=high;policyVersion=default-v1;identityExists=False;reputationScore=14
```

---

## High-risk default safety rule
For **high-risk** requests, if HIP is missing key context (identity/reputation uncertainty),
it **blocks by default**.

In logs/results this appears as:
- `policyCode: policy.uncertainContext`

This is intentional safety behavior.

---

## Reputation in simple terms
Reputation is a trust score from 0–100.

- Good signals increase trust over time.
- Bad security events reduce trust.
- Recent bad events count more than old ones (time decay).

So trust can recover over time if behavior improves.

---

## Policy versions
HIP policy decisions include a version label (example: `default-v1`).

This helps answer: **“Which rule set made this decision?”**

---

## If something is blocked, what to check
1. Check `policyCode` (why blocked)
2. Check `decisionTrace` (identity + score + reason)
3. Confirm identity exists and is valid
4. Confirm request risk level is correct
5. Retry only after fixing the root cause

---

## Quick glossary (non-technical)
- **Identity**: who is making the request
- **Reputation**: trust score for that identity
- **Policy**: rules that decide allow/review/block
- **Audit**: historical log of what happened
- **Decision trace**: explanation snapshot for one decision

---

If you want, this file can be expanded into:
- “Operator playbook” (step-by-step responses)
- “FAQ for non-engineers”
- “Incident checklist” for blocked/high-risk events
