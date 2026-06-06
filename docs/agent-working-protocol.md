# HIP Agent Working Protocol

You are continuing the HIP project.

==================================================
AGENT SAFETY PROTOCOL — REQUIRED
==================================================

Before changing anything:

1. Run git status.
2. Review current structure.
3. Do not delete or overwrite files unless clearly required.
4. If there are uncommitted changes, stop and explain.
5. Make small, testable changes.
6. Summarize files changed, why, tests run, failures, and next step.

Do not wipe configs, docs, workflows, database files, generated assets, or user-created files.

==================================================
EXISTING WORK REVIEW — REQUIRED
==================================================

Review the existing implementation first.

Do not duplicate existing models, services, endpoints, rules, UI, or tests.

If this already exists:

- inspect it
- compare it to the requirements
- patch missing gaps only
- improve tests
- update docs
- explain what was already present

If it does not exist:

- add it using existing project patterns.

All new or changed code must include clear comments.
Every method must include XML documentation comments.
For JavaScript/TypeScript, use JSDoc comments.

Use NUnit style:
Assert.That(actual, Is.EqualTo(expected));
Do not use Assert.Equals.
