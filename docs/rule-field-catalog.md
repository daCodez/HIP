# HIP rule field and operator catalog

Last verified: 2026-07-20

HIP-0402 uses one immutable catalog for admin-rule validation, version-schema
mapping, and condition evaluation. A field absent from this catalog is not
available to rules. Raw page text, passwords, form values, cookies, tokens,
messages, and private content are intentionally absent.

| Field type | Fields | Allowed operators |
|---|---|---|
| String | `Domain`, `Tld` | `equals`, `notEquals`, `contains`, `startsWith`, `endsWith`, `in` |
| Boolean | `HasHttps`, `HasLoginForm`, `HasPasswordField`, `HasPaymentField` | `equals`, `notEquals` |
| Integer | redirect, link, script, download, abuse-report, and reputation counts/scores | equality, ordered comparison, `in` |
| String collection | `MatchedRiskTerms` | `contains`, `containsAny` |
| Enum collection | `ProviderEvidenceType`, `ProviderEvidenceStatus` | `contains`, `containsAny` |

Validation rules:

- Field lookup is case-insensitive, then evaluation and `hip-rule/1` mapping use
  the canonical catalog name.
- Boolean, integer, string, and list JSON shapes must match the field type.
- Null, undefined, empty lists, mixed-type lists, non-32-bit integers, control
  characters, strings over 160 characters, and lists over 64 values are rejected.
- Unsupported enum values and operators incompatible with the field type are
  rejected before simulation or evaluation.
- Compatibility operators `greaterThanOrEqual`, `lessThanOrEqual`, and
  `containsAny` remain supported where type-safe. The `hip-rule/1` mapper emits
  stable lower-camel operator names.

The catalog is an allow-list and a public rule-authoring compatibility boundary.
Adding a field requires a privacy review, a typed source value, evaluator support,
and focused positive and adversarial tests.
