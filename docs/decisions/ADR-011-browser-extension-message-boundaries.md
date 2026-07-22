# ADR-011: Browser extension messages use closed, sender-bound contracts

Date: 2026-07-20
Status: Accepted

## Context

HIP content scripts observe untrusted pages and send privacy-safe structural
evidence to the extension service worker. Browser isolation prevents a normal
page from calling extension APIs directly, but every cross-context message is
still a trust boundary. Previously, listener branches read message properties
without one complete allow-list, size limit, or sender policy.

## Decision

- Maintain a closed inventory of every service-worker and content-script message
  type. Reject unknown types, extra root properties, unknown contexts, and
  messages from another extension.
- Allow content-originated operations only when Chromium identifies the sender
  as this extension's content script in an HTTP(S) tab. Allow the small popup
  subset only from this extension's own pages.
- Bind page-specific URL origins and domain claims to the sender tab. A content
  script may scan links to other public origins, but it may not claim that its
  own page is another origin.
- Copy accepted data into prototype-free objects, reject pollution keys and
  unsupported values, and cap depth, nodes, arrays, strings, numbers, URLs, and
  total encoded size.
- Apply explicit nested contracts to site-safety evidence, risk findings,
  feedback, and scan-result submissions. Raw risk-report URLs, arbitrary
  metadata, executable URL schemes, embedded URL credentials, and private
  content flags are rejected before API forwarding.
- Bound and prototype-strip service/API results before returning them across an
  extension message boundary. Return stable generic operational errors instead
  of reflecting internal URLs or attacker-controlled input.
- Accept only payload-free refresh and summary commands in the content script.

## Consequences

Adding or changing an extension message now requires an explicit contract and a
focused test. Contract limits may intentionally reject unexpectedly large
provider results; callers should keep popup projections compact. Rollback is a
normal Git revert of the validators, listener wiring, tests, and this record.
