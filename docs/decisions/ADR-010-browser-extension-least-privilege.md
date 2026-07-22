# ADR-010: Browser extension host access is user-selected and least-privileged

Date: 2026-07-20
Status: Accepted

## Context

HIP protects arbitrary HTTP and HTTPS pages, so its isolated declarative content
script must observe those pages. That does not justify permanent network access
from the extension service worker to every origin. The worker needs to connect
only to the HIP API and Web hosts selected by the user.

## Decision

- Keep `activeTab`, `scripting`, and `storage`; each has a verified popup,
  recovery-injection, or settings/cache use.
- Keep broad HTTP/HTTPS `content_scripts.matches` because whole-web page and link
  protection is the product function. Do not inject into the page's main world.
- Grant permanent host access only to loopback HTTP origins used by local
  development.
- Declare HTTPS as optional host access and request only the exact configured HIP
  API and Web hosts when the user saves settings. Reject non-loopback HTTP and
  URLs containing credentials.
- Declare no web-accessible resources, externally connectable origins, commands,
  or unused permissions.
- Apply an extension-page CSP with local scripts, styles, and images only; no
  inline or remote code, unsafe evaluation, objects, frames, data URLs, or blob
  execution. HTTPS connections remain subject to the separately granted host
  permission.

Chromium match patterns cannot restrict ports. An exact user-selected permission
therefore covers the selected scheme and hostname on any port.

## Consequences

Production and self-hosted HTTPS deployments require one browser permission
prompt when their HIP host is saved. Existing users upgrading from broad
permanent host access may need to save settings once. Localhost development
continues without a prompt. Rollback is a normal Git revert of the manifest,
permission helper, options flow, tests, and this decision record.
