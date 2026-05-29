(function renderHipTrustBadges() {
  const BADGE_CLASS = "hip-trust-badge";
  const STYLE_ID = "hip-trust-badge-style";
  const scriptOrigin = getScriptOrigin();

  ensureStyles();

  for (const container of document.querySelectorAll(`.${BADGE_CLASS}`)) {
    renderBadge(container).catch(() => renderUnavailable(container));
  }

  async function renderBadge(container) {
    const requestedDomain = normalizeDomain(container.dataset.domain);
    if (!requestedDomain) {
      renderMismatch(container, "Missing badge domain");
      return;
    }

    const hostDomain = normalizeDomain(window.location.hostname);
    if (hostDomain && requestedDomain !== hostDomain) {
      renderMismatch(container, "HIP Badge Domain Mismatch");
      return;
    }

    const apiBase = container.dataset.apiBase || scriptOrigin;
    const response = await fetch(`${apiBase}/api/v1/public/badge/domain/${encodeURIComponent(requestedDomain)}`, {
      method: "GET",
      headers: {
        "Accept": "application/json"
      }
    });

    if (!response.ok) {
      throw new Error(`HIP badge lookup failed with status ${response.status}.`);
    }

    const badge = await response.json();
    if (normalizeDomain(badge.domain) !== requestedDomain) {
      renderMismatch(container, "HIP Badge Domain Mismatch");
      return;
    }

    renderLiveBadge(container, badge, apiBase);
  }

  function renderLiveBadge(container, badge, apiBase) {
    const variant = normalizeVariant(badge.badgeVariant);
    const lookupUrl = new URL(badge.publicLookupUrl || `/lookup/domain/${badge.domain}`, apiBase).toString();
    const checked = badge.lastCheckedUtc ? new Date(badge.lastCheckedUtc).toLocaleDateString() : "Unknown";
    const label = badge.verifiedDomain ? "HIP Verified" : "HIP Warning";

    container.replaceChildren();
    container.classList.add("hip-badge-rendered", `hip-badge-${variant}`);
    container.innerHTML = `
      <a class="hip-badge-card" href="${escapeAttribute(lookupUrl)}" target="_blank" rel="noopener noreferrer">
        <span class="hip-badge-label">${label}</span>
        <strong>Score: ${escapeHtml(badge.score)}/100</strong>
        <span>Status: ${escapeHtml(badge.status)}</span>
        <span>Verified: ${badge.verifiedDomain ? "Yes" : "No"}</span>
        <small>Last checked: ${escapeHtml(checked)}</small>
      </a>
    `;
  }

  function renderMismatch(container, message) {
    container.replaceChildren();
    container.classList.add("hip-badge-rendered", "hip-badge-mismatch");
    container.innerHTML = `
      <a class="hip-badge-card" href="${escapeAttribute(`${scriptOrigin}/lookup`)}" target="_blank" rel="noopener noreferrer">
        <span class="hip-badge-label">HIP Badge Domain Mismatch</span>
        <strong>${escapeHtml(message)}</strong>
        <span>Score: unavailable</span>
        <span>Status: Unknown</span>
      </a>
    `;
  }

  function renderUnavailable(container) {
    container.replaceChildren();
    container.classList.add("hip-badge-rendered", "hip-badge-unknown");
    container.innerHTML = `
      <a class="hip-badge-card" href="${escapeAttribute(`${scriptOrigin}/lookup`)}" target="_blank" rel="noopener noreferrer">
        <span class="hip-badge-label">HIP Unavailable</span>
        <strong>Score: unavailable</strong>
        <span>Status: Unknown</span>
      </a>
    `;
  }

  function ensureStyles() {
    if (document.getElementById(STYLE_ID)) {
      return;
    }

    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
      .hip-trust-badge.hip-badge-rendered {
        display: inline-block;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }
      .hip-trust-badge .hip-badge-card {
        display: inline-grid;
        gap: 2px;
        min-width: 158px;
        padding: 10px 12px;
        color: #111827;
        border: 1px solid #cbd5e1;
        border-left: 5px solid #64748b;
        border-radius: 8px;
        background: #fff;
        box-shadow: 0 6px 16px rgba(15, 23, 42, 0.12);
        text-decoration: none;
        line-height: 1.25;
      }
      .hip-trust-badge .hip-badge-label {
        font-size: 12px;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0;
      }
      .hip-trust-badge strong {
        font-size: 15px;
      }
      .hip-trust-badge span,
      .hip-trust-badge small {
        font-size: 12px;
      }
      .hip-badge-trusted .hip-badge-card { border-left-color: #047857; }
      .hip-badge-probablysafe .hip-badge-card { border-left-color: #0f766e; }
      .hip-badge-caution .hip-badge-card { border-left-color: #ca8a04; }
      .hip-badge-highrisk .hip-badge-card { border-left-color: #ea580c; }
      .hip-badge-dangerous .hip-badge-card,
      .hip-badge-critical .hip-badge-card,
      .hip-badge-mismatch .hip-badge-card { border-left-color: #b91c1c; }
      .hip-badge-unknown .hip-badge-card { border-left-color: #64748b; }
    `;
    document.head.appendChild(style);
  }

  function normalizeDomain(domain) {
    return String(domain || "").trim().replace(/^www\./i, "").toLowerCase();
  }

  function normalizeVariant(variant) {
    return String(variant || "unknown").replace(/[^a-z0-9]/gi, "").toLowerCase() || "unknown";
  }

  function getScriptOrigin() {
    const script = document.currentScript;
    return script?.src ? new URL(script.src).origin : window.location.origin;
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function escapeAttribute(value) {
    return escapeHtml(value);
  }
})();
