(function renderHipTrustBadges() {
  const BADGE_CLASS = "hip-trust-badge";
  const STYLE_ID = "hip-trust-badge-style";
  const scriptOrigin = getScriptOrigin();
  let badgeInstance = 0;

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
    const response = await fetch(`${apiBase}/api/v1/badge/${encodeURIComponent(requestedDomain)}`, {
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

    await verifySignedBadge(badge, requestedDomain, apiBase);

    renderLiveBadge(container, badge, apiBase);
  }

  async function verifySignedBadge(badge, requestedDomain, apiBase) {
    const signed = badge && badge.signedBadge;
    const payload = signed && signed.payload;
    const expiresAt = payload && Date.parse(payload.expiresAtUtc);
    const certificate = badge && badge.certificate;
    const signedCertificate = payload && payload.certificate;
    const certificateMatches = (!certificate && !signedCertificate) ||
      (certificate && signedCertificate &&
       certificate.certificateId === signedCertificate.certificateId &&
       normalizeDomain(certificate.domain) === requestedDomain &&
       certificate.domain === signedCertificate.domain &&
       certificate.level === signedCertificate.level &&
       certificate.status === signedCertificate.status &&
       certificate.signatureStatus === signedCertificate.signatureStatus &&
       certificate.expiresAtUtc === signedCertificate.expiresAtUtc &&
       certificate.publicCertificateUrl === signedCertificate.publicCertificateUrl &&
       certificate.isActive === signedCertificate.isActive);
    if (!badge || badge.isAvailable !== true || badge.signatureStatus !== "Verified" ||
        !signed || !payload || !signed.signature ||
        payload.documentType !== "hip-live-badge" || payload.version !== "1.0" ||
        normalizeDomain(payload.domain) !== requestedDomain ||
        payload.score !== badge.score || payload.status !== badge.status ||
        payload.displayScore !== badge.displayScore ||
        payload.scorePresentation !== badge.scorePresentation ||
        payload.evidenceCoverage !== badge.evidenceCoverage ||
        payload.evidenceConfidence !== badge.evidenceConfidence ||
        payload.verifiedDomain !== badge.verifiedDomain ||
        payload.identityVerificationStatus !== badge.identityVerificationStatus ||
        payload.verifiedMeaning !== badge.verifiedMeaning || !certificateMatches ||
        (certificate?.isActive === true && (certificate.status !== "Active" || certificate.signatureStatus !== "Verified")) ||
        !Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      throw new Error("HIP badge signature state is unavailable or inconsistent.");
    }

    const response = await fetch(`${apiBase}/api/v1/badge/verify`, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(signed)
    });
    if (!response.ok) {
      throw new Error(`HIP badge verification failed with status ${response.status}.`);
    }

    const result = await response.json();
    if (!result || result.isVerified !== true || result.status !== "Verified") {
      throw new Error("HIP badge signature did not verify.");
    }
  }

  function renderLiveBadge(container, badge, apiBase) {
    const certificate = badge.certificate;
    const active = certificate && certificate.isActive === true &&
      normalizeDomain(certificate.domain) === normalizeDomain(badge.domain);
    const variant = normalizeVariant(certificate ? (active ? certificate.level : certificate.status) : "unknown");
    const lookupUrl = new URL(certificate?.publicCertificateUrl || badge.publicLookupUrl || `/lookup/domain/${badge.domain}`, apiBase).toString();
    const checked = badge.lastCheckedUtc ? new Date(badge.lastCheckedUtc).toLocaleDateString() : "Unknown";
    const identityStatus = badge.identityVerificationStatus === "Verified" ? "Verified" : badge.identityVerificationStatus === "Pending" ? "Pending" : "Unverified";
    const label = active && identityStatus === "Verified"
      ? "HIP Identity Verified"
      : active
        ? "HIP Identity Pending"
        : certificate ? `HIP ${certificate.status}` : "HIP Identity Unverified";
    const safetyAssessment = badge.scorePresentation === "Available" && badge.displayScore !== null && badge.displayScore !== undefined && Number.isFinite(Number(badge.displayScore))
      ? `<span class="hip-badge-fact"><b>Safety score</b>${escapeHtml(badge.displayScore)}/100 (${escapeHtml(badge.status)})</span>`
      : '<span class="hip-badge-fact"><b>Safety assessment</b>Not enough evidence yet</span>';
    const panelId = `hip-badge-panel-${++badgeInstance}`;

    container.replaceChildren();
    container.classList.add("hip-badge-rendered", `hip-badge-${variant}`);
    container.innerHTML = `
      <div class="hip-badge-widget" data-hip-state="expanded">
        <button type="button" class="hip-badge-shield" data-hip-action="toggle" aria-label="Minimize HIP trust details" aria-expanded="true" aria-controls="${escapeAttribute(panelId)}">
          ${shieldMarkup()}
        </button>
        <section id="${escapeAttribute(panelId)}" class="hip-badge-panel" aria-label="${escapeAttribute(label)} for ${escapeAttribute(badge.domain)}">
          <div class="hip-badge-toolbar">
            <strong class="hip-badge-label">${escapeHtml(label)}</strong>
            <span class="hip-badge-controls">
              <button type="button" data-hip-action="minimize" aria-label="Minimize HIP badge" title="Minimize">−</button>
              <button type="button" data-hip-action="close" aria-label="Close HIP badge" title="Close">×</button>
            </span>
          </div>
          <span class="hip-badge-fact"><b>Certificate</b>${escapeHtml(certificate?.status || "Not issued")} · ${escapeHtml(certificate?.level || "None")}</span>
          <span class="hip-badge-fact"><b>Identity</b>${escapeHtml(identityStatus)}</span>
          <span class="hip-badge-fact"><b>Evidence</b>${escapeHtml(badge.evidenceCoverage || "Insufficient")} · ${escapeHtml(badge.evidenceConfidence || "None")} confidence</span>
          ${safetyAssessment}
          <small>Last checked: ${escapeHtml(checked)}</small>
          <small>Identity verification does not automatically mean safe.</small>
          <a class="hip-badge-details" href="${escapeAttribute(lookupUrl)}" target="_blank" rel="noopener noreferrer">View HIP details</a>
        </section>
        <button type="button" class="hip-badge-show" data-hip-action="show" aria-controls="${escapeAttribute(panelId)}" hidden>Show HIP</button>
      </div>
    `;
    initializeWidget(container);
  }

  /**
   * Wires accessible expanded, minimized, and closed states without storing visitor data.
   */
  function initializeWidget(container) {
    const widget = container.querySelector(".hip-badge-widget");
    const panel = widget?.querySelector(".hip-badge-panel");
    const shield = widget?.querySelector(".hip-badge-shield");
    const show = widget?.querySelector(".hip-badge-show");
    const minimize = widget?.querySelector('[data-hip-action="minimize"]');
    const close = widget?.querySelector('[data-hip-action="close"]');
    if (!widget || !panel || !shield || !show || !minimize || !close) {
      throw new Error("HIP badge controls are unavailable.");
    }

    const setState = (state, focusTarget) => {
      widget.dataset.hipState = state;
      const expanded = state === "expanded";
      panel.hidden = !expanded;
      show.hidden = expanded;
      shield.hidden = state === "closed";
      shield.setAttribute("aria-expanded", String(expanded));
      shield.setAttribute("aria-label", expanded ? "Minimize HIP trust details" : "Show HIP trust details");
      if (focusTarget) {
        focusTarget.focus();
      }
    };

    shield.addEventListener("click", () =>
      setState(widget.dataset.hipState === "expanded" ? "minimized" : "expanded"));
    minimize.addEventListener("click", () => setState("minimized", show));
    close.addEventListener("click", () => setState("closed", show));
    show.addEventListener("click", () => setState("expanded", minimize));
  }

  /**
   * Returns the transparent HIP protocol shield used by the floating badge.
   */
  function shieldMarkup() {
    return '<svg class="hip-badge-shield-logo" viewBox="0 0 256 256" aria-hidden="true" focusable="false"><path d="M128 18 214 52v67c0 55-33 96-86 116-53-20-86-61-86-116V52z" fill="#0d1918"/><path d="M87 83v91M169 83v91M87 128h82" fill="none" stroke="#eff8f6" stroke-width="13" stroke-linecap="round"/><path d="M87 102 67 89M169 102l20-13M128 128V74M128 128v67" stroke="#5ad7bb" stroke-width="7" stroke-linecap="round"/><g fill="#5ad7bb"><circle cx="62" cy="86" r="8"/><circle cx="194" cy="86" r="8"/><circle cx="128" cy="68" r="8"/><circle cx="128" cy="201" r="8"/></g></svg>';
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
        --hip-accent: #5ad7bb;
        position: fixed !important;
        right: max(1rem, env(safe-area-inset-right)) !important;
        bottom: max(1rem, env(safe-area-inset-bottom)) !important;
        z-index: 2147483000 !important;
        display: block !important;
        width: auto !important;
        max-width: calc(100vw - 2rem) !important;
        margin: 0 !important;
        padding: 0 !important;
        background: transparent !important;
        border: 0 !important;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif !important;
        color: #f8fafc !important;
      }
      .hip-trust-badge .hip-badge-widget {
        display: grid;
        justify-items: end;
        gap: .5rem;
        background: transparent;
      }
      .hip-trust-badge .hip-badge-panel[hidden],
      .hip-trust-badge .hip-badge-shield[hidden],
      .hip-trust-badge .hip-badge-show[hidden] { display: none !important; }
      .hip-trust-badge .hip-badge-shield {
        all: unset;
        box-sizing: border-box;
        width: 4.25rem;
        height: 4.25rem;
        cursor: pointer;
        filter: drop-shadow(0 .4rem .65rem rgba(2, 8, 23, .38));
        transition: transform .16s ease, filter .16s ease;
      }
      .hip-trust-badge .hip-badge-shield:hover { transform: translateY(-.125rem); }
      .hip-trust-badge .hip-badge-shield-logo { display: block; width: 100%; height: 100%; }
      .hip-trust-badge .hip-badge-panel {
        box-sizing: border-box;
        display: grid;
        gap: .5rem;
        width: min(22rem, calc(100vw - 2rem));
        max-height: calc(100vh - 7rem);
        overflow: auto;
        padding: .875rem;
        color: #f8fafc;
        border: 1px solid rgba(148, 163, 184, .42);
        border-left: .25rem solid var(--hip-accent);
        border-radius: .75rem;
        background: rgba(7, 18, 34, .82);
        box-shadow: 0 .75rem 2rem rgba(2, 8, 23, .28);
        backdrop-filter: blur(1rem) saturate(130%);
        -webkit-backdrop-filter: blur(1rem) saturate(130%);
        line-height: 1.35;
      }
      .hip-trust-badge .hip-badge-toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: .75rem;
      }
      .hip-trust-badge .hip-badge-label {
        font-size: .8125rem;
        font-weight: 800;
        letter-spacing: .02em;
        text-transform: uppercase;
      }
      .hip-trust-badge .hip-badge-controls { display: inline-flex; gap: .25rem; }
      .hip-trust-badge .hip-badge-controls button,
      .hip-trust-badge .hip-badge-show {
        all: unset;
        box-sizing: border-box;
        cursor: pointer;
        color: #f8fafc;
        border: 1px solid rgba(148, 163, 184, .55);
        background: rgba(15, 23, 42, .4);
      }
      .hip-trust-badge .hip-badge-controls button {
        display: inline-grid;
        place-items: center;
        width: 2rem;
        height: 2rem;
        border-radius: .375rem;
        font-size: 1.125rem;
        line-height: 1;
      }
      .hip-trust-badge .hip-badge-show {
        padding: .5rem .75rem;
        border-radius: 999px;
        font: 700 .75rem/1 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        backdrop-filter: blur(.75rem);
      }
      .hip-trust-badge .hip-badge-controls button:hover,
      .hip-trust-badge .hip-badge-show:hover { background: rgba(30, 41, 59, .72); }
      .hip-trust-badge button:focus-visible,
      .hip-trust-badge a:focus-visible { outline: .1875rem solid #67e8f9; outline-offset: .1875rem; }
      .hip-trust-badge .hip-badge-fact {
        display: grid;
        grid-template-columns: 7rem minmax(0, 1fr);
        gap: .5rem;
        font-size: .8125rem;
      }
      .hip-trust-badge .hip-badge-fact b { color: #a7f3d0; font-weight: 700; }
      .hip-trust-badge small { color: #cbd5e1; font-size: .75rem; }
      .hip-trust-badge .hip-badge-details {
        justify-self: start;
        color: #67e8f9;
        font-size: .8125rem;
        font-weight: 700;
        text-underline-offset: .1875rem;
      }
      .hip-trust-badge .hip-badge-card {
        display: grid;
        gap: .25rem;
        padding: .75rem;
        color: #f8fafc;
        border: 1px solid rgba(148, 163, 184, .42);
        border-radius: .75rem;
        background: rgba(7, 18, 34, .82);
        text-decoration: none;
        backdrop-filter: blur(1rem);
      }
      .hip-badge-dangerous, .hip-badge-critical, .hip-badge-mismatch { --hip-accent: #fb7185 !important; }
      .hip-badge-highrisk, .hip-badge-suspended, .hip-badge-renewalrequired { --hip-accent: #fb923c !important; }
      .hip-badge-caution { --hip-accent: #fbbf24 !important; }
      .hip-badge-unknown, .hip-badge-expired { --hip-accent: #94a3b8 !important; }
      @media (max-width: 30rem) {
        .hip-trust-badge .hip-badge-panel { width: calc(100vw - 2rem); max-height: calc(100vh - 6rem); }
        .hip-trust-badge .hip-badge-fact { grid-template-columns: 1fr; gap: .125rem; }
      }
      @media (prefers-reduced-motion: reduce) {
        .hip-trust-badge, .hip-trust-badge * { transition: none !important; animation: none !important; }
      }
    `;
    document.head.appendChild(style);
  }
  function normalizeDomain(domain) {
    return String(domain || "").trim().replace(/\.$/, "").toLowerCase();
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
