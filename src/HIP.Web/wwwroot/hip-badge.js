(function renderHipTrustBadges() {
  "use strict";

  const STYLE_ID = "hip-trust-badge-style-v3";
  const DEFAULT_OPACITY = 82;
  const scriptOrigin = getScriptOrigin();
  let badgeInstance = 0;

  ensureStyles();
  for (const container of document.querySelectorAll(".hip-trust-badge, [data-hip-badge]")) {
    if (container.dataset.hipInitialized === "true") continue;
    container.dataset.hipInitialized = "true";
    renderBadge(container).catch(() => renderUnavailable(container, "Unable to verify"));
  }

  async function renderBadge(container) {
    const requestedDomain = normalizeDomain(container.dataset.domain || container.dataset.hipBadge);
    const hostDomain = normalizeDomain(window.location.hostname);
    const apiBase = safeApiBase();
    applyConfiguration(container);

    if (!requestedDomain || !sameHostname(requestedDomain, hostDomain)) {
      renderUnavailable(container, "Domain mismatch");
      return;
    }

    const response = await fetch(`${apiBase}/api/v1/badge/${encodeURIComponent(requestedDomain)}`, {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      headers: { "Accept": "application/json" }
    });
    if (!response.ok) throw new Error("HIP badge lookup failed.");

    const badge = await response.json();
    if (normalizeDomain(badge?.domain) !== requestedDomain) {
      renderUnavailable(container, "Domain mismatch");
      return;
    }

    await verifySignedBadge(badge, requestedDomain, apiBase);
    renderLiveBadge(container, badge, apiBase);
  }

  async function verifySignedBadge(badge, requestedDomain, apiBase) {
    const signed = badge?.signedBadge;
    const payload = signed?.payload;
    const certificate = badge?.certificate;
    const signedCertificate = payload?.certificate;
    const badgeExpires = Date.parse(payload?.expiresAtUtc);
    const certificateExpires = Date.parse(certificate?.expiresAtUtc);
    const certificateMatches = certificate && signedCertificate &&
      certificate.certificateId === signedCertificate.certificateId &&
      normalizeDomain(certificate.domain) === requestedDomain &&
      certificate.domain === signedCertificate.domain &&
      certificate.level === signedCertificate.level &&
      certificate.status === signedCertificate.status &&
      certificate.signatureStatus === signedCertificate.signatureStatus &&
      certificate.expiresAtUtc === signedCertificate.expiresAtUtc &&
      certificate.publicCertificateUrl === signedCertificate.publicCertificateUrl &&
      certificate.isActive === signedCertificate.isActive;

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
        certificate.signatureStatus !== "Verified" ||
        !Number.isFinite(badgeExpires) || badgeExpires <= Date.now() ||
        (certificate.isActive === true && (!Number.isFinite(certificateExpires) || certificateExpires <= Date.now()))) {
      throw new Error("HIP badge proof is unavailable or inconsistent.");
    }

    const response = await fetch(`${apiBase}/api/v1/badge/verify`, {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      headers: { "Accept": "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(signed)
    });
    if (!response.ok) throw new Error("HIP badge signature verification failed.");
    const result = await response.json();
    if (result?.isVerified !== true || result?.status !== "Verified") {
      throw new Error("HIP badge signature did not verify.");
    }
  }

  function renderLiveBadge(container, badge, apiBase) {
    const state = displayState(badge);
    const score = badge.certificate?.isActive === true && badge.scorePresentation === "Available" && Number.isFinite(Number(badge.displayScore))
      ? String(badge.displayScore)
      : "-";
    const panelId = `hip-trust-panel-${++badgeInstance}`;
    const tooltipId = `${panelId}-status`;
    const label = `HIP ${state.label} for ${badge.domain}. Score ${score} out of 100. Open trust details.`;

    container.replaceChildren();
    container.classList.add("hip-trust-badge", "hip-badge-rendered", `hip-state-${state.key}`);
    container.innerHTML = `
      <div class="hip-badge-anchor">
        <button type="button" class="hip-badge-card" aria-label="${escapeAttribute(label)}" aria-describedby="${tooltipId}" aria-expanded="false" aria-controls="${panelId}">
          <span class="hip-badge-mark" aria-hidden="true">${shieldMarkup()}</span>
          <span class="hip-badge-copy"><small>Protected by</small><strong>HIP</strong></span>
          <span class="hip-badge-divider" aria-hidden="true"></span>
          <strong class="hip-badge-score" aria-label="Score ${escapeAttribute(score)} out of 100">${escapeHtml(score)}</strong>
        </button>
        <section id="${panelId}" class="hip-trust-panel" aria-label="HIP trust information" hidden>
          <p class="hip-panel-loading" role="status">Checking the live HIP certificate…</p>
        </section>
        <span id="${tooltipId}" class="hip-badge-tooltip" role="tooltip"><strong>${escapeHtml(state.label)}</strong>: ${escapeHtml(stateMeaning(state.key))}</span>
      </div>`;

    const button = container.querySelector(".hip-badge-card");
    const panel = container.querySelector(".hip-trust-panel");
    button.addEventListener("click", () => togglePanel(container, button, panel, badge, apiBase));
    document.addEventListener("pointerdown", event => {
      if (!panel.hidden && !container.contains(event.target)) closePanel(button, panel);
    });
    document.addEventListener("keydown", event => {
      if (event.key === "Escape" && !panel.hidden) {
        closePanel(button, panel);
        button.focus();
      }
    });
    scheduleOverlapAvoidance(container);
  }

  async function togglePanel(container, button, panel, badge, apiBase) {
    if (!panel.hidden) {
      closePanel(button, panel);
      return;
    }
    panel.hidden = false;
    button.setAttribute("aria-expanded", "true");
    panel.innerHTML = '<p class="hip-panel-loading" role="status">Checking the live HIP certificate…</p>';
    positionPanel(container, panel);

    try {
      const certificateId = badge.certificate.certificateId;
      const response = await fetch(`${apiBase}/api/v1/public/certificates/${encodeURIComponent(certificateId)}`, {
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        headers: { "Accept": "application/json" }
      });
      if (!response.ok) throw new Error("Certificate lookup failed.");
      const certificate = await response.json();
      assertCertificate(certificate, badge);
      renderCertificatePanel(panel, certificate, badge, apiBase);
      positionPanel(container, panel);
    } catch {
      panel.innerHTML = `
        <header class="hip-panel-header"><div><small>HIP certificate details</small><strong>Details temporarily unavailable</strong></div><button type="button" class="hip-panel-close" aria-label="Close trust details">×</button></header>
        <p class="hip-panel-warning">HIP could not load the detailed certificate view. The signed badge summary above remains unchanged.</p>
        <p class="hip-panel-note">HIP does not replace TLS. TLS protects the connection; HIP adds identity and policy evidence.</p>`;
      wireClose(panel, button);
    }
  }

  function assertCertificate(certificate, badge) {
    const payload = certificate?.signedCertificate?.payload;
    if (!payload || certificate.signatureStatus !== "Verified" ||
        payload.certificateId !== badge.certificate.certificateId ||
        normalizeDomain(payload.domain) !== normalizeDomain(badge.domain) ||
        payload.level !== badge.certificate.level ||
        certificate.currentStatus !== badge.certificate.status ||
        payload.expiresAtUtc !== badge.certificate.expiresAtUtc ||
        (certificate.isActive === true && Date.parse(payload.expiresAtUtc) <= Date.now())) {
      throw new Error("Certificate identity or state mismatch.");
    }
  }

  function renderCertificatePanel(panel, certificate, badge, apiBase) {
    const payload = certificate.signedCertificate.payload;
    const methods = Array.isArray(payload.completedVerificationMethods) ? payload.completedVerificationMethods : [];
    const findings = Array.isArray(payload.publicFindingCodes) ? payload.publicFindingCodes : [];
    const publisher = payload.publicOrganizationName || payload.publicDisplayName;
    const score = certificate.isActive === true && Number.isFinite(Number(badge.displayScore)) && badge.scorePresentation === "Available" ? `${badge.displayScore}/100` : "Not published";
    const certificateUrl = safePublicUrl(payload.publicCertificateUrl, apiBase);
    const strengths = methods.length ? methods.map(value => `<li>${escapeHtml(readable(value))}</li>`).join("") : "<li>Current HIP certificate signature verified</li>";
    const warnings = findings.length ? findings.map(value => `<li>${escapeHtml(readable(value))}</li>`).join("") : "<li>No current public warnings</li>";

    panel.innerHTML = `
      <header class="hip-panel-header">
        <div><small>${escapeHtml(payload.domain)}</small><strong>HIP ${escapeHtml(payload.level)}</strong></div>
        <button type="button" class="hip-panel-close" aria-label="Close trust details">×</button>
      </header>
      ${publisher ? `<p class="hip-panel-publisher">${escapeHtml(publisher)}</p>` : ""}
      <dl class="hip-panel-facts">
        <div><dt>Status</dt><dd>${escapeHtml(certificate.currentStatus)}</dd></div>
        <div><dt>Score</dt><dd>${escapeHtml(score)}</dd></div>
        <div><dt>Public risk</dt><dd>${escapeHtml(payload.publicRiskClassification)}</dd></div>
        <div><dt>Issued</dt><dd>${formatDate(payload.issuedAtUtc)}</dd></div>
        <div><dt>Last verified</dt><dd>${formatDate(payload.lastVerificationAtUtc)}</dd></div>
        <div><dt>Expires</dt><dd>${formatDate(payload.expiresAtUtc)}</dd></div>
      </dl>
      <div class="hip-panel-columns">
        <section><h3>Verification strengths</h3><ul>${strengths}</ul></section>
        <section class="hip-panel-warnings"><h3>Public warnings</h3><ul>${warnings}</ul></section>
      </div>
      <a class="hip-panel-link" href="${escapeAttribute(certificateUrl)}" target="_blank" rel="noopener noreferrer">View full HIP certificate</a>
      <p class="hip-panel-note">HIP does not replace TLS. TLS protects the connection; HIP adds identity and policy evidence.</p>`;
    wireClose(panel, panel.parentElement.querySelector(".hip-badge-card"));
  }

  function wireClose(panel, button) {
    panel.querySelector(".hip-panel-close")?.addEventListener("click", () => {
      closePanel(button, panel);
      button.focus();
    });
  }

  function closePanel(button, panel) {
    panel.hidden = true;
    button.setAttribute("aria-expanded", "false");
  }

  function renderUnavailable(container, message) {
    applyConfiguration(container);
    container.replaceChildren();
    container.classList.add("hip-trust-badge", "hip-badge-rendered", "hip-state-unable-to-verify");
    container.innerHTML = `<div class="hip-badge-anchor"><a class="hip-badge-card" href="${escapeAttribute(`${scriptOrigin}/lookup`)}" target="_blank" rel="noopener noreferrer" aria-label="HIP unable to verify. ${escapeAttribute(message)}">
      <span class="hip-badge-mark" aria-hidden="true">${shieldMarkup()}</span><span class="hip-badge-copy"><small>HIP status</small><strong>Unable to verify</strong></span><span class="hip-badge-divider"></span><strong class="hip-badge-score">-</strong>
    </a></div>`;
    scheduleOverlapAvoidance(container);
  }

  function displayState(badge) {
    const status = String(badge.certificate?.status || "UnableToVerify");
    const level = String(badge.certificate?.level || "Registered");
    const risk = String(badge.status || "Unknown");
    if (status !== "Active") return state(status);
    if (["Dangerous", "Critical"].includes(risk)) return state("Critical");
    if (risk === "HighRisk") return state("Risk");
    if (risk === "Suspicious") return state("Caution");
    return state(level);
  }

  function state(value) {
    const key = String(value || "UnableToVerify").replace(/([a-z])([A-Z])/g, "$1-$2").toLowerCase();
    return { key, label: readable(value || "UnableToVerify") };
  }

  function stateMeaning(key) {
    if (["active", "verified", "monitored"].includes(key)) return "HIP verified the current certificate and published evidence.";
    if (key === "registered") return "HIP verified domain control; this is not a safety guarantee.";
    if (["caution", "renewal-required"].includes(key)) return "Review the live certificate before relying on this badge.";
    if (["risk", "critical", "suspended", "revoked"].includes(key)) return "This badge is not a current positive trust signal.";
    return "HIP cannot establish a current verified trust state.";
  }

  function applyConfiguration(container) {
    const opacity = parseOpacity(container.dataset.opacity);
    const theme = ["light", "dark", "auto"].includes(container.dataset.theme) ? container.dataset.theme : "auto";
    const position = ["inline", "top-left", "top-right", "bottom-left", "bottom-right"].includes(container.dataset.position)
      ? container.dataset.position : "bottom-right";
    container.style.setProperty("--hip-owner-alpha", String(opacity / 100));
    container.dataset.theme = theme;
    container.dataset.position = position;
    container.dataset.opacity = String(opacity);
  }

  function parseOpacity(value) {
    if (!/^\d+$/.test(String(value || ""))) return DEFAULT_OPACITY;
    const number = Number(value);
    return Number.isInteger(number) && number >= 60 && number <= 100 ? number : DEFAULT_OPACITY;
  }

  function scheduleOverlapAvoidance(container) {
    if (container.dataset.position === "inline") return;
    const adjust = () => avoidOverlap(container);
    requestAnimationFrame(adjust);
    window.addEventListener("resize", adjust, { passive: true });
    if ("ResizeObserver" in window) new ResizeObserver(adjust).observe(container);
  }

  function avoidOverlap(container) {
    container.style.setProperty("--hip-overlap-shift", "0px");
    const badgeRect = container.getBoundingClientRect();
    let shift = 0;
    for (const element of document.querySelectorAll("body *")) {
      if (element === container || container.contains(element) || element.contains(container)) continue;
      const style = getComputedStyle(element);
      if (style.display === "none" || style.visibility === "hidden" || !["fixed", "sticky"].includes(style.position)) continue;
      const rect = element.getBoundingClientRect();
      const overlaps = badgeRect.left < rect.right && badgeRect.right > rect.left && badgeRect.top < rect.bottom && badgeRect.bottom > rect.top;
      if (overlaps) shift = Math.max(shift, Math.min(rect.height + 12, window.innerHeight / 3));
    }
    container.style.setProperty("--hip-overlap-shift", `${Math.round(shift)}px`);
  }

  function positionPanel(container, panel) {
    panel.classList.toggle("hip-panel-above", container.dataset.position.startsWith("bottom"));
    panel.classList.toggle("hip-panel-left", container.dataset.position.endsWith("right"));
  }

  function shieldMarkup() {
    const logoUrl = `${scriptOrigin}/images/public/marketing/hip-logo.png?v=3`;
    return `<img src="${escapeAttribute(logoUrl)}" alt="" width="40" height="47">`;
  }

  function ensureStyles() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
      .hip-trust-badge.hip-badge-rendered{--hip-status:#14B8A6;--hip-owner-alpha:.82;--hip-surface-alpha:var(--hip-owner-alpha);--hip-overlap-shift:0px;position:fixed!important;z-index:2147483000!important;max-width:calc(100vw - 24px)!important;margin:0!important;padding:0!important;background:transparent!important;border:0!important;color:#e8edf6!important;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif!important;line-height:1.35!important}
      .hip-trust-badge[data-position="bottom-right"]{right:max(16px,env(safe-area-inset-right))!important;bottom:calc(max(16px,env(safe-area-inset-bottom)) + var(--hip-overlap-shift))!important}.hip-trust-badge[data-position="bottom-left"]{left:max(16px,env(safe-area-inset-left))!important;bottom:calc(max(16px,env(safe-area-inset-bottom)) + var(--hip-overlap-shift))!important}.hip-trust-badge[data-position="top-right"]{right:max(16px,env(safe-area-inset-right))!important;top:calc(max(16px,env(safe-area-inset-top)) + var(--hip-overlap-shift))!important}.hip-trust-badge[data-position="top-left"]{left:max(16px,env(safe-area-inset-left))!important;top:calc(max(16px,env(safe-area-inset-top)) + var(--hip-overlap-shift))!important}.hip-trust-badge[data-position="inline"]{position:relative!important;display:inline-block!important;z-index:auto!important}
      .hip-badge-anchor{position:relative!important}.hip-badge-card{all:unset!important;box-sizing:border-box!important;display:grid!important;grid-template-columns:44px minmax(82px,1fr) 1px 38px!important;align-items:center!important;gap:12px!important;min-width:246px!important;padding:13px 16px!important;cursor:pointer!important;color:inherit!important;border:1px solid rgba(148,163,184,.22)!important;border-radius:16px!important;background:rgba(10,20,36,var(--hip-surface-alpha))!important;box-shadow:0 12px 30px rgba(2,8,23,.24)!important;backdrop-filter:blur(14px) saturate(135%)!important;-webkit-backdrop-filter:blur(14px) saturate(135%)!important;text-decoration:none!important;transition:transform .16s ease,border-color .16s ease,box-shadow .16s ease!important}.hip-badge-card:hover{transform:translateY(-2px)!important;border-color:color-mix(in srgb,var(--hip-status) 58%,transparent)!important;box-shadow:0 16px 34px rgba(2,8,23,.32)!important}.hip-badge-card:focus-visible,.hip-trust-panel button:focus-visible,.hip-trust-panel a:focus-visible{outline:3px solid #3082F6!important;outline-offset:3px!important}.hip-badge-mark{display:grid!important;place-items:center!important;width:44px!important;height:50px!important}.hip-badge-mark img{display:block!important;width:40px!important;height:47px!important;object-fit:contain!important}.hip-badge-copy{display:grid!important;gap:1px!important}.hip-badge-copy small{color:#9ca9bd!important;font-size:14px!important}.hip-badge-copy strong{color:#f8fafc!important;font-size:25px!important;line-height:1!important;letter-spacing:.01em!important}.hip-badge-divider{width:1px!important;height:40px!important;background:rgba(148,163,184,.22)!important}.hip-badge-score{color:var(--hip-status)!important;font-size:18px!important;text-align:center!important}.hip-badge-tooltip{box-sizing:border-box!important;position:absolute!important;right:0!important;bottom:calc(100% + 8px)!important;width:max-content!important;max-width:min(300px,calc(100vw - 24px))!important;padding:8px 10px!important;pointer-events:none!important;opacity:0!important;transform:translateY(4px)!important;color:#e2e8f0!important;border:1px solid rgba(148,163,184,.28)!important;border-radius:9px!important;background:#0f172a!important;box-shadow:0 10px 24px rgba(2,8,23,.3)!important;font-size:12px!important;transition:opacity .14s ease,transform .14s ease!important}.hip-badge-card:hover~.hip-badge-tooltip,.hip-badge-card:focus-visible~.hip-badge-tooltip{opacity:1!important;transform:translateY(0)!important}.hip-trust-badge[data-position^="top"] .hip-badge-tooltip{top:calc(100% + 8px)!important;bottom:auto!important}
      .hip-trust-panel{box-sizing:border-box!important;position:absolute!important;right:0!important;z-index:2!important;width:min(390px,calc(100vw - 24px))!important;max-height:min(620px,calc(100vh - 32px))!important;overflow:auto!important;padding:20px!important;color:#e8edf6!important;border:1px solid rgba(148,163,184,.28)!important;border-top:3px solid var(--hip-status)!important;border-radius:18px!important;background:rgba(9,18,33,.97)!important;box-shadow:0 22px 60px rgba(2,8,23,.48)!important;backdrop-filter:blur(18px)!important}.hip-trust-panel[hidden]{display:none!important}.hip-panel-above{bottom:calc(100% + 10px)!important}.hip-trust-panel:not(.hip-panel-above){top:calc(100% + 10px)!important}.hip-panel-left{right:0!important}.hip-trust-panel:not(.hip-panel-left){left:0!important;right:auto!important}.hip-panel-header{display:flex!important;align-items:start!important;justify-content:space-between!important;gap:16px!important}.hip-panel-header div{display:grid!important;gap:3px!important}.hip-panel-header small{color:#9ca9bd!important;font-size:13px!important}.hip-panel-header strong{color:#f8fafc!important;font-size:21px!important}.hip-panel-close{all:unset!important;display:grid!important;place-items:center!important;width:32px!important;height:32px!important;cursor:pointer!important;border:1px solid rgba(148,163,184,.28)!important;border-radius:9px!important}.hip-panel-loading,.hip-panel-warning,.hip-panel-note,.hip-panel-publisher{font-size:13px!important}.hip-panel-warning{padding:10px!important;color:#fecaca!important;border:1px solid rgba(239,68,68,.4)!important;border-radius:10px!important;background:rgba(127,29,29,.3)!important}.hip-panel-publisher{color:#cbd5e1!important}.hip-panel-facts{display:grid!important;grid-template-columns:1fr 1fr!important;gap:9px!important;margin:16px 0!important}.hip-panel-facts div{padding:9px!important;border:1px solid rgba(148,163,184,.18)!important;border-radius:10px!important;background:rgba(15,23,42,.5)!important}.hip-panel-facts dt{color:#94a3b8!important;font-size:11px!important;text-transform:uppercase!important;letter-spacing:.07em!important}.hip-panel-facts dd{margin:3px 0 0!important;color:#f8fafc!important;font-size:13px!important;font-weight:700!important}.hip-panel-columns{display:grid!important;grid-template-columns:1fr 1fr!important;gap:10px!important}.hip-panel-columns section{padding:10px!important;border-radius:10px!important;background:rgba(20,184,166,.08)!important}.hip-panel-columns h3{margin:0 0 7px!important;color:#99f6e4!important;font-size:12px!important}.hip-panel-columns ul{margin:0!important;padding-left:17px!important;color:#cbd5e1!important;font-size:12px!important}.hip-panel-warnings{background:rgba(245,158,11,.08)!important}.hip-panel-warnings h3{color:#fbbf24!important}.hip-panel-link{display:inline-block!important;margin-top:16px!important;color:#67e8f9!important;font-size:13px!important;font-weight:800!important;text-underline-offset:3px!important}.hip-panel-note{margin:14px 0 0!important;padding-top:12px!important;color:#94a3b8!important;border-top:1px solid rgba(148,163,184,.18)!important}
      .hip-state-active,.hip-state-verified{--hip-status:#14B8A6}.hip-state-registered{--hip-status:#3082F6}.hip-state-monitored{--hip-status:#22C55E}.hip-state-caution,.hip-state-renewal-required{--hip-status:#F59E0B;--hip-surface-alpha:.94}.hip-state-risk,.hip-state-suspended,.hip-state-revoked{--hip-status:#EF4444;--hip-surface-alpha:.94}.hip-state-critical{--hip-status:#B91C1C;--hip-surface-alpha:.94}.hip-state-expired,.hip-state-unable-to-verify{--hip-status:#94A3B8;--hip-surface-alpha:.94}
      .hip-trust-badge[data-theme="light"]{color:#111827!important}.hip-trust-badge[data-theme="light"] .hip-badge-card{background:rgba(248,250,252,var(--hip-surface-alpha))!important;border-color:rgba(100,116,139,.22)!important}.hip-trust-badge[data-theme="light"] .hip-badge-copy strong{color:#111827!important}.hip-trust-badge[data-theme="light"] .hip-badge-copy small{color:#64748b!important}.hip-trust-badge[data-theme="light"] .hip-badge-divider{background:rgba(100,116,139,.25)!important}
      .hip-trust-badge[data-theme="light"] .hip-trust-panel{color:#172033!important;border-color:rgba(100,116,139,.24)!important;background:rgba(248,250,252,.98)!important}.hip-trust-badge[data-theme="light"] .hip-panel-header strong,.hip-trust-badge[data-theme="light"] .hip-panel-facts dd{color:#111827!important}.hip-trust-badge[data-theme="light"] .hip-panel-publisher,.hip-trust-badge[data-theme="light"] .hip-panel-columns ul{color:#475569!important}.hip-trust-badge[data-theme="light"] .hip-panel-facts div{background:rgba(226,232,240,.5)!important}
      @media (prefers-color-scheme:light){.hip-trust-badge[data-theme="auto"]{color:#111827!important}.hip-trust-badge[data-theme="auto"] .hip-badge-card{background:rgba(248,250,252,var(--hip-surface-alpha))!important;border-color:rgba(100,116,139,.22)!important}.hip-trust-badge[data-theme="auto"] .hip-badge-copy strong{color:#111827!important}.hip-trust-badge[data-theme="auto"] .hip-badge-copy small{color:#64748b!important}.hip-trust-badge[data-theme="auto"] .hip-badge-divider{background:rgba(100,116,139,.25)!important}.hip-trust-badge[data-theme="auto"] .hip-trust-panel{color:#172033!important;border-color:rgba(100,116,139,.24)!important;background:rgba(248,250,252,.98)!important}.hip-trust-badge[data-theme="auto"] .hip-panel-header strong,.hip-trust-badge[data-theme="auto"] .hip-panel-facts dd{color:#111827!important}.hip-trust-badge[data-theme="auto"] .hip-panel-publisher,.hip-trust-badge[data-theme="auto"] .hip-panel-columns ul{color:#475569!important}.hip-trust-badge[data-theme="auto"] .hip-panel-facts div{background:rgba(226,232,240,.5)!important}}
      @supports not ((backdrop-filter:blur(1px)) or (-webkit-backdrop-filter:blur(1px))){.hip-badge-card{background:#0a1424!important}.hip-trust-badge[data-theme="light"] .hip-badge-card{background:#f8fafc!important}}
      @media(max-width:460px){.hip-panel-facts,.hip-panel-columns{grid-template-columns:1fr!important}.hip-trust-panel{max-height:calc(100vh - 24px)!important}}
      @media(prefers-reduced-motion:reduce){.hip-trust-badge,.hip-trust-badge *{transition:none!important;animation:none!important;scroll-behavior:auto!important}}
    `;
    document.head.appendChild(style);
  }

  function getScriptOrigin() {
    const script = document.currentScript;
    return script?.src ? new URL(script.src).origin : window.location.origin;
  }
  function safeApiBase() { return scriptOrigin; }
  function safePublicUrl(value, apiBase) {
    try { const url = new URL(value, apiBase); return url.protocol === "https:" ? url.href : `${apiBase}/lookup`; }
    catch { return `${apiBase}/lookup`; }
  }
  function sameHostname(requested, actual) { return requested === actual; }
  function normalizeDomain(value) { return String(value || "").trim().replace(/\.$/, "").toLowerCase(); }
  function readable(value) { return String(value || "").replace(/[_-]+/g, " ").replace(/([a-z])([A-Z])/g, "$1 $2").replace(/^./, letter => letter.toUpperCase()); }
  function formatDate(value) { const date = new Date(value); return Number.isFinite(date.getTime()) ? date.toLocaleDateString() : "Unavailable"; }
  function escapeHtml(value) { return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;"); }
  function escapeAttribute(value) { return escapeHtml(value); }
})();
