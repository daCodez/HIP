(function attachRiskBadgeRenderer() {
  const badgeClass = "hip-link-risk-badge";
  const styleId = "hip-link-risk-badge-style";

  const badgeMap = {
    Unknown: { label: "Unknown", className: "unknown", icon: "?" },
    LimitedTrustData: { label: "Limited data", className: "caution", icon: "?" },
    Caution: { label: "Caution", className: "caution", icon: "!" },
    Suspicious: { label: "Suspicious", className: "high-risk", icon: "!" },
    HighRisk: { label: "Suspicious", className: "high-risk", icon: "!" },
    Dangerous: { label: "Dangerous", className: "dangerous", icon: "x" },
    Critical: { label: "Critical", className: "critical", icon: "x" },
    Verified: { label: "Verified", className: "verified", icon: "✓" }
  };

  window.HipRiskBadgeRenderer = {
    ensureStyles,
    renderLinkBadge,
    renderTrustBanner,
    renderWarningBanner,
    renderFormIndicator
  };

  function renderLinkBadge(anchor, status, lookup) {
    ensureStyles();

    const displayStatus = lookup?.verificationStatus === "Verified" && status === "Trusted"
      ? "Verified"
      : status;

    const badge = badgeMap[displayStatus];
    if (!badge || anchor.dataset.hipBadgeRendered === "true") {
      return;
    }

    const element = document.createElement("span");
    element.className = `${badgeClass} ${badge.className}`;
    element.title = `HIP ${badge.label}: ${lookup?.finalHipScore ?? "unknown"}/100`;
    element.setAttribute("aria-label", `HIP ${badge.label}`);
    element.innerHTML = `<span class="hip-badge-icon">${badge.icon}</span><span>${badge.label}</span>`;

    anchor.insertAdjacentElement("afterend", element);
    anchor.dataset.hipBadgeRendered = "true";
  }

  /**
   * Renders the page-level HIP trust banner for the current website.
   * The banner is intentionally site-level, not per-link, and includes the manifest-derived plugin version
   * so dev testers can confirm Chrome loaded the latest unpacked build.
   * Dismissal is stored in page localStorage only as a local user preference; it is not a trust signal.
   */
  function renderTrustBanner(lookup, pluginVersion = "HIP Plugin vunknown-dev", options = {}) {
    ensureStyles();

    if (document.getElementById("hip-trust-banner")) {
      return;
    }

    const status = lookup?.status || "Unknown";
    const domain = lookup?.domain || window.location.hostname || "unknown";
    const dismissedKey = bannerDismissedKey(domain);
    if (isBannerDismissed(dismissedKey)) {
      return;
    }

    const statusClass = status.toLowerCase().replace(/[^a-z0-9]+/g, "-");
    const score = lookup?.finalHipScore ?? lookup?.score ?? "Unknown";
    const title = bannerTitle(status);
    const reason = lookup?.knownRisks?.[0] || lookup?.explanations?.[0] || "HIP has not found a stronger public trust signal for this website yet.";
    const lookupUrl = safeHref(lookup?.publicLookupUrl);
    const banner = document.createElement("div");
    banner.id = "hip-trust-banner";
    banner.className = `hip-trust-banner-${statusClass}`;
    banner.innerHTML = `
      <div class="hip-trust-main">
        <strong>${escapeHtml(title)}</strong>
        <span><span class="hip-trust-status-badge ${statusClass}">${escapeHtml(status)}</span> HIP Trust Score: ${escapeHtml(score)}/100</span>
        <span>${escapeHtml(reason)}</span>
        <small class="hip-trust-version">${escapeHtml(pluginVersion)}</small>
      </div>
      <div class="hip-trust-actions" aria-label="HIP trust feedback">
        <button class="hip-trust-feedback hip-trust-safe" type="button" data-hip-feedback="LooksSafe">Looks Safe</button>
        <button class="hip-trust-feedback hip-trust-suspicious" type="button" data-hip-feedback="LooksSuspicious">Looks Suspicious</button>
        <a class="hip-trust-link" href="${lookupUrl}" target="_blank" rel="noopener noreferrer">Details</a>
      </div>
      <button class="hip-trust-close" type="button" aria-label="Dismiss HIP trust banner">×</button>
    `;

    banner.querySelector(".hip-trust-close").addEventListener("click", () => {
      saveBannerDismissed(dismissedKey);
      banner.remove();
    });
    for (const button of banner.querySelectorAll("[data-hip-feedback]")) {
      button.addEventListener("click", async () => {
        button.disabled = true;
        button.textContent = "Sent";
        await options.onFeedback?.(button.dataset.hipFeedback, lookup).catch(error => console.warn("HIP banner feedback failed safely.", error));
      });
    }

    document.documentElement.prepend(banner);
  }

  /**
   * Backwards-compatible wrapper used by older content scripts.
   * It now renders the same site-level trust banner instead of a risk-only warning.
   */
  function renderWarningBanner(lookup, pluginVersion = "HIP Plugin vunknown-dev") {
    renderTrustBanner(lookup, pluginVersion);
  }

  function renderFormIndicator(form, lookup, reason) {
    ensureStyles();

    if (form.dataset.hipFormIndicatorRendered === "true") {
      return;
    }

    const element = document.createElement("div");
    element.className = "hip-form-risk-indicator";
    element.textContent = `HIP caution: ${reason} Status: ${lookup.status}.`;
    form.insertAdjacentElement("beforebegin", element);
    form.dataset.hipFormIndicatorRendered = "true";
  }

  function ensureStyles() {
    if (document.getElementById(styleId)) {
      return;
    }

    const style = document.createElement("style");
    style.id = styleId;
    style.textContent = `
      .${badgeClass} {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        margin-left: 6px;
        padding: 2px 7px;
        border-radius: 999px;
        font: 600 11px/1.3 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        vertical-align: baseline;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.16);
      }
      .${badgeClass} .hip-badge-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 14px;
        height: 14px;
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.75);
      }
      .${badgeClass}.unknown { color: #334155; background: #e2e8f0; }
      .${badgeClass}.caution { color: #713f12; background: #fef08a; }
      .${badgeClass}.high-risk { color: #7c2d12; background: #fed7aa; }
      .${badgeClass}.dangerous,
      .${badgeClass}.critical { color: #7f1d1d; background: #fecaca; }
      .${badgeClass}.verified { color: #075985; background: #bae6fd; }
      #hip-trust-banner {
        position: sticky;
        top: 0;
        z-index: 2147483647;
        display: flex;
        align-items: center;
        gap: 14px;
        padding: 12px 16px;
        color: #dbeafe;
        background: #0f172a;
        border-bottom: 1px solid rgba(14, 165, 233, 0.42);
        box-shadow: 0 8px 22px rgba(15, 23, 42, 0.24);
        font: 14px/1.4 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }
      #hip-trust-banner.hip-trust-banner-suspicious,
      #hip-trust-banner.hip-trust-banner-highrisk,
      #hip-trust-banner.hip-trust-banner-dangerous,
      #hip-trust-banner.hip-trust-banner-critical {
        color: #fee2e2;
        background: #450a0a;
        border-bottom-color: rgba(248, 113, 113, 0.6);
      }
      #hip-trust-banner .hip-trust-main {
        display: grid;
        gap: 2px;
        flex: 1;
      }
      #hip-trust-banner .hip-trust-version {
        opacity: 0.82;
        font-size: 12px;
      }
      #hip-trust-banner .hip-trust-status-badge {
        display: inline-flex;
        align-items: center;
        margin-right: 8px;
        padding: 2px 8px;
        border-radius: 999px;
        color: #0f172a;
        background: #e2e8f0;
        font-weight: 700;
      }
      #hip-trust-banner .hip-trust-status-badge.trusted,
      #hip-trust-banner .hip-trust-status-badge.mostlytrusted,
      #hip-trust-banner .hip-trust-status-badge.probablysafe { background: #86efac; }
      #hip-trust-banner .hip-trust-status-badge.limitedtrustdata,
      #hip-trust-banner .hip-trust-status-badge.caution,
      #hip-trust-banner .hip-trust-status-badge.unknown { background: #fde68a; }
      #hip-trust-banner .hip-trust-status-badge.suspicious,
      #hip-trust-banner .hip-trust-status-badge.highrisk,
      #hip-trust-banner .hip-trust-status-badge.dangerous,
      #hip-trust-banner .hip-trust-status-badge.critical { background: #fecaca; }
      #hip-trust-banner .hip-trust-link,
      #hip-trust-banner .hip-trust-feedback,
      #hip-trust-banner .hip-trust-close {
        color: inherit;
        border: 1px solid rgba(255, 255, 255, 0.46);
        background: rgba(255, 255, 255, 0.10);
        border-radius: 6px;
        padding: 6px 10px;
        text-decoration: none;
        cursor: pointer;
      }
      #hip-trust-banner .hip-trust-actions {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
      }
      #hip-trust-banner .hip-trust-feedback:disabled {
        cursor: default;
        opacity: 0.72;
      }
      #hip-trust-banner .hip-trust-safe {
        border-color: rgba(52, 211, 153, 0.72);
      }
      #hip-trust-banner .hip-trust-suspicious {
        border-color: rgba(251, 113, 133, 0.72);
      }
      #hip-trust-banner .hip-trust-close {
        font-size: 18px;
        line-height: 1;
      }
      @media (max-width: 720px) {
        #hip-trust-banner {
          align-items: flex-start;
          flex-wrap: wrap;
        }
        #hip-trust-banner .hip-trust-actions {
          width: 100%;
        }
      }
      .hip-form-risk-indicator {
        margin: 8px 0;
        padding: 8px 10px;
        border: 1px solid #f59e0b;
        border-radius: 6px;
        color: #713f12;
        background: #fffbeb;
        font: 600 12px/1.4 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }
    `;
    document.head.appendChild(style);
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  /**
   * Selects a concise banner title that distinguishes normal trust checks from high-risk warnings.
   */
  function bannerTitle(status) {
    if (status === "Suspicious" || status === "HighRisk" || status === "Dangerous" || status === "Critical") {
      return "HIP Warning";
    }

    if (status === "Unknown" || status === "LimitedTrustData") {
      return "HIP Trust Status Unknown";
    }

    return "HIP Trust Check";
  }

  /**
   * Allows only HTTP(S) lookup links so injected markup cannot create script or data URL navigation.
   */
  function safeHref(value) {
    if (!value) {
      return "#";
    }

    try {
      const url = new URL(value, window.location.origin);
      return url.protocol === "http:" || url.protocol === "https:" ? url.toString() : "#";
    } catch {
      return "#";
    }
  }

  /**
   * Builds the localStorage key for banner dismissal.
   * This is intentionally per-domain so closing HIP on one site does not hide warnings everywhere.
   */
  function bannerDismissedKey(domain) {
    return `hip:trust-banner-dismissed:${String(domain).toLowerCase()}`;
  }

  /**
   * Checks local banner dismissal without treating localStorage as trusted security state.
   */
  function isBannerDismissed(key) {
    try {
      return window.localStorage.getItem(key) === "true";
    } catch {
      return false;
    }
  }

  /**
   * Saves the local-only banner dismissal preference.
   */
  function saveBannerDismissed(key) {
    try {
      window.localStorage.setItem(key, "true");
    } catch {
      // Some pages block localStorage; banner dismissal should fail safely.
    }
  }
})();
