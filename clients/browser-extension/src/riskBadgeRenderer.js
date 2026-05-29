(function attachRiskBadgeRenderer() {
  const badgeClass = "hip-link-risk-badge";
  const styleId = "hip-link-risk-badge-style";

  const badgeMap = {
    Unknown: { label: "Unknown", className: "unknown", icon: "?" },
    Caution: { label: "Caution", className: "caution", icon: "!" },
    HighRisk: { label: "Suspicious", className: "high-risk", icon: "!" },
    Dangerous: { label: "Dangerous", className: "dangerous", icon: "x" },
    Critical: { label: "Critical", className: "critical", icon: "x" },
    Verified: { label: "Verified", className: "verified", icon: "✓" }
  };

  window.HipRiskBadgeRenderer = {
    ensureStyles,
    renderLinkBadge,
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

  function renderWarningBanner(lookup) {
    ensureStyles();

    if (document.getElementById("hip-warning-banner")) {
      return;
    }

    const reason = lookup?.knownRisks?.[0] || lookup?.explanations?.[0] || "HIP found public risk signals for this website.";
    const banner = document.createElement("div");
    banner.id = "hip-warning-banner";
    banner.innerHTML = `
      <div class="hip-warning-main">
        <strong>HIP Warning: This website has a low trust score.</strong>
        <span>Score: ${lookup.finalHipScore}/100 · Status: ${lookup.status}</span>
        <span>${escapeHtml(reason)}</span>
      </div>
      <a class="hip-warning-link" href="${lookup.publicLookupUrl || "#"}" target="_blank" rel="noopener noreferrer">Lookup</a>
      <button class="hip-warning-dismiss" type="button" aria-label="Dismiss HIP warning">×</button>
    `;

    banner.querySelector(".hip-warning-dismiss").addEventListener("click", () => banner.remove());
    document.documentElement.prepend(banner);
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
      #hip-warning-banner {
        position: sticky;
        top: 0;
        z-index: 2147483647;
        display: flex;
        align-items: center;
        gap: 14px;
        padding: 12px 16px;
        color: #fff;
        background: #991b1b;
        box-shadow: 0 8px 22px rgba(15, 23, 42, 0.28);
        font: 14px/1.4 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }
      #hip-warning-banner .hip-warning-main {
        display: grid;
        gap: 2px;
        flex: 1;
      }
      #hip-warning-banner .hip-warning-link,
      #hip-warning-banner .hip-warning-dismiss {
        color: #fff;
        border: 1px solid rgba(255, 255, 255, 0.7);
        background: rgba(255, 255, 255, 0.12);
        border-radius: 6px;
        padding: 6px 10px;
        text-decoration: none;
        cursor: pointer;
      }
      #hip-warning-banner .hip-warning-dismiss {
        font-size: 18px;
        line-height: 1;
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
})();
