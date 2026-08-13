(function attachSafetyPageRouter() {
  const interstitialId = "hip-current-page-interstitial";
  let continuedPageUrl = null;

  window.HipSafetyPageRouter = {
    removeCurrentPageInterstitial,
    renderCurrentPageInterstitial,
    routeClick,
    shouldBlockCurrentPage
  };

  /**
   * Requires an explicit server blocking disposition or a final Critical result.
   * Confidence must be High so incomplete scans and provider failures never block a page.
   */
  function shouldBlockCurrentPage(lookup = {}, siteSafety = {}, settings = {}) {
    if (settings.enableSafetyPageRouting === false || settings.enableSafetyRouting === false) {
      return false;
    }

    if (!siteSafety || typeof siteSafety !== "object") {
      return false;
    }

    const scoring = siteSafety.scoring || siteSafety.Scoring || {};
    const status = scoring.presentationStatus || scoring.PresentationStatus ||
      scoring.finalStatus || scoring.FinalStatus || siteSafety.status || lookup.status;
    const confidence = scoring.confidence || scoring.Confidence ||
      siteSafety.confidenceLevel || lookup.evidenceConfidence;
    const disposition = scoring.blockingDisposition || scoring.BlockingDisposition ||
      siteSafety.blockingDisposition || siteSafety.BlockingDisposition;
    const finalScore = scoring.finalHipScore ?? scoring.FinalHipScore ??
      siteSafety.finalHipScore ?? lookup.finalHipScore;

    return confidence === "High" &&
      Number.isFinite(Number(finalScore)) &&
      (status === "Critical" || disposition === "Block");
  }

  /**
   * Covers a completed high-confidence critical page without modifying host content or form state.
   * The user may explicitly continue for the current page load.
   */
  function renderCurrentPageInterstitial(lookup = {}, siteSafety = {}, settings = {}) {
    removeCurrentPageInterstitial();
    if (continuedPageUrl === window.location.href ||
        !shouldBlockCurrentPage(lookup, siteSafety, settings)) {
      return false;
    }

    const host = document.createElement("div");
    host.id = interstitialId;
    host.style.cssText = "all:initial;position:fixed;inset:0;z-index:2147483647;display:block;";
    const shadow = host.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      .backdrop { position: fixed; inset: 0; display: grid; place-items: center; padding: 24px; box-sizing: border-box;
        background: rgba(2, 8, 23, .96); color: #f8fafc; font-family: Arial, sans-serif; }
      .dialog { width: min(620px, 100%); box-sizing: border-box; padding: 32px; border: 2px solid #ef4444;
        border-radius: 20px; background: #0f172a; box-shadow: 0 24px 80px rgba(0,0,0,.65); }
      .eyebrow { margin: 0 0 12px; color: #f87171; font-size: 14px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
      h1 { margin: 0 0 16px; font-size: clamp(28px, 5vw, 42px); line-height: 1.08; }
      p { margin: 0 0 14px; color: #cbd5e1; font-size: 17px; line-height: 1.55; }
      .domain { color: #fff; font-weight: 700; overflow-wrap: anywhere; }
      .actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 28px; }
      button, a { min-height: 46px; box-sizing: border-box; border-radius: 10px; padding: 12px 18px; font: 700 15px Arial, sans-serif;
        cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; }
      button:focus-visible, a:focus-visible { outline: 3px solid #22d3ee; outline-offset: 3px; }
      .leave { border: 1px solid #ef4444; background: #ef4444; color: #fff; }
      .details { border: 1px solid #64748b; background: #1e293b; color: #fff; }
      .continue { border: 1px solid transparent; background: transparent; color: #cbd5e1; }
      @media (prefers-reduced-motion: reduce) { * { scroll-behavior: auto !important; transition: none !important; } }
    `;

    const backdrop = document.createElement("div");
    backdrop.className = "backdrop";
    const dialog = document.createElement("section");
    dialog.className = "dialog";
    dialog.setAttribute("role", "alertdialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", "hip-critical-title");

    const eyebrow = document.createElement("p");
    eyebrow.className = "eyebrow";
    eyebrow.textContent = "HIP critical security warning";
    const title = document.createElement("h1");
    title.id = "hip-critical-title";
    title.textContent = "HIP recommends leaving this page";
    const domain = document.createElement("p");
    domain.className = "domain";
    domain.textContent = String(lookup.domain || window.location.hostname || "This site").slice(0, 253);
    const reason = document.createElement("p");
    reason.textContent = "HIP received a completed, high-confidence critical assessment. The page may expose passwords, payments, or downloads to a serious threat.";
    const choice = document.createElement("p");
    choice.textContent = "The page remains underneath this warning. You can leave, review HIP's details, or continue at your own risk.";

    const actions = document.createElement("div");
    actions.className = "actions";
    const leave = document.createElement("button");
    leave.className = "leave";
    leave.type = "button";
    leave.textContent = "Leave this page";
    leave.addEventListener("click", leaveCurrentPage);

    const detailsUrl = lookup.publicLookupUrl;
    if (typeof detailsUrl === "string" && /^https?:\/\//i.test(detailsUrl)) {
      const details = document.createElement("a");
      details.className = "details";
      details.href = detailsUrl;
      details.target = "_blank";
      details.rel = "noopener noreferrer";
      details.textContent = "Review HIP details";
      actions.append(details);
    }

    const proceed = document.createElement("button");
    proceed.className = "continue";
    proceed.type = "button";
    proceed.textContent = "Continue anyway";
    proceed.addEventListener("click", () => {
      continuedPageUrl = window.location.href;
      removeCurrentPageInterstitial();
    });

    actions.prepend(leave);
    actions.append(proceed);
    dialog.addEventListener("keydown", event => trapDialogFocus(event, actions));
    dialog.append(eyebrow, title, domain, reason, choice, actions);
    backdrop.append(dialog);
    shadow.append(style, backdrop);
    document.documentElement.append(host);
    leave.focus();
    return true;
  }

  /** Removes only HIP's isolated overlay and leaves the host page untouched. */
  function removeCurrentPageInterstitial() {
    document.getElementById(interstitialId)?.remove();
  }

  function leaveCurrentPage() {
    if (window.history.length > 1) {
      window.history.back();
      return;
    }
    window.location.replace("about:blank");
  }

  /** Keeps keyboard navigation inside the modal without touching host-page controls. */
  function trapDialogFocus(event, actions) {
    if (event.key !== "Tab") {
      return;
    }

    const controls = Array.from(actions.querySelectorAll("button, a[href]"));
    if (controls.length === 0) {
      return;
    }

    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && shadowActiveElement(event) === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && shadowActiveElement(event) === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function shadowActiveElement(event) {
    return event.currentTarget?.getRootNode()?.activeElement;
  }

  async function routeClick(event, anchor, lookup, sourceDomain) {
    if (!anchor?.href) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();

    if (lookup?.safetyPageUrl && /^https?:\/\//i.test(lookup.safetyPageUrl)) {
      window.location.assign(lookup.safetyPageUrl);
      return;
    }

    const response = await chrome.runtime.sendMessage({
      type: "HIP_SAFETY_URL",
      originalUrl: anchor.href,
      sourceDomain,
      riskStatus: lookup?.status
    });

    if (response?.ok && response.result) {
      window.location.assign(response.result);
      return;
    }

    window.location.assign(anchor.href);
  }
})();
