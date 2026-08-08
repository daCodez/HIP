(function registerHipXrayRenderer(global) {
  "use strict";

  const SCAN_ANIMATION_MS = 2600;
  const TARGET_RESOLVE_COOLDOWN_MS = 500;

  function create(controls, environment = {}) {
    const documentObject = environment.document || global.document;
    const windowObject = environment.window || global.window;
    const nowValue = environment.now || (() => Date.now());
    let host = null;
    let shadow = null;
    let theatre = null;
    let scanLine = null;
    let markerLayer = null;
    let announcer = null;
    let findings = [];
    let references = new Map();
    let markerNodes = [];
    let selectedFindingId = "";
    let selectedTarget = null;
    let markersVisible = environment.markersVisible !== false;
    let animationTimer = null;
    let resizeObserver = null;
    const resolvedTargets = new Map();

    // Kept as a no-op compatibility seam while old callers migrate. It never
    // injects a launcher or control into the host page.
    function mountLauncher() {
      ensureHost();
      return { installed: true };
    }

    function setLauncherPosition() {
      return "side-panel";
    }

    function ensureHost() {
      if (host?.isConnected) return;
      host = documentObject.createElement("div");
      host.dataset.hipXrayOwned = "true";
      host.setAttribute?.("aria-hidden", "false");
      shadow = host.attachShadow({ mode: "open" });
      const style = documentObject.createElement("style");
      style.textContent = styles();
      theatre = documentObject.createElement("div");
      theatre.className = "theatre";
      theatre.dataset.hipXrayOwned = "true";
      const scrim = documentObject.createElement("div");
      scrim.className = "scrim";
      scanLine = documentObject.createElement("div");
      scanLine.className = "scan-line";
      markerLayer = documentObject.createElement("div");
      markerLayer.className = "marker-layer";
      announcer = documentObject.createElement("div");
      announcer.className = "sr-only";
      announcer.role = "status";
      announcer.ariaLive = "polite";
      theatre.append(scrim, scanLine, markerLayer, announcer);
      shadow.append(style, theatre);
      documentObject.documentElement.append(host);
      const ResizeObserverType = environment.ResizeObserver || windowObject.ResizeObserver || global.ResizeObserver;
      if (typeof ResizeObserverType === "function") resizeObserver = new ResizeObserverType(() => controls.updatePositions());
    }

    function open() {
      ensureHost();
      runSweep();
    }

    function render(nextFindings, nextReferences, _coverage = {}, _backend = {}, options = {}) {
      ensureHost();
      findings = Array.isArray(nextFindings) ? nextFindings.slice(0, 500) : [];
      references = nextReferences instanceof Map ? nextReferences : new Map();
      if (!findings.some(item => item.id === selectedFindingId)) {
        selectedFindingId = "";
        selectedTarget = null;
      }
      buildMarkers();
      if (options.animate !== false) runSweep();
      updateMarkerPositions();
    }

    function buildMarkers() {
      markerNodes = [];
      markerLayer?.replaceChildren();
      resizeObserver?.disconnect?.();
      findings.forEach((finding, index) => {
        const target = resolveFindingTarget(finding, true);
        if (!target) return;
        const frame = documentObject.createElement("div");
        frame.className = "marker-frame";
        frame.dataset.findingId = finding.id;
        frame.style.setProperty("--marker-tone", tone(finding.severity));
        const marker = documentObject.createElement("button");
        marker.type = "button";
        marker.className = "marker";
        marker.dataset.findingId = finding.id;
        marker.dataset.severity = finding.severity;
        marker.style.setProperty("--marker-tone", tone(finding.severity));
        marker.ariaLabel = `Select finding ${index + 1}: ${finding.title}`;
        const number = documentObject.createElement("span");
        number.className = "marker-number";
        number.textContent = String(index + 1).padStart(2, "0");
        const label = documentObject.createElement("span");
        label.className = "marker-label";
        label.textContent = markerSummary(finding);
        marker.append(number, label);
        marker.addEventListener("click", event => {
          event.stopPropagation();
          selectFinding(finding.id, { scroll: false });
          controls.activateFinding?.(finding.id);
        });
        markerLayer.append(frame, marker);
        markerNodes.push({ finding, target, frame, marker, lastResolveAt: 0 });
        resizeObserver?.observe?.(target);
      });
      markerLayer.hidden = !markersVisible;
    }

    function selectFinding(findingId, options = {}) {
      const finding = findings.find(item => item.id === findingId);
      if (!finding) return { status: "stale", findingId };
      const target = resolveFindingTarget(finding, true);
      if (!target?.getBoundingClientRect) {
        announce("Element no longer available");
        return { status: "missing", findingId };
      }
      selectedFindingId = finding.id;
      selectedTarget = target;
      if (options.scroll !== false) {
        scrollActualContainer(target, prefersReducedMotion() ? "auto" : "smooth");
      }
      emphasizeMarker(finding.id);
      updateMarkerPositions();
      announce(`${markerSummary(finding)} selected on the page.`);
      return { status: "selected", findingId };
    }

    function scrollActualContainer(target, behavior) {
      const container = nearestScrollableAncestor(target, windowObject);
      if (!container || container === documentObject.documentElement || container === documentObject.body) {
        target.scrollIntoView?.({ behavior, block: "center", inline: "nearest" });
        return;
      }
      const targetRect = target.getBoundingClientRect();
      const containerRect = container.getBoundingClientRect();
      const nextTop = container.scrollTop + targetRect.top - containerRect.top - (containerRect.height - targetRect.height) / 2;
      container.scrollTo?.({ top: Math.max(0, nextTop), behavior });
    }

    function updateMarkerPositions() {
      if (!host || !markersVisible || !markerLayer) return;
      const safeTop = stickyTopInset();
      markerNodes.forEach((entry, index) => {
        let target = entry.target;
        if (!target?.isConnected || !target.getBoundingClientRect) {
          const now = nowValue();
          if (now - entry.lastResolveAt >= TARGET_RESOLVE_COOLDOWN_MS) {
            entry.lastResolveAt = now;
            target = resolveFindingTarget(entry.finding, true);
            entry.target = target;
          }
        }
        if (!target?.isConnected || !target.getBoundingClientRect) {
          entry.marker.hidden = true;
          entry.frame.hidden = true;
          return;
        }
        const rect = target.getBoundingClientRect();
        const visible = rect.width > 0 && rect.height > 0 && rect.bottom >= 0 && rect.top <= windowObject.innerHeight && rect.right >= 0 && rect.left <= windowObject.innerWidth;
        entry.marker.hidden = !visible;
        entry.frame.hidden = !visible;
        if (!visible) return;
        positionBox(entry.frame, rect, 2);
        const estimatedWidth = Math.min(240, Math.max(100, entry.marker.textContent.length * 6 + 38));
        const x = clamp(rect.left + (index % 3) * 16, 6, Math.max(6, windowObject.innerWidth - estimatedWidth - 6));
        const y = clamp(rect.top - 34 - (index % 3) * 25, safeTop + 6, Math.max(safeTop + 6, windowObject.innerHeight - 36));
        entry.marker.style.transform = `translate(${x}px, ${y}px)`;
      });
      emphasizeMarker(selectedFindingId);
    }

    function positionBox(element, rect, padding) {
      element.style.transform = `translate(${Math.max(0, rect.left - padding)}px, ${Math.max(0, rect.top - padding)}px)`;
      element.style.width = `${Math.max(0, rect.width + padding * 2)}px`;
      element.style.height = `${Math.max(0, rect.height + padding * 2)}px`;
    }

    function emphasizeMarker(findingId) {
      markerNodes.forEach(entry => {
        const selected = entry.finding.id === findingId;
        entry.marker.dataset.selected = String(selected);
        entry.frame.dataset.selected = String(selected);
      });
    }

    function resolveFindingTarget(finding, force = false) {
      if (!finding) return null;
      const cached = resolvedTargets.get(finding.elementRefKey);
      if (!force && cached?.isConnected) return cached;
      const reference = references.get(finding.elementRefKey);
      const direct = reference?.element || reference;
      if (direct?.isConnected && direct.getBoundingClientRect) {
        resolvedTargets.set(finding.elementRefKey, direct);
        return direct;
      }
      const selector = typeof reference?.selector === "string" ? reference.selector : "";
      if (!selector || selector.length > 700) return null;
      try {
        const replacement = documentObject.querySelector(selector);
        if (!replacement || (reference.tagName && String(replacement.tagName || "").toLowerCase() !== reference.tagName)) return null;
        resolvedTargets.set(finding.elementRefKey, replacement);
        return replacement;
      } catch {
        return null;
      }
    }

    function setMarkersVisible(visible) {
      markersVisible = visible === true;
      if (markerLayer) markerLayer.hidden = !markersVisible;
      if (markersVisible) updateMarkerPositions();
      return { visible: markersVisible };
    }

    function runSweep() {
      if (!scanLine || prefersReducedMotion()) return;
      scanLine.classList.remove("active");
      void scanLine.offsetWidth;
      scanLine.classList.add("active");
      if (animationTimer !== null) windowObject.clearTimeout(animationTimer);
      animationTimer = windowObject.setTimeout(() => scanLine?.classList.remove("active"), SCAN_ANIMATION_MS);
    }

    function setProgress(message) {
      announce(String(message || ""));
    }

    function announce(message) {
      if (announcer) announcer.textContent = message;
    }

    function resetForNavigation() {
      selectedFindingId = "";
      selectedTarget = null;
      findings = [];
      references = new Map();
      resolvedTargets.clear();
      markerNodes = [];
      markerLayer?.replaceChildren();
    }

    function showLauncher() {
      resetForNavigation();
    }

    function isMounted() {
      return Boolean(host?.isConnected);
    }

    function focus() {
      announce("HIP Page X-ray is open in the side panel.");
    }

    function destroy() {
      if (animationTimer !== null) windowObject.clearTimeout(animationTimer);
      animationTimer = null;
      resizeObserver?.disconnect?.();
      resizeObserver = null;
      host?.remove();
      host = shadow = theatre = scanLine = markerLayer = announcer = null;
      resetForNavigation();
    }

    function stickyTopInset() {
      if (typeof documentObject.elementsFromPoint !== "function" || typeof windowObject.getComputedStyle !== "function") return 0;
      let inset = 0;
      for (const element of documentObject.elementsFromPoint(Math.max(1, windowObject.innerWidth / 2), 1).slice(0, 8)) {
        if (element === host || element?.closest?.("[data-hip-xray-owned='true']")) continue;
        const style = windowObject.getComputedStyle(element);
        const rect = element.getBoundingClientRect?.();
        if (["fixed", "sticky"].includes(style?.position) && rect?.top <= 1 && rect.bottom > 0 && rect.height < windowObject.innerHeight * .4) inset = Math.max(inset, rect.bottom);
      }
      return Math.min(inset, windowObject.innerHeight * .4);
    }

    function prefersReducedMotion() {
      return windowObject.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches === true;
    }

    return Object.freeze({ mountLauncher, setLauncherPosition, open, render, selectFinding, setMarkersVisible, updateMarkerPositions, setProgress, showLauncher, resetForNavigation, isMounted, focus, destroy });
  }

  function nearestScrollableAncestor(element, windowObject) {
    let parent = element?.parentElement;
    while (parent) {
      const style = windowObject.getComputedStyle?.(parent);
      if (/(auto|scroll|overlay)/.test(`${style?.overflow || ""} ${style?.overflowY || ""}`) && parent.scrollHeight > parent.clientHeight) return parent;
      parent = parent.parentElement;
    }
    return null;
  }

  function tone(severity) {
    return ({ Critical: "#ef4444", High: "#ef4444", Medium: "#f97316", Low: "#f59e0b", Info: "#3882f6" })[severity] || "#3882f6";
  }

  function markerSummary(finding = {}) {
    const category = String(finding.category || "Finding");
    const text = `${finding.title || ""} ${finding.evidence || ""}`.toLowerCase();
    let value;
    if (/media|image|video|audio/.test(category.toLowerCase())) {
      value = /confirmed ai|verified ai disclosure/.test(text) ? "Media · Confirmed AI" : /likely ai/.test(text) ? "Media · Likely AI" : /no provenance/.test(text) ? "Media · Unverified" : "Media · Origin unknown";
    } else {
      const status = finding.severity === "High" || finding.severity === "Critical" ? "Risky" : finding.severity === "Medium" ? "Caution" : finding.severity === "Low" ? "Review" : "Info";
      value = `${status} · ${category}`;
    }
    return value.length > 62 ? `${value.slice(0, 61)}…` : value;
  }

  function clamp(value, minimum, maximum) {
    return Math.max(minimum, Math.min(maximum, value));
  }

  function styles() {
    return `:host{all:initial}.theatre,.scrim,.scan-line,.marker-layer{position:fixed;inset:0;pointer-events:none}.theatre{z-index:2147483646;font-family:Satoshi,Inter,system-ui,sans-serif}.scrim{background:transparent}.scan-line{height:3px;bottom:auto;opacity:0;background:linear-gradient(90deg, transparent, #14b8a6, transparent);box-shadow:0 0 22px #14b8a6}.scan-line.active{opacity:1;animation:hip-scan ${SCAN_ANIMATION_MS}ms cubic-bezier(.45,0,.2,1)}@keyframes hip-scan{from{transform:translateY(0)}to{transform:translateY(100vh)}}.marker-layer{pointer-events:none}.marker-frame{position:absolute;pointer-events:none;border:2px solid var(--marker-tone);border-radius:5px;box-shadow:0 0 0 2px color-mix(in srgb,var(--marker-tone) 20%,transparent)}.marker-frame[data-selected=true]{outline:4px double var(--marker-tone);outline-offset:3px}.marker{position:absolute;display:flex;align-items:center;max-width:240px;padding:5px 8px;border:1px solid var(--marker-tone);border-radius:999px;background:#08111ded;color:#fff;pointer-events:auto;cursor:pointer;font:700 11px/1.2 Satoshi,Inter,sans-serif;white-space:nowrap;box-shadow:0 5px 18px #0008}.marker-number{margin-right:6px;color:var(--marker-tone);font:800 10px/1 "JetBrains Mono",monospace}.marker-label{overflow:hidden;text-overflow:ellipsis}.marker[data-selected=true]{outline:3px solid var(--marker-tone);outline-offset:2px}.marker:focus-visible{outline:3px solid #7dd3fc;outline-offset:3px}.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}@media(max-width:620px){.marker-label{max-width:150px}}@media(prefers-reduced-motion:reduce){.scan-line.active{animation:none;opacity:0}.marker,.marker-frame{transition:none!important}}`;
  }

  global.HipXrayRenderer = Object.freeze({ create, markerSummary, nearestScrollableAncestor, SCAN_ANIMATION_MS });
})(globalThis);
