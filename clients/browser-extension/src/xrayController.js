(function registerHipXrayController(global) {
  "use strict";

  const MAX_AUTOMATIC_RESCANS = 12;
  const RESCAN_DEBOUNCE_MS = 400;
  const ROUTE_POLL_MS = 500;
  const SESSION_VERSION = 3;
  const SESSION_KEY = "__hipXrayControllerSession";

  function create(options = {}) {
    const documentObject = options.document || global.document;
    const windowObject = options.window || global.window;
    const rules = options.rules || global.HipXrayRules;
    const rendererFactory = options.createRenderer || global.HipXrayRenderer?.create;
    const scan = options.scan || (scanOptions => rules.collectAndScan(documentObject, windowObject.location, scanOptions));
    const backendAdapter = options.backendAdapter || null;
    const makeObserver = options.mutationObserverFactory || (callback => new MutationObserver(callback));
    const schedule = options.schedule || ((callback, delay) => setTimeout(callback, delay));
    const cancelScheduled = options.cancelScheduled || (handle => clearTimeout(handle));
    const startInterval = options.startInterval || ((callback, delay) => setInterval(callback, delay));
    const cancelInterval = options.cancelInterval || (handle => clearInterval(handle));
    let active = false;
    let renderer = null;
    let observer = null;
    let scheduledRescan = null;
    let animationFrame = null;
    let routeWatcher = null;
    let currentLocation = String(windowObject?.location?.href || "");
    let findings = [];
    let references = new Map();
    let coverage = {};
    let inventory = [];
    let selectedFindingId = "";
    let scanState = "idle";
    let scanTimestamp = null;
    let markersVisible = options.markersVisible !== false;
    let automaticRescans = 0;
    const newElements = new Set();

    const controls = Object.freeze({
      start: () => start(),
      rescan: () => runScan(false),
      exit: () => stop(),
      updatePositions: () => requestPositionUpdate(),
      activateFinding: findingId => activateFromMarker(findingId)
    });

    function installLauncher() {
      ensureRenderer();
      renderer.mountLauncher();
      startRouteWatcher();
      return { installed: true, active };
    }

    function ensureRenderer() {
      if (renderer) return;
      if (!documentObject?.documentElement || !windowObject || typeof rendererFactory !== "function" || typeof scan !== "function") {
        throw new Error("X-ray is unavailable on this page.");
      }
      renderer = rendererFactory(controls, { document: documentObject, window: windowObject, markersVisible });
    }

    function start() {
      if (active) {
        renderer?.focus();
        return { active: true, alreadyActive: true, findingCount: findings.length };
      }
      ensureRenderer();
      active = true;
      renderer.open();
      runScan(false);
      observer = makeObserver(handleMutations);
      observer.observe(documentObject.documentElement, { childList: true, subtree: true });
      windowObject.addEventListener("scroll", requestPositionUpdate, { passive: true });
      windowObject.addEventListener("resize", requestPositionUpdate, { passive: true });
      windowObject.addEventListener("popstate", handleRouteChange, { passive: true });
      windowObject.addEventListener("hashchange", handleRouteChange, { passive: true });
      startRouteWatcher();
      return { active: true, alreadyActive: false, findingCount: findings.length };
    }

    function runScan(isAutomatic) {
      if (!active) return { active: false, findingCount: 0 };
      scanState = "scanning";
      renderer.setProgress("Scanning this page…");
      const result = scan({ newElements: new Set(newElements), isAutomatic });
      const backendFindings = backendAdapter?.readAvailableFindings?.() || [];
      const mergedResult = rules?.mergeHipFindings && backendFindings.length
        ? rules.mergeHipFindings(result, backendFindings)
        : result;
      findings = Array.isArray(mergedResult?.findings) ? mergedResult.findings : [];
      references = result?.references instanceof Map ? result.references : new Map();
      coverage = result?.coverage || {};
      inventory = Array.isArray(result?.inventory) ? result.inventory.slice(0, 2500) : [];
      scanTimestamp = new Date().toISOString();
      scanState = "complete";
      renderer.render(
        findings,
        references,
        coverage,
        mergedResult?.backend || { available: false, message: "Full domain scan unavailable." },
        { animate: !isAutomatic }
      );
      renderer.setProgress(`${findings.length} ${findings.length === 1 ? "finding" : "findings"}`);
      requestPositionUpdate();
      return { active: true, findingCount: findings.length };
    }

    function handleMutations(records = []) {
      if (!active) return;
      if (renderer?.isMounted && !renderer.isMounted()) {
        destroy();
        return;
      }
      if (automaticRescans >= MAX_AUTOMATIC_RESCANS) return;
      let relevant = false;
      for (const record of records) {
        if (Array.from(record?.removedNodes || []).some(node => node?.nodeType === 1)) requestPositionUpdate();
        for (const node of Array.from(record?.addedNodes || [])) {
          if (node?.nodeType !== 1 || node?.dataset?.hipXrayOwned === "true" || node?.closest?.("[data-hip-xray-owned='true']")) continue;
          if (newElements.size < 2500) newElements.add(node);
          for (const descendant of Array.from(node.querySelectorAll?.("script[src],iframe[src],frame[src]") || [])) {
            if (newElements.size < 2500) newElements.add(descendant);
          }
          relevant = true;
        }
      }
      if (!relevant) return;
      if (scheduledRescan !== null) cancelScheduled(scheduledRescan);
      scheduledRescan = schedule(() => {
        scheduledRescan = null;
        automaticRescans += 1;
        runScan(true);
      }, RESCAN_DEBOUNCE_MS);
    }

    /** Starts one bounded URL watcher for History API route changes. */
    function startRouteWatcher() {
      if (routeWatcher !== null) return;
      currentLocation = String(windowObject?.location?.href || "");
      routeWatcher = startInterval(checkRoute, ROUTE_POLL_MS);
    }

    function checkRoute() {
      const nextLocation = String(windowObject?.location?.href || "");
      if (nextLocation === currentLocation) return;
      currentLocation = nextLocation;
      handleRouteChange();
    }

    /** Removes active overlays when the current document changes logical route. */
    function handleRouteChange() {
      currentLocation = String(windowObject?.location?.href || "");
      renderer?.resetForNavigation?.();
      selectedFindingId = "";
      if (active) runScan(true);
    }

    function requestPositionUpdate() {
      if (!active || animationFrame !== null) return;
      animationFrame = windowObject.requestAnimationFrame(() => {
        animationFrame = null;
        renderer?.updateMarkerPositions();
      });
    }

    function stop() {
      if (!active) return;
      active = false;
      observer?.disconnect();
      observer = null;
      if (scheduledRescan !== null) cancelScheduled(scheduledRescan);
      scheduledRescan = null;
      if (animationFrame !== null) windowObject.cancelAnimationFrame(animationFrame);
      animationFrame = null;
      windowObject.removeEventListener("scroll", requestPositionUpdate);
      windowObject.removeEventListener("resize", requestPositionUpdate);
      windowObject.removeEventListener("popstate", handleRouteChange);
      windowObject.removeEventListener("hashchange", handleRouteChange);
      renderer?.showLauncher();
      findings = [];
      references.clear();
      references = new Map();
      newElements.clear();
      coverage = {};
      inventory = [];
      selectedFindingId = "";
      scanState = "idle";
      scanTimestamp = null;
      automaticRescans = 0;
    }

    function getState(request = {}) {
      const offset = Math.max(0, Math.min(Number(request.inventoryOffset) || 0, inventory.length));
      const limit = Math.max(1, Math.min(Number(request.inventoryLimit) || 50, 100));
      const nextOffset = Math.min(inventory.length, offset + limit);
      const findingOffset = Math.max(0, Math.min(Number(request.findingOffset) || 0, findings.length));
      const findingLimit = Math.max(1, Math.min(Number(request.findingLimit) || 50, 100));
      const nextFindingOffset = Math.min(findings.length, findingOffset + findingLimit);
      const metadata = options.getSummaryMetadata?.() || {};
      const severity = highestSeverity(findings);
      return {
        active,
        scanState,
        scanTimestamp,
        score: scoreFor(findings),
        status: findings.length ? statusForSeverity(severity) : "Safe in this scan",
        statusSeverity: findings.length ? severity : "Safe",
        findingCount: findings.length,
        referenceCount: references.size,
        coverage: safeCoverage(coverage),
        selectedFindingId,
        markersVisible,
        findings: findings.slice(findingOffset, nextFindingOffset).map(finding => safeFinding(finding, inventory)),
        nextFindingOffset: nextFindingOffset < findings.length ? nextFindingOffset : null,
        inventory: {
          items: inventory.slice(offset, nextOffset).map(safeInventoryItem),
          nextOffset: nextOffset < inventory.length ? nextOffset : null
        },
        submissionState: safeText(metadata.scanResultSubmission, 40) || "Skipped",
        lastSubmittedUtc: safeText(metadata.scanResultLastSubmittedUtc || metadata.lastSubmittedUtc, 40) || null
      };
    }

    function selectFinding(findingId) {
      if (!active) return { status: "stale", findingId };
      let result = renderer?.selectFinding?.(findingId) || { status: "stale", findingId };
      if (result.status === "missing") {
        runScan(false);
        result = renderer?.selectFinding?.(findingId) || { status: "stale", findingId };
      }
      if (result.status === "selected") selectedFindingId = findingId;
      return result;
    }

    function setMarkersVisible(visible) {
      markersVisible = visible === true;
      renderer?.setMarkersVisible?.(markersVisible);
      return { visible: markersVisible };
    }

    function activateFromMarker(findingId) {
      const result = selectFinding(findingId);
      options.onMarkerActivated?.(findingId, result);
      return result;
    }

    /** Applies persisted presentation preferences without restarting an active scan. */
    function setPreferences(preferences = {}) {
      options.launcherPosition = preferences.launcherPosition || options.launcherPosition;
      renderer?.setLauncherPosition?.(options.launcherPosition);
      if (typeof preferences.markersVisible === "boolean") setMarkersVisible(preferences.markersVisible);
      return { launcherPosition: "side-panel", markersVisible };
    }

    function destroy() {
      stop();
      if (routeWatcher !== null) cancelInterval(routeWatcher);
      routeWatcher = null;
      renderer?.destroy();
      renderer = null;
    }

    return Object.freeze({ installLauncher, start, stop, destroy, rescan: () => active ? runScan(false) : start(), getState, selectFinding, setMarkersVisible, setPreferences });
  }

  function safeFinding(finding = {}, inventory = []) {
    const inspected = inventory.find(item => item.elementRefKey === finding.elementRefKey);
    return {
      findingId: safeText(finding.id, 240),
      ruleId: safeText(finding.ruleId, 160),
      ruleVersion: safeText(finding.ruleVersion, 80),
      source: safeText(finding.source, 40),
      category: safeText(finding.category, 80),
      severity: ["Info", "Low", "Medium", "High", "Critical"].includes(finding.severity) ? finding.severity : "Info",
      title: safeText(finding.title, 160),
      plainExplanation: safeText(finding.plainExplanation, 600),
      technicalExplanation: safeText(finding.technicalExplanation, 800),
      evidence: safeText(finding.evidence, 600),
      remediation: safeText(finding.remediation, 600),
      elementKind: safeText(finding.elementKind || inspected?.elementKind || finding.category, 80)
    };
  }

  function safeInventoryItem(item = {}) {
    return {
      id: safeText(item.id, 240),
      elementKind: safeText(item.elementKind, 80) || "element",
      status: "No issue observed"
    };
  }

  function safeCoverage(value = {}) {
    return {
      inspectedElementCount: Math.max(0, Math.min(2500, Number(value.inspectedElementCount) || 0)),
      inaccessibleFrameCount: Math.max(0, Math.min(2500, Number(value.inaccessibleFrameCount) || 0)),
      truncated: value.truncated === true,
      closedShadowRoots: "Closed shadow roots are not observable"
    };
  }

  function safeText(value, maximum) {
    return String(value || "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, maximum);
  }

  function highestSeverity(items) {
    const rank = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
    return items.reduce((value, item) => (rank[item.severity] > rank[value] ? item.severity : value), "Info");
  }

  function statusForSeverity(severity) {
    return ({ Critical: "Risky", High: "Risky", Medium: "Caution", Low: "Review", Info: "Informational" })[severity] || "Informational";
  }

  function scoreFor(items) {
    const penalties = { Critical: 30, High: 18, Medium: 9, Low: 4, Info: 0 };
    return Math.max(0, Math.min(100, 100 - items.reduce((total, item) => total + (penalties[item.severity] || 0), 0)));
  }

  /**
   * Returns one versioned session per isolated page world. Popup reinjection can
   * call this directly even when a stale content-script guard skipped startup.
   */
  function getOrCreate(options = {}) {
    const current = global[SESSION_KEY];
    if (!current || current.version !== SESSION_VERSION || typeof current.session?.setPreferences !== "function") {
      current?.session?.destroy?.();
      global[SESSION_KEY] = { version: SESSION_VERSION, session: create(options) };
    } else {
      current.session.setPreferences(options);
    }
    return global[SESSION_KEY].session;
  }

  global.HipXrayController = Object.freeze({ create, getOrCreate, MAX_AUTOMATIC_RESCANS, ROUTE_POLL_MS, SESSION_VERSION });
})(globalThis);
