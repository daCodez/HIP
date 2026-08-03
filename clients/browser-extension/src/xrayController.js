(function registerHipXrayController(global) {
  "use strict";

  const MAX_AUTOMATIC_RESCANS = 12;
  const RESCAN_DEBOUNCE_MS = 400;

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
    let active = false;
    let renderer = null;
    let observer = null;
    let scheduledRescan = null;
    let animationFrame = null;
    let findings = [];
    let references = new Map();
    let coverage = {};
    let automaticRescans = 0;
    const newElements = new Set();

    const controls = Object.freeze({
      start: () => start(),
      rescan: () => runScan(false),
      exit: () => stop(),
      updatePositions: () => requestPositionUpdate()
    });

    function installLauncher() {
      ensureRenderer();
      renderer.mountLauncher();
      return { installed: true, active };
    }

    function ensureRenderer() {
      if (renderer) return;
      if (!documentObject?.documentElement || !windowObject || typeof rendererFactory !== "function" || typeof scan !== "function") {
        throw new Error("X-ray is unavailable on this page.");
      }
      renderer = rendererFactory(controls, { document: documentObject, window: windowObject });
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
      return { active: true, alreadyActive: false, findingCount: findings.length };
    }

    function runScan(isAutomatic) {
      if (!active) return { active: false, findingCount: 0 };
      renderer.setProgress("Scanning this page…");
      const result = scan({ newElements: new Set(newElements), isAutomatic });
      const backendFindings = backendAdapter?.readAvailableFindings?.() || [];
      const mergedResult = rules?.mergeHipFindings && backendFindings.length
        ? rules.mergeHipFindings(result, backendFindings)
        : result;
      findings = Array.isArray(mergedResult?.findings) ? mergedResult.findings : [];
      references = result?.references instanceof Map ? result.references : new Map();
      coverage = result?.coverage || {};
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
      if (!active || automaticRescans >= MAX_AUTOMATIC_RESCANS) return;
      let relevant = false;
      for (const record of records) {
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
      renderer?.showLauncher();
      findings = [];
      references.clear();
      references = new Map();
      newElements.clear();
      coverage = {};
      automaticRescans = 0;
    }

    function getState() {
      return { active, findingCount: findings.length, referenceCount: references.size, automaticRescans, coverage };
    }

    function destroy() {
      stop();
      renderer?.destroy();
      renderer = null;
    }

    return Object.freeze({ installLauncher, start, stop, destroy, rescan: () => runScan(false), getState });
  }

  global.HipXrayController = Object.freeze({ create, MAX_AUTOMATIC_RESCANS });
})(globalThis);
