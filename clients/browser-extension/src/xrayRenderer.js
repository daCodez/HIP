(function registerHipXrayRenderer(global) {
  "use strict";

  const SCAN_ANIMATION_MS = 2600;
  const MAX_SCAN_BOXES = 180;
  const TONES = Object.freeze({ Critical: "#ef4444", High: "#ef4444", Medium: "#f59e0b", Low: "#60a5fa", Info: "#22c55e" });
  const SCORE_PENALTIES = Object.freeze({ Critical: 30, High: 18, Medium: 9, Low: 4, Info: 0 });
  const SCAN_STAGES = Object.freeze([
    Object.freeze({ label: "Reading page structure", detail: "forms, links and visible elements" }),
    Object.freeze({ label: "Checking transport signals", detail: "page and submission paths" }),
    Object.freeze({ label: "Mapping scripts and frames", detail: "first- and third-party sources" }),
    Object.freeze({ label: "Applying local HIP rules", detail: "plain-language reasons" })
  ]);

  /**
   * Creates the isolated page X-ray UI without reading or changing host-page values.
   * @param {object} controls X-ray controller callbacks.
   * @param {object} environment Browser objects used by production and tests.
   * @returns {object} Renderer lifecycle methods.
   */
  function create(controls, environment = {}) {
    const documentObject = environment.document || global.document;
    const windowObject = environment.window || global.window;
    let host, shadow, launcher, theatre, scanLayer, markerLayer, scanLine, hud;
    let scanView, resultView, statusLabel, scanProgressFill, scanElapsed, scanStageList;
    let scoreLabel, resultProgressFill, statusPill, hostnameLabel, metadata, summary, list;
    let animationFrame = null;
    let animationRunning = false;
    let findings = [];
    let references = new Map();
    let markerNodes = [];
    let scanBoxes = [];
    let selectedTarget = null;
    let technicalMode = false;
    let markersHidden = false;
    let pendingProgress = "";

    function mountLauncher() {
      if (!host) {
        host = documentObject.createElement("div");
        host.dataset.hipXrayOwned = "true";
        shadow = host.attachShadow({ mode: "open" });
        const style = documentObject.createElement("style");
        style.textContent = styleText();
        launcher = actionButton("X-ray this page", "X-ray this page", controls.start, "launcher");
        launcher.prepend(node("span", "scan-icon"));
        shadow.append(style, launcher);
        documentObject.documentElement.append(host);
      }
      launcher.hidden = false;
    }

    function open() {
      mountLauncher();
      cleanupTheatre();
      launcher.hidden = true;
      theatre = node("div", "theatre");
      const scrim = actionButton("", "Close X-ray", controls.exit, "scrim");
      scanLayer = node("div", "scan-layer");
      scanLayer.ariaHidden = "true";
      scanLine = node("div", "scan-line");
      markerLayer = node("div", "marker-layer");
      markerLayer.ariaHidden = "true";
      hud = node("aside", "hud");
      hud.role = "region";
      hud.ariaLabel = "HIP X-ray findings";
      buildHud();
      theatre.append(scrim, scanLayer, scanLine, markerLayer, hud);
      shadow.append(theatre);
      windowObject.addEventListener("keydown", handleKeydown);
    }

    function buildHud() {
      const heading = textNode("h2", "sr-only", "X-ray this page");
      scanView = node("section", "scan-view");
      scanView.append(buildWindowBar("HIP · SCANNING THIS PAGE"));
      const scanBody = node("div", "scan-body");
      const scanLead = node("div", "scan-lead");
      scanLead.append(node("span", "spinner"));
      statusLabel = textNode("p", "scan-status", `scanning ${hostnameForDisplay()}`);
      statusLabel.ariaLive = "polite";
      scanElapsed = textNode("span", "scan-elapsed", "0 ms");
      scanLead.append(statusLabel, scanElapsed);
      const scanProgress = node("div", "scan-progress");
      scanProgressFill = node("div", "scan-progress-fill");
      scanProgress.append(scanProgressFill);
      scanStageList = node("ol", "scan-stage-list");
      SCAN_STAGES.forEach(stage => {
        const item = node("li", "scan-stage");
        item.dataset.state = "pending";
        const indicator = textNode("span", "stage-indicator", "");
        const copy = node("span", "stage-copy");
        copy.append(textNode("strong", "stage-label", stage.label), textNode("span", "stage-detail", stage.detail));
        const state = textNode("span", "stage-state", "");
        item.append(indicator, copy, state);
        scanStageList.append(item);
      });
      scanBody.append(scanLead, scanProgress, scanStageList);
      scanView.append(scanBody);

      resultView = node("section", "result-view");
      resultView.hidden = true;
      resultView.append(buildWindowBar("hip · trust result"));
      const resultBody = node("div", "result-body");
      const resultTop = node("div", "result-top");
      const identity = node("div", "result-identity");
      hostnameLabel = textNode("p", "result-hostname", hostnameForDisplay());
      const scoreRow = node("div", "result-score-row");
      scoreLabel = textNode("strong", "result-score", "0");
      scoreRow.append(scoreLabel, textNode("span", "result-score-unit", "/ 100 · checked today"));
      identity.append(hostnameLabel, scoreRow);
      statusPill = textNode("span", "status-pill", "Checking");
      resultTop.append(identity, statusPill);
      const progress = node("div", "result-progress");
      resultProgressFill = node("div", "result-progress-fill");
      progress.append(resultProgressFill);
      metadata = textNode("p", "metadata", "Inspecting page structure · live");
      list = node("ol", "findings");
      list.ariaLabel = "X-ray findings";
      const toolbar = buildToolbar();
      summary = textNode("p", "summary", "Local page inspection only.");
      const reasonNote = textNode("p", "reason-note", "Every score comes with its reasons. Nothing is hidden.");
      resultBody.append(resultTop, progress, metadata, list, toolbar, summary, reasonNote);
      resultView.append(resultBody);
      hud.append(heading, scanView, resultView);
    }

    function buildWindowBar(label) {
      const bar = node("header", "window-bar");
      const dots = node("span", "window-dots");
      dots.append(node("i", "window-dot"), node("i", "window-dot"), node("i", "window-dot"));
      bar.append(dots, textNode("span", "window-title", label), actionButton("×", "Close X-ray", controls.exit, "icon-close"));
      return bar;
    }

    function buildToolbar() {
      const toolbar = node("div", "toolbar");
      toolbar.role = "toolbar";
      toolbar.ariaLabel = "X-ray controls";
      const plain = modeButton("Plain", "plain", false);
      const technical = modeButton("Technical", "technical", true);
      const hide = actionButton("Hide markers", "Hide numbered page markers", () => toggleMarkers(hide), "tool");
      hide.ariaPressed = "false";
      toolbar.append(plain, technical, hide, actionButton("Rescan", "Rescan the current page", controls.rescan, "tool"), actionButton("Close", "Exit X-ray", controls.exit, "tool tool-close"));
      return toolbar;
    }

    function render(nextFindings, nextReferences, coverage = {}, backend = {}, renderOptions = {}) {
      findings = Array.isArray(nextFindings) ? nextFindings : [];
      references = nextReferences instanceof Map ? nextReferences : new Map();
      selectedTarget = null;
      buildFindingRows();
      buildMarkers();
      buildScanBoxes();
      const limits = [];
      if (coverage.inaccessibleFrameCount > 0) limits.push(`${coverage.inaccessibleFrameCount} inaccessible embedded frame${coverage.inaccessibleFrameCount === 1 ? "" : "s"}`);
      if (coverage.truncated) limits.push("page element cap reached");
      limits.push("closed shadow roots cannot be inspected");
      const backendMessage = backend?.available ? "HIP domain evidence included." : (backend?.message || "Full domain scan unavailable.");
      summary.textContent = `Measured from this page in your browser, just now. ${backendMessage} Limits: ${limits.join("; ")}.`;
      metadata.textContent = `${Number(coverage.inspectedElementCount || 0).toLocaleString()} elements inspected · local X-ray`;
      hostnameLabel.textContent = hostnameForDisplay();
      prepareResultScore();
      if (renderOptions.animate === false || prefersReducedMotion()) completeAnimation();
      else startAnimation();
    }

    function prepareResultScore() {
      const score = scoreFor(findings);
      const status = statusFor(score);
      scoreLabel.textContent = String(score);
      resultProgressFill.style.width = `${score}%`;
      statusPill.textContent = status.label;
      statusPill.dataset.tone = status.tone;
    }

    function buildFindingRows() {
      replaceChildren(list);
      if (windowObject.location?.protocol === "https:") {
        list.append(buildSignalRow({
          title: "Connection is encrypted",
          plainExplanation: "Traffic between this page and your browser uses HTTPS.",
          technicalExplanation: "The top-level page protocol is HTTPS.",
          severity: "Info",
          status: "Safe"
        }, -1));
      }
      if (!findings.length) {
        list.append(buildSignalRow({
          title: "No local page-structure risks detected",
          plainExplanation: "The inspectable part of this page did not trigger a local HIP rule.",
          technicalExplanation: "No versioned local X-ray rule matched the collected page snapshot.",
          severity: "Info",
          status: "Clear"
        }, -1));
      }
      findings.forEach((finding, index) => list.append(buildSignalRow(finding, index)));
    }

    function buildSignalRow(finding, index) {
      const item = node("li", "finding-item");
      const selectable = index >= 0;
      const row = selectable
        ? actionButton("", `Show finding ${index + 1}: ${finding.title}`, () => selectFinding(finding), "finding-row")
        : node("div", "finding-row finding-row-static");
      const dot = node("span", "tone-dot");
      dot.style.background = tone(finding.severity);
      const copy = node("span", "finding-copy");
      const explanation = technicalMode ? finding.technicalExplanation : finding.plainExplanation;
      copy.append(textNode("strong", "finding-title", finding.title), textNode("span", "finding-explanation", explanation));
      const status = textNode("span", "severity", finding.status || statusForSeverity(finding.severity));
      status.style.color = tone(finding.severity);
      row.append(dot, copy, status);
      item.append(row);
      return item;
    }

    function buildMarkers() {
      markerNodes = [];
      replaceChildren(markerLayer);
      const targetOffsets = new Map();
      findings.forEach((finding, index) => {
        const target = references.get(finding.elementRefKey);
        if (!target) return;
        const offset = targetOffsets.get(target) || 0;
        targetOffsets.set(target, offset + 1);
        const marker = textNode("span", "marker", String(index + 1));
        marker.style.background = tone(finding.severity);
        marker.hidden = true;
        markerLayer.append(marker);
        markerNodes.push({ marker, target, offset });
      });
      const highlight = node("div", "highlight");
      highlight.hidden = true;
      markerLayer.append(highlight);
    }

    function buildScanBoxes() {
      scanBoxes = [];
      replaceChildren(scanLayer);
      const candidates = safeQuery("h1,h2,h3,p,a,button,input,img,svg,section").slice(0, MAX_SCAN_BOXES);
      for (const element of candidates) {
        if (element === host || element.closest?.("[data-hip-xray-owned='true']")) continue;
        const rect = element.getBoundingClientRect?.();
        if (!rect || rect.width < 24 || rect.height < 12 || rect.bottom < 0 || rect.top > windowObject.innerHeight) continue;
        if (rect.width > windowObject.innerWidth * .98 && rect.height > windowObject.innerHeight * .9) continue;
        const box = node("div", "scan-box");
        box.style.transform = `translate(${rect.left - 2}px, ${rect.top - 2}px)`;
        box.style.width = `${rect.width + 4}px`;
        box.style.height = `${rect.height + 4}px`;
        box.append(textNode("span", "scan-label", String(element.tagName || "element").toLowerCase()));
        scanLayer.append(box);
        scanBoxes.push({ box, top: rect.top, lit: false });
      }
    }

    function startAnimation() {
      cancelAnimation();
      animationRunning = true;
      pendingProgress = "";
      scanView.hidden = false;
      resultView.hidden = true;
      scanLine.hidden = false;
      scanLine.style.opacity = "1";
      theatre.style.setProperty("--scrim-opacity", "0");
      scanProgressFill.style.width = "0%";
      scanElapsed.textContent = "0 ms";
      statusLabel.textContent = `scanning ${hostnameForDisplay()}`;
      setStageProgress(0);
      scanBoxes.forEach(item => { item.lit = false; item.box.style.opacity = "0"; });
      const startedAt = nowValue();
      const step = timestamp => {
        if (!animationRunning) return;
        const current = Number.isFinite(timestamp) ? timestamp : nowValue();
        const progress = Math.min(1, Math.max(0, (current - startedAt) / SCAN_ANIMATION_MS));
        const eased = progress < .5 ? 2 * progress * progress : 1 - Math.pow(-2 * progress + 2, 2) / 2;
        const y = eased * windowObject.innerHeight;
        theatre.style.setProperty("--scrim-opacity", String(Math.min(.58, progress * 2.2)));
        scanLine.style.transform = `translateY(${y.toFixed(1)}px)`;
        scanProgressFill.style.width = `${Math.round(progress * 100)}%`;
        scanElapsed.textContent = `${Math.round(progress * SCAN_ANIMATION_MS)} ms`;
        setStageProgress(progress);
        scanBoxes.forEach(item => { if (!item.lit && item.top <= y) { item.lit = true; item.box.style.opacity = "1"; } });
        if (progress < 1) animationFrame = windowObject.requestAnimationFrame(step);
        else completeAnimation();
      };
      animationFrame = windowObject.requestAnimationFrame(step);
    }

    function setStageProgress(progress) {
      const activeIndex = Math.min(SCAN_STAGES.length - 1, Math.floor(progress * SCAN_STAGES.length));
      Array.from(scanStageList.children).forEach((item, index) => {
        const state = progress >= 1 || index < activeIndex ? "done" : index === activeIndex ? "active" : "pending";
        item.dataset.state = state;
        item.querySelector(".stage-state").textContent = state === "done" ? "done" : state === "active" ? "…" : "";
      });
    }

    function completeAnimation() {
      cancelAnimation();
      theatre?.style.setProperty("--scrim-opacity", ".58");
      setStageProgress(1);
      scanBoxes.forEach(item => { item.lit = true; item.box.style.opacity = "1"; });
      if (scanLine) scanLine.hidden = true;
      if (scanView) scanView.hidden = true;
      if (resultView) resultView.hidden = false;
      prepareResultScore();
      updateMarkerPositions();
      if (pendingProgress) pendingProgress = "";
    }

    function modeButton(label, mode, technical) {
      const button = actionButton(label, `Show ${mode} explanations`, () => setMode(technical), "tool");
      button.dataset.mode = mode;
      button.ariaPressed = String(technicalMode === technical);
      return button;
    }

    function setMode(nextTechnical) {
      technicalMode = nextTechnical;
      for (const button of shadow.querySelectorAll("[data-mode]")) button.ariaPressed = String((button.dataset.mode === "technical") === technicalMode);
      buildFindingRows();
    }

    function toggleMarkers(button) {
      markersHidden = !markersHidden;
      button.ariaPressed = String(markersHidden);
      button.textContent = markersHidden ? "Show markers" : "Hide markers";
      scanLayer.hidden = markersHidden;
      markerLayer.hidden = markersHidden;
      if (!markersHidden) updateMarkerPositions();
    }

    function selectFinding(finding) {
      const target = references.get(finding.elementRefKey);
      if (!target?.getBoundingClientRect) return;
      selectedTarget = target;
      target.scrollIntoView?.({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "center", inline: "nearest" });
      updateMarkerPositions();
    }

    function updateMarkerPositions() {
      if (!host || markersHidden || !markerLayer) return;
      markerNodes.forEach(({ marker, target, offset }) => {
        if (!target?.isConnected || !target.getBoundingClientRect) { marker.hidden = true; return; }
        const rect = target.getBoundingClientRect();
        marker.hidden = false;
        marker.style.transform = `translate(${clamp(rect.left - 12 + offset * 30, 4, windowObject.innerWidth - 34)}px, ${clamp(rect.top - 12, 4, windowObject.innerHeight - 34)}px)`;
      });
      const highlight = markerLayer.querySelector(".highlight");
      if (selectedTarget?.isConnected && selectedTarget.getBoundingClientRect) positionBox(highlight, selectedTarget.getBoundingClientRect(), 3);
      else if (highlight) highlight.hidden = true;
    }

    function positionBox(element, rect, padding) {
      element.style.transform = `translate(${Math.max(0, rect.left - padding)}px, ${Math.max(0, rect.top - padding)}px)`;
      element.style.width = `${Math.max(0, rect.width + padding * 2)}px`;
      element.style.height = `${Math.max(0, rect.height + padding * 2)}px`;
      element.hidden = false;
    }

    function setProgress(message) {
      pendingProgress = String(message || "");
      if (!animationRunning && statusLabel && !pendingProgress.includes("finding")) statusLabel.textContent = pendingProgress;
    }

    function showLauncher() {
      cleanupTheatre();
      if (launcher) launcher.hidden = false;
      findings = [];
      references.clear();
      references = new Map();
      markerNodes = [];
      scanBoxes = [];
      selectedTarget = null;
    }

    function cleanupTheatre() {
      cancelAnimation();
      windowObject.removeEventListener("keydown", handleKeydown);
      theatre?.remove();
      theatre = scanLayer = markerLayer = scanLine = hud = scanView = resultView = statusLabel = scanProgressFill = scanElapsed = scanStageList = null;
      scoreLabel = resultProgressFill = statusPill = hostnameLabel = metadata = summary = list = null;
    }

    function destroy() { cleanupTheatre(); host?.remove(); host = shadow = launcher = null; }
    function cancelAnimation() { animationRunning = false; if (animationFrame !== null) windowObject.cancelAnimationFrame(animationFrame); animationFrame = null; }
    function handleKeydown(event) { if (event.key === "Escape") controls.exit(); }
    function focus() { /* Repeated activation keeps host-page focus and selection unchanged. */ }
    function tone(severity) { return TONES[severity] || TONES.Info; }
    function statusForSeverity(severity) { return severity === "Critical" ? "Critical" : severity === "High" ? "Risk" : severity === "Medium" ? "Needs work" : severity === "Low" ? "Review" : "Observed"; }
    function scoreFor(items) { return clamp(100 - items.reduce((total, item) => total + (SCORE_PENALTIES[item?.severity] || 0), 0), 0, 100); }
    function statusFor(score) {
      if (score >= 85) return { label: "Trusted", tone: "good" };
      if (score >= 70) return { label: "Mostly Trusted", tone: "good" };
      if (score >= 50) return { label: "Use Caution", tone: "warn" };
      return { label: "High Risk", tone: "risk" };
    }
    function hostnameForDisplay() { return windowObject.location?.hostname || "this page"; }
    function nowValue() { return Number(windowObject.performance?.now?.()) || Date.now(); }
    function prefersReducedMotion() { return Boolean(windowObject.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches); }
    function safeQuery(selector) { try { return Array.from(documentObject.querySelectorAll(selector)); } catch { return []; } }
    function clamp(value, minimum, maximum) { return Math.max(minimum, Math.min(maximum, value)); }
    function replaceChildren(element) { while (element?.firstChild) element.firstChild.remove(); }
    function node(tag, className) { const element = documentObject.createElement(tag); element.className = className; return element; }
    function textNode(tag, className, text) { const element = node(tag, className); element.textContent = text; return element; }
    function actionButton(label, ariaLabel, handler, className) { const button = textNode("button", className, label); button.type = "button"; button.ariaLabel = ariaLabel; button.addEventListener("click", handler); return button; }

    return Object.freeze({ mountLauncher, open, render, setProgress, focus, updateMarkerPositions, showLauncher, destroy });
  }

  function styleText() {
    return `
      :host{all:initial;position:fixed;inset:0;z-index:2147483646;pointer-events:none;color-scheme:dark;font-family:Satoshi,"Segoe UI",system-ui,sans-serif}
      *{box-sizing:border-box}.launcher{pointer-events:auto;position:fixed;right:24px;bottom:24px;display:inline-flex;align-items:center;gap:10px;padding:13px 20px;border:1px solid #14b8a6;border-radius:11px;background:#111827;color:#14b8a6;box-shadow:0 12px 34px rgba(0,0,0,.34);font:700 15px/1 Satoshi,"Segoe UI",system-ui,sans-serif;cursor:pointer}.launcher:hover{background:#102522}.scan-icon{width:17px;height:17px;background:linear-gradient(#14b8a6,#14b8a6) 0 3px/17px 2px no-repeat,linear-gradient(#14b8a6,#14b8a6) 3px 8px/11px 2px no-repeat,linear-gradient(#14b8a6,#14b8a6) 0 13px/17px 2px no-repeat}
      .theatre{--scrim-opacity:0;position:fixed;inset:0;pointer-events:none}.scrim{pointer-events:auto;position:absolute;inset:0;width:100%;height:100%;border:0;background:#0b1220;opacity:var(--scrim-opacity);backdrop-filter:saturate(.45) blur(1px);cursor:default}.scan-layer,.marker-layer{position:fixed;inset:0;pointer-events:none}.scan-line{position:fixed;left:0;right:0;top:0;height:2px;background:linear-gradient(90deg, transparent, #14b8a6, transparent);box-shadow:0 0 26px 5px rgba(20,184,166,.45);transform:translateY(-4px)}.scan-box{position:fixed;left:0;top:0;border:1px solid #14b8a6;border-radius:4px;opacity:0;box-shadow:inset 0 0 22px rgba(20,184,166,.1);transition:opacity .12s ease}.scan-label{position:absolute;left:0;top:-15px;color:#14b8a6;opacity:.85;font:9px/1 "JetBrains Mono",Consolas,monospace;letter-spacing:.06em}
      .hud{pointer-events:auto;position:fixed;right:24px;top:16px;width:min(560px,calc(100vw - 48px));max-height:calc(100vh - 32px);overflow-y:auto;border:1px solid #1f2937;border-radius:18px;background:#111827;color:#f8fafb;box-shadow:0 26px 70px rgba(0,0,0,.55);font:14px/1.45 Satoshi,"Segoe UI",system-ui,sans-serif}.window-bar{position:sticky;top:0;z-index:4;display:flex;align-items:center;gap:14px;min-height:62px;padding:0 26px;border-bottom:1px solid #1f2937;background:#161e2e}.window-dots{display:flex;gap:10px}.window-dot{display:block;width:12px;height:12px;border-radius:50%;background:#202a3d}.window-title{flex:1;color:#9ca3af;font:600 14px/1 "JetBrains Mono",Consolas,monospace;letter-spacing:.02em}.icon-close{display:grid;place-items:center;width:30px;height:30px;padding:0;border:1px solid transparent;border-radius:8px;background:transparent;color:#9ca3af;font-size:18px;cursor:pointer}.icon-close:hover{border-color:#334155;color:#f8fafb}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
      .scan-body{position:relative;min-height:430px;padding:34px 34px 38px;overflow:hidden}.scan-body:before{content:"";position:absolute;inset:-45% -15%;background:radial-gradient(circle at 15% 30%,rgba(20,184,166,.13),transparent 46%);animation:scan-aurora 4s ease-in-out infinite;pointer-events:none}.scan-lead{position:relative;display:flex;align-items:center;gap:13px;margin-bottom:15px}.spinner{width:20px;height:20px;flex:0 0 auto;border:2px solid #334155;border-top-color:#14b8a6;border-radius:50%;animation:spin .85s linear infinite}.scan-status{flex:1;min-width:0;margin:0;overflow:hidden;color:#f8fafb;font:600 14px/1.3 "JetBrains Mono",Consolas,monospace;text-overflow:ellipsis;white-space:nowrap}.scan-elapsed{color:#9ca3af;font:12px/1 "JetBrains Mono",Consolas,monospace}.scan-progress,.result-progress{height:6px;overflow:hidden;border-radius:999px;background:#161e2e}.scan-progress{position:relative;margin-bottom:30px}.scan-progress-fill,.result-progress-fill{height:100%;width:0;background:linear-gradient(90deg,#1f6feb,#14b8a6);transition:width .16s linear}.scan-stage-list{position:relative;display:flex;flex-direction:column;gap:13px;margin:0;padding:0;list-style:none}.scan-stage{display:grid;grid-template-columns:18px minmax(0,1fr) auto;align-items:start;gap:12px;padding:13px 14px;border:1px solid #1f2937;border-radius:11px;background:#0b1220;opacity:.48;transition:opacity .2s ease,border-color .2s ease,transform .2s ease}.scan-stage[data-state="active"]{border-color:#245b57;opacity:1;transform:translateX(3px)}.scan-stage[data-state="done"]{opacity:1}.stage-indicator{width:8px;height:8px;margin-top:5px;border-radius:50%;background:#334155}.scan-stage[data-state="active"] .stage-indicator{background:#14b8a6;box-shadow:0 0 0 5px rgba(20,184,166,.12);animation:pulse 1s ease-in-out infinite}.scan-stage[data-state="done"] .stage-indicator{background:#22c55e}.stage-label,.stage-detail{display:block}.stage-label{color:#f8fafb;font-size:14px;line-height:1.35}.stage-detail{margin-top:2px;color:#9ca3af;font-size:12px;line-height:1.4}.stage-state{color:#22c55e;font:700 11px/1.4 "JetBrains Mono",Consolas,monospace}
      .result-view{animation:result-in .32s ease-out}.result-body{padding:34px 34px 30px}.result-top{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;margin-bottom:28px}.result-hostname{margin:0 0 9px;color:#9ca3af;font:600 14px/1.4 "JetBrains Mono",Consolas,monospace;overflow-wrap:anywhere}.result-score-row{display:flex;align-items:baseline;gap:10px}.result-score{color:#14b8a6;font:800 66px/.95 "JetBrains Mono",Consolas,monospace;letter-spacing:-.05em}.result-score-unit{color:#9ca3af;font-size:16px}.status-pill{flex:0 0 auto;margin-top:1px;padding:9px 16px;border-radius:999px;background:rgba(34,197,94,.13);color:#22c55e;font-size:13px;font-weight:700;white-space:nowrap}.status-pill[data-tone="warn"]{background:rgba(245,158,11,.13);color:#f59e0b}.status-pill[data-tone="risk"]{background:rgba(239,68,68,.13);color:#ef4444}.result-progress{margin-bottom:14px}.metadata{margin:0 0 24px;color:#9ca3af;font:11px/1.4 "JetBrains Mono",Consolas,monospace}.findings{display:flex;flex-direction:column;gap:12px;margin:0;padding:0;list-style:none}.finding-row{display:flex;align-items:flex-start;gap:13px;width:100%;min-height:88px;padding:18px 20px;border:1px solid #1f2937;border-radius:13px;background:#0b1220;text-align:left;cursor:pointer}.finding-row:hover{border-color:#334155}.finding-row-static{cursor:default}.tone-dot{width:8px;height:8px;flex:0 0 auto;margin-top:6px;border-radius:50%}.finding-copy{flex:1;min-width:0}.finding-title,.finding-explanation{display:block}.finding-title{color:#f8fafb;font-size:15px;font-weight:700;line-height:1.35}.finding-explanation{margin-top:3px;color:#9ca3af;font-size:13px;line-height:1.45}.severity{flex:0 0 auto;margin-top:2px;font-size:12px;font-weight:700;white-space:nowrap}.toolbar{display:flex;flex-wrap:wrap;gap:7px;margin-top:18px;padding-top:16px;border-top:1px solid #1f2937}.tool{padding:7px 10px;border:1px solid #263244;border-radius:8px;background:transparent;color:#cbd5e1;font:700 11px/1 Satoshi,"Segoe UI",system-ui,sans-serif;cursor:pointer}.tool:hover,.tool[aria-pressed="true"]{border-color:#14b8a6;color:#14b8a6}.tool-close{margin-left:auto}.summary{margin:16px 0 0;color:#9ca3af;font-size:11.5px;line-height:1.5}.reason-note{margin:20px 0 0;padding-top:18px;border-top:1px solid #1f2937;color:#9ca3af;font-size:13px;line-height:1.5}
      .marker{position:fixed;left:0;top:0;display:grid;place-items:center;width:28px;height:28px;border:2px solid #fff;border-radius:50%;color:#fff;box-shadow:0 2px 10px rgba(0,0,0,.7);font:800 12px/1 "JetBrains Mono",Consolas,monospace}.highlight{position:fixed;left:0;top:0;border:2px solid #14b8a6;border-radius:4px;box-shadow:inset 0 0 22px rgba(20,184,166,.12),0 0 0 3px rgba(20,184,166,.2)}button:focus-visible{outline:3px solid #5eead4;outline-offset:3px}[hidden]{display:none!important}
      @keyframes spin{to{transform:rotate(360deg)}}@keyframes pulse{50%{transform:scale(.72);opacity:.65}}@keyframes scan-aurora{50%{transform:translate3d(8%,4%,0)}}@keyframes result-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
      @media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important;animation:none!important}}@media(max-width:620px){.launcher{right:12px;bottom:12px}.hud{inset:8px;width:auto;max-height:calc(100vh - 16px)}.window-bar{min-height:54px;padding:0 18px}.scan-body,.result-body{padding:24px 20px}.result-top{display:block}.status-pill{display:inline-block;margin-top:14px}.result-score{font-size:54px}.result-score-unit{font-size:13px}.finding-row{min-height:0;padding:15px}.tool-close{margin-left:0}}
    `;
  }

  global.HipXrayRenderer = Object.freeze({ create, SCAN_ANIMATION_MS });
})(globalThis);
