(function registerHipXrayRenderer(global) {
  "use strict";

  const SCAN_ANIMATION_MS = 2600;
  const MAX_SCAN_BOXES = 180;
  const PANEL_MARGIN = 16;
  const TARGET_RESOLVE_COOLDOWN_MS = 500;
  const LAUNCHER_POSITIONS = new Set(["bottom-left", "bottom-right", "top-left", "top-right"]);
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
    let launcherPosition = normalizeLauncherPosition(environment.launcherPosition);
    let host, shadow, launcher, theatre, scrim, scanLayer, markerLayer, scanLine, hud, collapsedPill;
    let scanView, resultView, statusLabel, scanProgressFill, scanElapsed, scanStageList;
    let scoreLabel, resultProgressFill, statusPill, hostnameLabel, metadata, summary, list, countLabel, categoryFilter, markerToggle;
    let animationFrame = null;
    let animationTimeout = null;
    let animationRunning = false;
    let findings = [];
    let references = new Map();
    let markerNodes = [];
    let scanBoxes = [];
    let selectedTarget = null;
    let selectedFindingId = "";
    let technicalMode = false;
    let markersHidden = false;
    let panelCollapsed = false;
    let markerOpenedPanel = false;
    let severityFilter = "all";
    let categoryFilterValue = "all";
    let pendingProgress = "";
    let resizeObserver = null;
    const resolvedTargets = new Map();

    function mountLauncher() {
      if (!host) {
        host = documentObject.createElement("div");
        host.dataset.hipXrayOwned = "true";
        shadow = host.attachShadow({ mode: "open" });
        const style = documentObject.createElement("style");
        style.textContent = styleText();
        launcher = actionButton("X-ray this page", "X-ray this page", controls.start, "launcher");
        launcher.dataset.position = launcherPosition;
        launcher.prepend(node("span", "scan-icon"));
        shadow.append(style, launcher);
        documentObject.documentElement.append(host);
      }
      launcher.hidden = false;
    }

    /** Moves only HIP's floating launcher; host-page elements are never changed. */
    function setLauncherPosition(value) {
      launcherPosition = normalizeLauncherPosition(value);
      if (launcher) launcher.dataset.position = launcherPosition;
      return launcherPosition;
    }

    function open() {
      mountLauncher();
      cleanupTheatre();
      launcher.hidden = true;
      theatre = node("div", "theatre");
      scrim = node("div", "scrim");
      scrim.ariaHidden = "true";
      scanLayer = node("div", "scan-layer");
      scanLayer.ariaHidden = "true";
      scanLine = node("div", "scan-line");
      markerLayer = node("div", "marker-layer");
      hud = node("aside", "hud");
      hud.role = "region";
      hud.ariaLabel = "HIP X-ray findings";
      hud.dataset.dock = "top-right";
      buildHud();
      collapsedPill = actionButton("", "Open Page X-ray results", () => expandPanel(true), "results-pill");
      collapsedPill.hidden = true;
      updateCollapsedPill();
      theatre.append(scrim, scanLayer, scanLine, markerLayer, hud, collapsedPill);
      shadow.append(theatre);
      windowObject.addEventListener("keydown", handleKeydown);
      attachResizeObserver();
    }

    function buildHud() {
      const heading = textNode("h2", "sr-only", "Page X-ray results");
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
      resultView.append(buildWindowBar("HIP · PAGE X-RAY RESULTS", true));
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
      const navigator = node("div", "navigator");
      countLabel = textNode("p", "finding-count", "0 findings");
      countLabel.ariaLive = "polite";
      navigator.append(countLabel, buildFilters());
      list = node("ol", "findings");
      list.ariaLabel = "X-ray findings";
      const toolbar = buildToolbar();
      summary = textNode("p", "summary", "Local page inspection only.");
      const reasonNote = textNode("p", "reason-note", "Every score comes with its reasons. Nothing is hidden.");
      resultBody.append(resultTop, progress, metadata, navigator, list, toolbar, summary, reasonNote);
      resultView.append(resultBody);
      hud.append(heading, scanView, resultView);
    }

    function buildWindowBar(label, collapsible = false) {
      const bar = node("header", "window-bar");
      const dots = node("span", "window-dots");
      dots.append(node("i", "window-dot"), node("i", "window-dot"), node("i", "window-dot"));
      bar.append(dots, textNode("span", "window-title", label));
      if (collapsible) bar.append(actionButton("−", "Collapse Page X-ray results", () => collapsePanel(), "icon-collapse"));
      bar.append(actionButton("×", "Close X-ray", controls.exit, "icon-close"));
      return bar;
    }

    function buildFilters() {
      const controlsContainer = node("div", "filters");
      controlsContainer.role = "group";
      controlsContainer.ariaLabel = "Filter X-ray findings";
      for (const filter of [
        ["all", "All"], ["risk", "Risk"], ["caution", "Caution"], ["review", "Review"]
      ]) {
        const button = actionButton(filter[1], `Show ${filter[1].toLowerCase()} findings`, () => setSeverityFilter(filter[0]), "filter-chip");
        button.dataset.severityFilter = filter[0];
        button.ariaPressed = String(severityFilter === filter[0]);
        controlsContainer.append(button);
      }
      categoryFilter = node("select", "category-filter");
      categoryFilter.ariaLabel = "Filter findings by category";
      categoryFilter.addEventListener("change", event => {
        categoryFilterValue = event.currentTarget?.selectedOptions?.[0]?.dataset?.filterCategory || "all";
        refreshFilteredView();
      });
      controlsContainer.append(categoryFilter);
      return controlsContainer;
    }

    function buildToolbar() {
      const toolbar = node("div", "toolbar");
      toolbar.role = "toolbar";
      toolbar.ariaLabel = "X-ray controls";
      const plain = modeButton("Plain", "plain", false);
      const technical = modeButton("Technical", "technical", true);
      markerToggle = actionButton("Markers on", "Hide numbered page markers", () => toggleMarkers(markerToggle), "tool marker-toggle");
      markerToggle.ariaPressed = String(!markersHidden);
      toolbar.append(plain, technical, markerToggle, actionButton("Rescan", "Rescan the current page", controls.rescan, "tool"), actionButton("Close", "Exit X-ray", controls.exit, "tool tool-close"));
      return toolbar;
    }

    function render(nextFindings, nextReferences, coverage = {}, backend = {}, renderOptions = {}) {
      findings = Array.isArray(nextFindings) ? nextFindings : [];
      references = nextReferences instanceof Map ? nextReferences : new Map();
      resolvedTargets.clear();
      if (selectedFindingId && !findings.some(finding => finding.id === selectedFindingId)) selectedFindingId = "";
      selectedTarget = selectedFindingId ? resolveFindingTarget(findings.find(finding => finding.id === selectedFindingId)) : null;
      populateCategoryFilter();
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
      updateFindingCount();
      updateCollapsedPill();
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
      findings.forEach((finding, index) => {
        if (findingMatchesFilters(finding)) list.append(buildSignalRow(finding, index));
      });
    }

    function buildSignalRow(finding, index) {
      const item = node("li", "finding-item");
      const selectable = index >= 0;
      if (selectable) {
        item.dataset.findingId = finding.id;
        item.dataset.selected = String(finding.id === selectedFindingId);
      }
      const row = selectable
        ? actionButton("", `Locate finding ${index + 1}: ${finding.title}`, () => selectFinding(finding, { focusRow: false }), "finding-row")
        : node("div", "finding-row finding-row-static");
      if (selectable) {
        row.dataset.findingId = finding.id;
        row.ariaPressed = String(finding.id === selectedFindingId);
      }
      const dot = node("span", "tone-dot");
      dot.style.background = tone(finding.severity);
      const copy = node("span", "finding-copy");
      const explanation = technicalMode ? finding.technicalExplanation : finding.plainExplanation;
      const title = textNode("strong", "finding-title", finding.title);
      if (selectable) title.prepend(textNode("span", "finding-number", String(index + 1).padStart(2, "0")));
      copy.append(title, textNode("span", "finding-explanation", explanation));
      const status = textNode("span", "severity", finding.status || statusForSeverity(finding.severity));
      status.style.color = tone(finding.severity);
      row.append(dot, copy, status);
      item.append(row);
      if (selectable) {
        const target = resolveFindingTarget(finding);
        const details = node("div", "finding-details");
        details.hidden = finding.id !== selectedFindingId;
        details.append(
          detailLine("Evidence", finding.evidence),
          detailLine("What to do", finding.remediation),
          textNode("p", target ? "target-state" : "target-state target-missing", target ? "Linked page element available" : "Element no longer available")
        );
        item.append(details);
      }
      return item;
    }

    function detailLine(label, value) {
      const line = node("p", "detail-line");
      line.append(textNode("strong", "detail-label", label), textNode("span", "detail-copy", value));
      return line;
    }

    function buildMarkers() {
      markerNodes = [];
      replaceChildren(markerLayer);
      const targetOffsets = new Map();
      findings.forEach((finding, index) => {
        const target = resolveFindingTarget(finding);
        if (!target) return;
        const offset = targetOffsets.get(target) || 0;
        targetOffsets.set(target, offset + 1);
        const frame = node("div", "marker-frame");
        frame.style.borderColor = tone(finding.severity);
        frame.style.setProperty("--marker-tone", tone(finding.severity));
        frame.style.zIndex = String(severityZIndex(finding.severity));
        frame.hidden = true;
        const marker = actionButton("", `Open finding ${index + 1}: ${finding.title}`, () => activateMarker(finding), "marker");
        marker.dataset.findingId = finding.id;
        marker.dataset.severity = finding.severity;
        marker.style.setProperty("--marker-tone", tone(finding.severity));
        marker.style.zIndex = String(100 + severityZIndex(finding.severity));
        marker.append(textNode("span", "marker-number", String(index + 1).padStart(2, "0")), textNode("span", "marker-label", markerSummary(finding)));
        marker.hidden = true;
        markerLayer.append(frame, marker);
        markerNodes.push({ marker, frame, finding, target, offset, lastResolveAt: 0 });
      });
      const highlight = node("div", "highlight");
      highlight.hidden = true;
      markerLayer.append(highlight);
      observeMarkerTargets();
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
      const scheduleTimeout = environment.setTimeout || global.setTimeout;
      if (typeof scheduleTimeout === "function") {
        animationTimeout = scheduleTimeout(() => completeAnimation(), SCAN_ANIMATION_MS + 350);
      }
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
      theatre?.style.setProperty("--scrim-opacity", "0");
      setStageProgress(1);
      scanBoxes.forEach(item => { item.lit = true; item.box.style.opacity = "0"; });
      if (scanLine) scanLine.hidden = true;
      if (scanView) scanView.hidden = true;
      if (resultView) resultView.hidden = false;
      if (scrim) scrim.hidden = true;
      prepareResultScore();
      updateMarkerPositions();
      if (panelCollapsed) collapsePanel(false);
      else expandPanel(false);
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

    function setSeverityFilter(nextFilter) {
      severityFilter = nextFilter;
      for (const button of shadow.querySelectorAll("[data-severity-filter]")) {
        button.ariaPressed = String(button.dataset.severityFilter === severityFilter);
      }
      refreshFilteredView();
    }

    function populateCategoryFilter() {
      if (!categoryFilter) return;
      const previous = categoryFilterValue;
      replaceChildren(categoryFilter);
      categoryFilter.append(optionNode("all", "All categories"));
      const categories = [...new Set(findings.map(finding => finding.category).filter(Boolean))].sort((left, right) => left.localeCompare(right));
      categories.forEach(category => categoryFilter.append(optionNode(category, category)));
      categoryFilterValue = categories.includes(previous) ? previous : "all";
      for (const option of Array.from(categoryFilter.options || [])) option.selected = option.dataset.filterCategory === categoryFilterValue;
    }

    function optionNode(value, label) {
      const option = textNode("option", "", label);
      option.dataset.filterCategory = value;
      return option;
    }

    function findingMatchesFilters(finding) {
      const severityMatches = severityFilter === "all" ||
        (severityFilter === "risk" && ["Critical", "High"].includes(finding.severity)) ||
        (severityFilter === "caution" && finding.severity === "Medium") ||
        (severityFilter === "review" && ["Low", "Info"].includes(finding.severity));
      return severityMatches && (categoryFilterValue === "all" || finding.category === categoryFilterValue);
    }

    function refreshFilteredView() {
      buildFindingRows();
      updateFindingCount();
      updateMarkerPositions();
    }

    function updateFindingCount() {
      const visibleCount = findings.filter(findingMatchesFilters).length;
      if (countLabel) countLabel.textContent = visibleCount === findings.length
        ? `${findings.length} ${findings.length === 1 ? "finding" : "findings"}`
        : `${visibleCount} of ${findings.length} findings`;
    }

    function toggleMarkers(button) {
      markersHidden = !markersHidden;
      button.ariaPressed = String(!markersHidden);
      button.ariaLabel = markersHidden ? "Show numbered page markers" : "Hide numbered page markers";
      button.textContent = markersHidden ? "Show markers" : "Markers on";
      scanLayer.hidden = markersHidden;
      markerLayer.hidden = markersHidden;
      if (!markersHidden) updateMarkerPositions();
    }

    function selectFinding(finding, options = {}) {
      if (!options.fromMarker) markerOpenedPanel = false;
      selectedFindingId = finding.id;
      const target = resolveFindingTarget(finding, true);
      selectedTarget = target;
      buildFindingRows();
      if (!target?.getBoundingClientRect) {
        controls.updatePositions();
        focusSelectedRow(options.focusRow === true);
        return;
      }
      target.scrollIntoView?.({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "center", inline: "nearest" });
      emphasizeMarker(finding.id);
      focusSelectedRow(options.focusRow === true);
      controls.updatePositions();
    }

    function activateMarker(finding) {
      markerOpenedPanel = true;
      selectFinding(finding, { focusRow: true, fromMarker: true });
      expandPanel(false);
      focusSelectedRow(true);
    }

    function focusSelectedRow(shouldFocus) {
      if (!shouldFocus) return;
      const row = findRow(selectedFindingId);
      row?.focus?.({ preventScroll: true });
    }

    function findRow(findingId) {
      return Array.from(shadow?.querySelectorAll?.(".finding-row[data-finding-id]") || [])
        .find(row => row.dataset.findingId === findingId);
    }

    function emphasizeMarker(findingId) {
      markerNodes.forEach(entry => {
        const selected = entry.finding.id === findingId;
        entry.marker.dataset.selected = String(selected);
        entry.frame.dataset.selected = String(selected);
      });
    }

    function updateMarkerPositions() {
      if (!host || markersHidden || !markerLayer) return;
      const visibleTargetRects = [];
      const safeTop = stickyTopInset();
      markerNodes.forEach(entry => {
        const { marker, frame, finding, offset } = entry;
        if (!findingMatchesFilters(finding)) { marker.hidden = true; frame.hidden = true; return; }
        let target = entry.target;
        if (!target?.isConnected || !target.getBoundingClientRect) {
          const now = nowValue();
          if (now - entry.lastResolveAt >= TARGET_RESOLVE_COOLDOWN_MS) {
            entry.lastResolveAt = now;
            target = resolveFindingTarget(finding, true);
            entry.target = target;
          }
        }
        if (!target?.isConnected || !target.getBoundingClientRect) { marker.hidden = true; frame.hidden = true; updateRowAvailability(finding.id, false); return; }
        const rect = target.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0 || rect.bottom < 0 || rect.top > windowObject.innerHeight || rect.right < 0 || rect.left > windowObject.innerWidth) {
          marker.hidden = true;
          frame.hidden = true;
          return;
        }
        updateRowAvailability(finding.id, true);
        positionBox(frame, rect, 2);
        frame.hidden = false;
        marker.hidden = false;
        const estimatedWidth = Math.min(240, Math.max(88, marker.textContent.length * 7 + 42));
        const markerX = clamp(rect.left + offset * 18, 6, Math.max(6, windowObject.innerWidth - estimatedWidth - 6));
        const markerY = clamp(rect.top - 31 - offset * 26, safeTop + 6, Math.max(safeTop + 6, windowObject.innerHeight - 34));
        marker.style.transform = `translate(${markerX}px, ${markerY}px)`;
        visibleTargetRects.push(rectLike(marker.getBoundingClientRect?.()));
      });
      const highlight = markerLayer.querySelector(".highlight");
      if (selectedTarget?.isConnected && selectedTarget.getBoundingClientRect) positionBox(highlight, selectedTarget.getBoundingClientRect(), 3);
      else if (highlight) highlight.hidden = true;
      emphasizeMarker(selectedFindingId);
      placePanelAvoidingMarkers(Boolean(selectedTarget), visibleTargetRects);
    }

    function positionBox(element, rect, padding) {
      element.style.transform = `translate(${Math.max(0, rect.left - padding)}px, ${Math.max(0, rect.top - padding)}px)`;
      element.style.width = `${Math.max(0, rect.width + padding * 2)}px`;
      element.style.height = `${Math.max(0, rect.height + padding * 2)}px`;
      element.hidden = false;
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

    function updateRowAvailability(findingId, available) {
      const item = Array.from(shadow?.querySelectorAll?.(".finding-item[data-finding-id]") || [])
        .find(candidate => candidate.dataset.findingId === findingId);
      const state = item?.querySelector?.(".target-state");
      if (!state) return;
      state.textContent = available ? "Linked page element available" : "Element no longer available";
      state.classList?.toggle?.("target-missing", !available);
    }

    function collapsePanel(persistPreference = true) {
      if (!hud || !collapsedPill) return;
      if (persistPreference) {
        panelCollapsed = true;
        markerOpenedPanel = false;
      }
      hud.hidden = true;
      collapsedPill.hidden = false;
      updateCollapsedPill();
      placeCollapsedPill();
      if (persistPreference) collapsedPill.focus?.({ preventScroll: true });
    }

    function expandPanel(focusPanel = false, persistPreference = true) {
      if (!hud || !collapsedPill) return;
      if (persistPreference) {
        panelCollapsed = false;
        markerOpenedPanel = true;
      }
      collapsedPill.hidden = true;
      hud.hidden = false;
      placePanelAvoidingMarkers(false);
      if (focusPanel) (findRow(selectedFindingId) || hud.querySelector?.(".icon-collapse"))?.focus?.({ preventScroll: true });
    }

    function updateCollapsedPill() {
      if (!collapsedPill) return;
      replaceChildren(collapsedPill);
      collapsedPill.append(
        textNode("span", "pill-count", String(findings.length)),
        textNode("span", "pill-label", "Page X-ray results"),
        textNode("span", "pill-open", "Open")
      );
      collapsedPill.ariaLabel = `Open Page X-ray results, ${findings.length} ${findings.length === 1 ? "finding" : "findings"}`;
    }

    function placeCollapsedPill() {
      if (!collapsedPill || collapsedPill.hidden) return;
      const targetRect = selectedTarget?.isConnected ? rectLike(selectedTarget.getBoundingClientRect()) : null;
      const size = collapsedPill.getBoundingClientRect?.() || { width: 230, height: 44 };
      const placement = choosePanelPlacement(
        { width: windowObject.innerWidth, height: windowObject.innerHeight },
        { width: size.width || 230, height: size.height || 44 },
        markerNodes.filter(entry => !entry.marker.hidden).map(entry => rectLike(entry.marker.getBoundingClientRect?.())),
        targetRect,
        PANEL_MARGIN
      );
      collapsedPill.dataset.dock = placement.dock;
    }

    function placePanelAvoidingMarkers(collapseWhenBlocked, visibleRects = null) {
      if (!hud || hud.hidden || !resultView || resultView.hidden) return;
      const panelRect = hud.getBoundingClientRect?.();
      if (!panelRect?.width || !panelRect?.height) return;
      const targetRect = selectedTarget?.isConnected ? rectLike(selectedTarget.getBoundingClientRect()) : null;
      const obstacles = visibleRects || markerNodes
        .filter(entry => !entry.marker.hidden)
        .map(entry => rectLike(entry.marker.getBoundingClientRect?.()));
      const placement = choosePanelPlacement(
        { width: windowObject.innerWidth, height: windowObject.innerHeight },
        { width: panelRect.width, height: panelRect.height },
        obstacles,
        targetRect,
        PANEL_MARGIN
      );
      if (collapseWhenBlocked && !markerOpenedPanel && placement.selectedOverlap > 0) {
        collapsePanel(false);
        return;
      }
      hud.dataset.dock = placement.dock;
    }

    function attachResizeObserver() {
      resizeObserver?.disconnect?.();
      const ResizeObserverType = environment.ResizeObserver || windowObject.ResizeObserver || global.ResizeObserver;
      if (typeof ResizeObserverType !== "function") return;
      resizeObserver = new ResizeObserverType(() => controls.updatePositions());
      if (hud) resizeObserver.observe(hud);
    }

    function observeMarkerTargets() {
      if (!resizeObserver) return;
      resizeObserver.disconnect();
      if (hud) resizeObserver.observe(hud);
      markerNodes.forEach(entry => { if (entry.target?.isConnected) resizeObserver.observe(entry.target); });
    }

    function stickyTopInset() {
      if (typeof documentObject.elementsFromPoint !== "function" || typeof windowObject.getComputedStyle !== "function") return 0;
      const candidates = documentObject.elementsFromPoint(Math.max(1, windowObject.innerWidth / 2), 1).slice(0, 8);
      let inset = 0;
      for (const element of candidates) {
        if (element === host || element?.closest?.("[data-hip-xray-owned='true']")) continue;
        const style = windowObject.getComputedStyle(element);
        if (!["fixed", "sticky"].includes(style?.position)) continue;
        const rect = element.getBoundingClientRect?.();
        if (rect && rect.top <= 1 && rect.bottom > 0 && rect.height < windowObject.innerHeight * .4) inset = Math.max(inset, rect.bottom);
      }
      return Math.min(inset, windowObject.innerHeight * .4);
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
      selectedFindingId = "";
      resolvedTargets.clear();
    }

    function cleanupTheatre() {
      cancelAnimation();
      resizeObserver?.disconnect?.();
      resizeObserver = null;
      windowObject.removeEventListener("keydown", handleKeydown);
      theatre?.remove();
      theatre = scrim = scanLayer = markerLayer = scanLine = hud = collapsedPill = scanView = resultView = statusLabel = scanProgressFill = scanElapsed = scanStageList = null;
      scoreLabel = resultProgressFill = statusPill = hostnameLabel = metadata = summary = list = countLabel = categoryFilter = markerToggle = null;
    }

    function resetForNavigation() {
      selectedFindingId = "";
      selectedTarget = null;
      resolvedTargets.clear();
      if (host && !theatre) launcher.hidden = false;
    }
    function destroy() { cleanupTheatre(); host?.remove(); host = shadow = launcher = null; resolvedTargets.clear(); }
    function cancelAnimation() {
      animationRunning = false;
      if (animationFrame !== null) windowObject.cancelAnimationFrame(animationFrame);
      animationFrame = null;
      if (animationTimeout !== null) (environment.clearTimeout || global.clearTimeout)?.(animationTimeout);
      animationTimeout = null;
    }
    function handleKeydown(event) { if (event.key === "Escape") controls.exit(); }
    function focus() { if (hud?.hidden) expandPanel(true); else hud?.querySelector?.(".icon-collapse")?.focus?.({ preventScroll: true }); }
    function tone(severity) { return TONES[severity] || TONES.Info; }
    function severityZIndex(severity) { return ({ Info: 1, Low: 2, Medium: 3, High: 4, Critical: 5 })[severity] || 1; }
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

    return Object.freeze({ mountLauncher, open, render, setProgress, setLauncherPosition, focus, updateMarkerPositions, showLauncher, resetForNavigation, isMounted: () => Boolean(host?.isConnected), destroy });
  }

  /** Accepts only the four viewport-safe corners supported by the options page. */
  function normalizeLauncherPosition(value) {
    return LAUNCHER_POSITIONS.has(value) ? value : "bottom-left";
  }

  /** Returns a compact, evidence-safe marker label without inferring AI origin. */
  function markerSummary(finding = {}) {
    const severity = finding.severity === "Critical" || finding.severity === "High" ? "Risky" :
      finding.severity === "Medium" ? "Caution" : finding.severity === "Low" ? "Review" : "Observed";
    const category = String(finding.category || "Finding").slice(0, 54);
    const provenanceText = `${finding.title || ""} ${finding.evidence || ""}`.toLowerCase();
    if (/media|provenance/.test(category.toLowerCase())) {
      if (/confirmed ai/.test(provenanceText)) return "Media · Confirmed AI";
      if (/likely ai/.test(provenanceText)) return "Media · Likely AI";
      if (/unknown|unverified/.test(provenanceText)) return "Media · Origin unknown";
      return "Media · Unverified";
    }
    return `${severity} · ${category}`;
  }

  /** Normalizes a DOMRect-like value for collision calculations and tests. */
  function rectLike(rect) {
    if (!rect) return { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 };
    const left = Number(rect.left) || 0;
    const top = Number(rect.top) || 0;
    const width = Math.max(0, Number(rect.width) || Math.max(0, (Number(rect.right) || 0) - left));
    const height = Math.max(0, Number(rect.height) || Math.max(0, (Number(rect.bottom) || 0) - top));
    return { left, top, right: left + width, bottom: top + height, width, height };
  }

  /** Calculates the overlap area between two normalized rectangles. */
  function intersectionArea(left, right) {
    if (!left || !right) return 0;
    return Math.max(0, Math.min(left.right, right.right) - Math.max(left.left, right.left)) *
      Math.max(0, Math.min(left.bottom, right.bottom) - Math.max(left.top, right.top));
  }

  /** Chooses the viewport corner with the least marker and selected-target overlap. */
  function choosePanelPlacement(viewport, panel, obstacles = [], selected = null, margin = PANEL_MARGIN) {
    const width = Math.min(Math.max(1, panel.width || 1), Math.max(1, viewport.width - margin * 2));
    const height = Math.min(Math.max(1, panel.height || 1), Math.max(1, viewport.height - margin * 2));
    const candidates = [
      ["top-left", margin, margin],
      ["top-right", viewport.width - width - margin, margin],
      ["bottom-left", margin, viewport.height - height - margin],
      ["bottom-right", viewport.width - width - margin, viewport.height - height - margin]
    ].map(([dock, left, top]) => {
      const rect = rectLike({ left, top, width, height });
      const selectedOverlap = intersectionArea(rect, selected);
      const obstacleOverlap = obstacles.reduce((total, obstacle) => total + intersectionArea(rect, obstacle), 0);
      return { dock, rect, selectedOverlap, obstacleOverlap, cost: selectedOverlap * 1000 + obstacleOverlap };
    });
    return candidates.sort((left, right) => left.cost - right.cost || left.dock.localeCompare(right.dock))[0];
  }

  function styleText() {
    return `
      :host{all:initial;position:fixed;inset:0;z-index:2147483646;pointer-events:none;color-scheme:dark;font-family:Satoshi,"Segoe UI",system-ui,sans-serif}
      *{box-sizing:border-box}.launcher{pointer-events:auto;position:fixed;display:inline-flex;align-items:center;gap:10px;padding:13px 20px;border:1px solid #14b8a6;border-radius:11px;background:#111827;color:#14b8a6;box-shadow:0 12px 34px rgba(0,0,0,.34);font:700 15px/1 Satoshi,"Segoe UI",system-ui,sans-serif;cursor:pointer}.launcher[data-position="bottom-left"]{left:24px;bottom:24px}.launcher[data-position="bottom-right"]{right:24px;bottom:24px}.launcher[data-position="top-left"]{left:24px;top:24px}.launcher[data-position="top-right"]{right:24px;top:24px}.launcher:hover{background:#102522}.scan-icon{width:17px;height:17px;background:linear-gradient(#14b8a6,#14b8a6) 0 3px/17px 2px no-repeat,linear-gradient(#14b8a6,#14b8a6) 3px 8px/11px 2px no-repeat,linear-gradient(#14b8a6,#14b8a6) 0 13px/17px 2px no-repeat}
      .theatre{--scrim-opacity:0;position:fixed;inset:0;pointer-events:none}.scrim{pointer-events:none;position:absolute;inset:0;width:100%;height:100%;border:0;background:#0b1220;opacity:var(--scrim-opacity);backdrop-filter:saturate(.45) blur(1px)}.scan-layer,.marker-layer{position:fixed;inset:0;pointer-events:none}.scan-line{position:fixed;left:0;right:0;top:0;height:2px;background:linear-gradient(90deg, transparent, #14b8a6, transparent);box-shadow:0 0 26px 5px rgba(20,184,166,.45);transform:translateY(-4px)}.scan-box{position:fixed;left:0;top:0;border:1px solid #14b8a6;border-radius:4px;opacity:0;box-shadow:inset 0 0 22px rgba(20,184,166,.1);transition:opacity .12s ease}.scan-label{position:absolute;left:0;top:-15px;color:#14b8a6;opacity:.85;font:9px/1 "JetBrains Mono",Consolas,monospace;letter-spacing:.06em}
      .hud{pointer-events:auto;position:fixed;width:min(480px,calc(100vw - 32px));max-height:calc(100vh - 32px);overflow-y:auto;border:1px solid #1f2937;border-radius:16px;background:#111827;color:#f8fafb;box-shadow:0 26px 70px rgba(0,0,0,.55);font:14px/1.45 Satoshi,"Segoe UI",system-ui,sans-serif}.hud[data-dock="top-left"]{left:16px;top:16px}.hud[data-dock="top-right"]{right:16px;top:16px}.hud[data-dock="bottom-left"]{left:16px;bottom:16px}.hud[data-dock="bottom-right"]{right:16px;bottom:16px}.window-bar{position:sticky;top:0;z-index:4;display:flex;align-items:center;gap:10px;min-height:54px;padding:0 18px;border-bottom:1px solid #1f2937;background:#161e2e}.window-dots{display:flex;gap:7px}.window-dot{display:block;width:9px;height:9px;border-radius:50%;background:#202a3d}.window-title{flex:1;color:#9ca3af;font:600 12px/1 "JetBrains Mono",Consolas,monospace;letter-spacing:.02em}.icon-close,.icon-collapse{display:grid;place-items:center;width:30px;height:30px;padding:0;border:1px solid transparent;border-radius:8px;background:transparent;color:#9ca3af;font-size:18px;cursor:pointer}.icon-close:hover,.icon-collapse:hover{border-color:#334155;color:#f8fafb}.results-pill{pointer-events:auto;position:fixed;display:flex;align-items:center;gap:10px;max-width:calc(100vw - 32px);padding:9px 12px;border:1px solid #245b57;border-radius:999px;background:#111827;color:#f8fafb;box-shadow:0 14px 35px rgba(0,0,0,.45);cursor:pointer}.results-pill[data-dock="top-left"]{left:16px;top:16px}.results-pill[data-dock="top-right"]{right:16px;top:16px}.results-pill[data-dock="bottom-left"]{left:16px;bottom:16px}.results-pill[data-dock="bottom-right"]{right:16px;bottom:16px}.pill-count{display:grid;place-items:center;min-width:26px;height:26px;padding:0 7px;border-radius:999px;background:#14b8a6;color:#07131d;font:800 12px/1 "JetBrains Mono",Consolas,monospace}.pill-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:700}.pill-open{color:#5eead4;font-size:12px;font-weight:700}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
      .scan-body{position:relative;min-height:430px;padding:34px 34px 38px;overflow:hidden}.scan-body:before{content:"";position:absolute;inset:-45% -15%;background:radial-gradient(circle at 15% 30%,rgba(20,184,166,.13),transparent 46%);animation:scan-aurora 4s ease-in-out infinite;pointer-events:none}.scan-lead{position:relative;display:flex;align-items:center;gap:13px;margin-bottom:15px}.spinner{width:20px;height:20px;flex:0 0 auto;border:2px solid #334155;border-top-color:#14b8a6;border-radius:50%;animation:spin .85s linear infinite}.scan-status{flex:1;min-width:0;margin:0;overflow:hidden;color:#f8fafb;font:600 14px/1.3 "JetBrains Mono",Consolas,monospace;text-overflow:ellipsis;white-space:nowrap}.scan-elapsed{color:#9ca3af;font:12px/1 "JetBrains Mono",Consolas,monospace}.scan-progress,.result-progress{height:6px;overflow:hidden;border-radius:999px;background:#161e2e}.scan-progress{position:relative;margin-bottom:30px}.scan-progress-fill,.result-progress-fill{height:100%;width:0;background:linear-gradient(90deg,#1f6feb,#14b8a6);transition:width .16s linear}.scan-stage-list{position:relative;display:flex;flex-direction:column;gap:13px;margin:0;padding:0;list-style:none}.scan-stage{display:grid;grid-template-columns:18px minmax(0,1fr) auto;align-items:start;gap:12px;padding:13px 14px;border:1px solid #1f2937;border-radius:11px;background:#0b1220;opacity:.48;transition:opacity .2s ease,border-color .2s ease,transform .2s ease}.scan-stage[data-state="active"]{border-color:#245b57;opacity:1;transform:translateX(3px)}.scan-stage[data-state="done"]{opacity:1}.stage-indicator{width:8px;height:8px;margin-top:5px;border-radius:50%;background:#334155}.scan-stage[data-state="active"] .stage-indicator{background:#14b8a6;box-shadow:0 0 0 5px rgba(20,184,166,.12);animation:pulse 1s ease-in-out infinite}.scan-stage[data-state="done"] .stage-indicator{background:#22c55e}.stage-label,.stage-detail{display:block}.stage-label{color:#f8fafb;font-size:14px;line-height:1.35}.stage-detail{margin-top:2px;color:#9ca3af;font-size:12px;line-height:1.4}.stage-state{color:#22c55e;font:700 11px/1.4 "JetBrains Mono",Consolas,monospace}
      .result-view{animation:result-in .32s ease-out}.result-body{padding:22px 22px 20px}.result-top{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;margin-bottom:18px}.result-hostname{margin:0 0 6px;color:#9ca3af;font:600 12px/1.4 "JetBrains Mono",Consolas,monospace;overflow-wrap:anywhere}.result-score-row{display:flex;align-items:baseline;gap:8px}.result-score{color:#14b8a6;font:800 48px/.95 "JetBrains Mono",Consolas,monospace;letter-spacing:-.05em}.result-score-unit{color:#9ca3af;font-size:14px}.status-pill{flex:0 0 auto;margin-top:1px;padding:8px 13px;border-radius:999px;background:rgba(34,197,94,.13);color:#22c55e;font-size:12px;font-weight:700;white-space:nowrap}.status-pill[data-tone="warn"]{background:rgba(245,158,11,.13);color:#f59e0b}.status-pill[data-tone="risk"]{background:rgba(239,68,68,.13);color:#ef4444}.result-progress{margin-bottom:10px}.metadata{margin:0 0 14px;color:#9ca3af;font:10px/1.4 "JetBrains Mono",Consolas,monospace}.navigator{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:12px}.finding-count{margin:0;color:#d7e0ed;font-size:12px;font-weight:700}.filters{display:flex;align-items:center;gap:6px;flex-wrap:wrap}.filter-chip,.category-filter{min-height:28px;border:1px solid #263244;border-radius:999px;background:#0b1220;color:#aeb9c9;font:700 10px/1 Satoshi,"Segoe UI",system-ui,sans-serif}.filter-chip{padding:5px 9px;cursor:pointer}.filter-chip[aria-pressed="true"]{border-color:#14b8a6;background:#102522;color:#5eead4}.category-filter{max-width:140px;padding:4px 9px;border-radius:8px}.findings{display:flex;flex-direction:column;gap:8px;margin:0;padding:0;list-style:none}.finding-item{overflow:hidden;border:1px solid #1f2937;border-radius:11px;background:#0b1220}.finding-item[data-selected="true"]{border-color:#14b8a6;box-shadow:0 0 0 2px rgba(20,184,166,.12)}.finding-row{display:flex;align-items:flex-start;gap:11px;width:100%;min-height:66px;padding:12px 14px;border:0;background:transparent;color:inherit;text-align:left;cursor:pointer}.finding-row:hover{background:#0e1828}.finding-row-static{cursor:default}.tone-dot{width:8px;height:8px;flex:0 0 auto;margin-top:6px;border-radius:50%}.finding-copy{flex:1;min-width:0}.finding-title,.finding-explanation{display:block}.finding-title{color:#f8fafb;font-size:13px;font-weight:700;line-height:1.35}.finding-number{display:inline-block;margin-right:8px;color:#5eead4;font:800 10px/1 "JetBrains Mono",Consolas,monospace}.finding-explanation{display:-webkit-box;margin-top:2px;overflow:hidden;color:#9ca3af;font-size:11.5px;line-height:1.4;-webkit-box-orient:vertical;-webkit-line-clamp:2}.severity{flex:0 0 auto;margin-top:2px;font-size:11px;font-weight:700;white-space:nowrap}.finding-details{padding:0 14px 13px 33px;border-top:1px solid #1f2937}.detail-line,.target-state{margin:9px 0 0;color:#9ca3af;font-size:11.5px;line-height:1.45}.detail-label{display:block;color:#dbe5f1}.detail-copy{display:block;overflow-wrap:anywhere}.target-state:before{content:"✓ ";color:#22c55e;font-weight:800}.target-missing{color:#f8b4b4}.target-missing:before{content:"! ";color:#ef4444}.toolbar{display:flex;flex-wrap:wrap;gap:7px;margin-top:14px;padding-top:13px;border-top:1px solid #1f2937}.tool{padding:7px 10px;border:1px solid #263244;border-radius:8px;background:transparent;color:#cbd5e1;font:700 11px/1 Satoshi,"Segoe UI",system-ui,sans-serif;cursor:pointer}.tool:hover,.tool[aria-pressed="true"]{border-color:#14b8a6;color:#14b8a6}.tool-close{margin-left:auto}.summary{margin:13px 0 0;color:#9ca3af;font-size:11px;line-height:1.5}.reason-note{margin:15px 0 0;padding-top:13px;border-top:1px solid #1f2937;color:#9ca3af;font-size:11.5px;line-height:1.5}
      .marker-frame{pointer-events:none;position:fixed;left:0;top:0;border:2px solid;border-radius:5px;background:color-mix(in srgb,var(--marker-tone,#14b8a6) 5%,transparent);box-shadow:inset 0 0 18px rgba(20,184,166,.08)}.marker-frame[data-selected="true"]{border-width:3px;box-shadow:0 0 0 4px rgba(20,184,166,.2),inset 0 0 22px rgba(20,184,166,.12)}.marker{pointer-events:auto;position:fixed;left:0;top:0;display:flex;align-items:center;max-width:240px;height:26px;padding:0;border:1px solid var(--marker-tone);border-radius:7px;background:#0b1220;color:#f8fafb;box-shadow:0 4px 15px rgba(0,0,0,.65);font:800 9px/1 "JetBrains Mono",Consolas,monospace;letter-spacing:.04em;text-align:left;cursor:pointer}.marker-number{display:grid;place-items:center;align-self:stretch;min-width:28px;padding:0 6px;background:var(--marker-tone);color:#07131d}.marker-label{min-width:0;padding:0 8px;overflow:hidden;text-overflow:ellipsis;text-transform:uppercase;white-space:nowrap}.marker[data-selected="true"]{box-shadow:0 0 0 3px color-mix(in srgb,var(--marker-tone) 35%,transparent),0 4px 15px rgba(0,0,0,.65);animation:marker-pulse .8s ease-in-out 2}.highlight{pointer-events:none;position:fixed;left:0;top:0;border:3px solid #14b8a6;border-radius:5px;box-shadow:inset 0 0 22px rgba(20,184,166,.12),0 0 0 4px rgba(20,184,166,.2)}button:focus-visible,select:focus-visible{outline:3px solid #5eead4;outline-offset:3px}[hidden]{display:none!important}
      @keyframes spin{to{transform:rotate(360deg)}}@keyframes pulse{50%{transform:scale(.72);opacity:.65}}@keyframes marker-pulse{50%{filter:brightness(1.45)}}@keyframes scan-aurora{50%{transform:translate3d(8%,4%,0)}}@keyframes result-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
      @media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important;animation:none!important}.marker[data-selected="true"]{outline:4px double var(--marker-tone);outline-offset:3px}}@media(max-width:620px){.launcher[data-position="bottom-left"]{left:12px;bottom:12px}.launcher[data-position="bottom-right"]{right:12px;bottom:12px}.launcher[data-position="top-left"]{left:12px;top:12px}.launcher[data-position="top-right"]{right:12px;top:12px}.hud{left:8px!important;right:8px!important;top:8px!important;bottom:auto!important;width:auto;max-height:calc(100vh - 16px)}.window-bar{min-height:50px;padding:0 12px}.window-dots{display:none}.scan-body,.result-body{padding:18px 14px}.result-top{display:block}.status-pill{display:inline-block;margin-top:10px}.result-score{font-size:42px}.result-score-unit{font-size:12px}.finding-row{min-height:0;padding:11px}.finding-details{padding-left:14px}.severity{max-width:82px;overflow:hidden;text-overflow:ellipsis}.tool-close{margin-left:0}.marker{max-width:min(210px,calc(100vw - 12px))}.results-pill{left:8px!important;right:auto!important;top:8px!important;bottom:auto!important;max-width:calc(100vw - 16px)}}
    `;
  }

  global.HipXrayRenderer = Object.freeze({ create, SCAN_ANIMATION_MS, markerSummary, rectLike, intersectionArea, choosePanelPlacement, normalizeLauncherPosition });
})(globalThis);
