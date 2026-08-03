(function registerHipXrayRules(global) {
  "use strict";

  const RULESET_VERSION = "hip-xray-local-1";
  const CONTENT_RULES_VERSION = "hip-content-signals-1";
  const MAX_SCANNED_ELEMENTS = 2500;
  const MAX_TEXT_SIGNAL_ELEMENTS = 400;
  const PRIVATE_CONTENT_SELECTOR = [
    "form", "input", "textarea", "select", "[contenteditable]", "[role='log']",
    "[aria-label*='message' i]", "[aria-label*='chat' i]", "[aria-label*='mail' i]",
    "[class*='message' i]", "[class*='chat' i]", "[class*='inbox' i]"
  ].join(",");
  const TEXT_SIGNAL_SELECTOR = "h1,h2,h3,p,button,[role='alert'],[role='status']";
  const BRAND_NAMES = Object.freeze(["paypal", "microsoft", "google", "apple", "amazon", "guardwithhip"]);
  const REDIRECT_KEYS = new Set(["url", "uri", "target", "dest", "destination", "redirect", "redirect_url", "redirect_uri", "continue", "next"]);
  const SEVERITIES = new Set(["Info", "Low", "Medium", "High", "Critical"]);

  function collectAndScan(documentObject, locationObject, options = {}) {
    const collected = collectPageSnapshot(documentObject, locationObject, options);
    const result = scanSnapshot(collected.snapshot);
    return { ...result, references: collected.references };
  }

  function collectPageSnapshot(documentObject, locationObject, options = {}) {
    const pageUrl = safeUrl(locationObject?.href)?.href || "";
    const page = safeUrl(pageUrl);
    const references = new Map();
    const elements = [];
    const newElements = options.newElements instanceof Set ? options.newElements : new Set();
    let sequence = 0;
    let inspected = 0;
    let inaccessibleFrameCount = 0;
    let truncated = false;

    const add = (element, descriptor) => {
      if (!element || isHipOwned(element)) return;
      if (inspected >= MAX_SCANNED_ELEMENTS) {
        truncated = true;
        return;
      }
      inspected += 1;
      const refKey = `xray-${++sequence}`;
      references.set(refKey, element);
      elements.push({ refKey, ...descriptor });
    };

    for (const form of safeQuery(documentObject, "form")) {
      const controls = safeQuery(form, "input,button,select,textarea");
      const controlFacts = controls.map(control => ({
        tag: lower(control.tagName),
        type: lower(control.getAttribute?.("type")),
        name: lower(control.getAttribute?.("name")),
        autocomplete: lower(control.getAttribute?.("autocomplete"))
      }));
      const action = safeUrl(form.getAttribute?.("action") || pageUrl, pageUrl);
      add(form, {
        kind: "form",
        actionUrl: action?.href || "",
        actionOrigin: action?.origin || "",
        hasPassword: controlFacts.some(item => item.type === "password"),
        hasAuthFields: controlFacts.some(item => item.type === "password" || /user|login|email/.test(item.name) || /username|email/.test(item.autocomplete)),
        hasPaymentFields: controlFacts.some(item => /cc-|card|payment|billing/.test(`${item.name} ${item.autocomplete}`))
      });
    }

    for (const anchor of safeQuery(documentObject, "a[href]")) {
      const target = safeUrl(anchor.getAttribute?.("href"), pageUrl);
      if (!target || !isWebProtocol(target.protocol)) continue;
      add(anchor, { kind: "link", url: target.href, visibleText: boundedText(anchor.textContent, 300) });
    }

    for (const script of safeQuery(documentObject, "script[src]")) {
      addUrlElement(script, "script", "src", script, pageUrl, page, newElements, add);
    }

    for (const frame of safeQuery(documentObject, "iframe[src],frame[src]")) {
      let accessible = false;
      try {
        accessible = Boolean(frame.contentDocument?.documentElement);
      } catch {
        accessible = false;
      }
      if (!accessible) inaccessibleFrameCount += 1;
      addUrlElement(frame, "frame", "src", frame, pageUrl, page, newElements, add, { accessible });
    }

    for (const resource of safeQuery(documentObject, "img[src],audio[src],video[src],source[src],link[href]")) {
      const attribute = lower(resource.tagName) === "link" ? "href" : "src";
      const url = safeUrl(resource.getAttribute?.(attribute), pageUrl);
      if (!url || !isWebProtocol(url.protocol)) continue;
      add(resource, { kind: "resource", url: url.href, resourceType: lower(resource.tagName) });
    }

    let textCount = 0;
    for (const element of safeQuery(documentObject, TEXT_SIGNAL_SELECTOR)) {
      if (textCount >= MAX_TEXT_SIGNAL_ELEMENTS) break;
      if (isPrivateContent(element)) continue;
      textCount += 1;
      const text = boundedText(element.textContent, 500).toLowerCase();
      const matchedSignals = [];
      if (/urgent|immediately|act now|final warning|within (?:\d+|one) (?:minute|hour|day)|account (?:will be|is) (?:closed|locked|suspended)/.test(text)) matchedSignals.push("urgency");
      if (/security team|support team|administrator|official notice|fraud department|we are (?:google|microsoft|paypal|apple|amazon)/.test(text)) matchedSignals.push("impersonation");
      if (/enter (?:your )?(?:password|credentials)|verify (?:your )?(?:account|identity)|sign in to (?:avoid|restore|confirm)|confirm (?:your )?(?:password|login)/.test(text)) matchedSignals.push("credential-request");
      if (matchedSignals.length) add(element, { kind: "visible-signal", matchedSignals: unique(matchedSignals) });
    }

    return {
      snapshot: {
        pageUrl,
        pageOrigin: page?.origin || "",
        pageProtocol: page?.protocol || "",
        elements,
        coverage: {
          inspectedElementCount: inspected,
          inaccessibleFrameCount,
          truncated,
          closedShadowRoots: "Closed shadow roots are not observable"
        }
      },
      references
    };
  }

  function scanSnapshot(snapshot = {}) {
    const findings = [];
    const pageOrigin = snapshot.pageOrigin || safeUrl(snapshot.pageUrl)?.origin || "";
    const pageProtocol = snapshot.pageProtocol || safeUrl(snapshot.pageUrl)?.protocol || "";
    let inaccessibleFrameCount = Number(snapshot.coverage?.inaccessibleFrameCount) || 0;

    const add = (element, ruleId, category, severity, title, plainExplanation, technicalExplanation, evidence, remediation, ruleVersion = RULESET_VERSION) => {
      const finding = {
        id: `${ruleId}:${element.refKey}`,
        ruleId,
        ruleVersion,
        category,
        severity,
        title,
        plainExplanation,
        technicalExplanation,
        evidence,
        remediation,
        source: "Local",
        elementRefKey: element.refKey
      };
      if (validateFinding(finding) && !findings.some(item => item.id === finding.id)) findings.push(finding);
    };

    for (const element of Array.isArray(snapshot.elements) ? snapshot.elements.slice(0, MAX_SCANNED_ELEMENTS) : []) {
      if (!element?.refKey || !element.kind) continue;

      if (element.kind === "form") {
        const action = safeUrl(element.actionUrl, snapshot.pageUrl);
        const insecureContext = pageProtocol === "http:" || action?.protocol === "http:";
        if (element.hasPassword && insecureContext) add(element, "form.password-on-insecure-page", "Forms", "High", "Password form is not fully encrypted", "Passwords entered here could travel over an unencrypted connection.", "The page or the form's effective submission action uses HTTP while a password control is present.", "Observed a password control and HTTP transport. No entered value was read.", "Use HTTPS for both the page and the form action, then redirect HTTP to HTTPS.");
        if (element.hasAuthFields && insecureContext) add(element, "form.auth-on-insecure-page", "Forms", "High", "Sign-in form is not fully encrypted", "This sign-in form may submit over an unencrypted connection.", "Authentication-shaped controls were observed with HTTP page or action transport.", "Observed authentication field structure and HTTP transport. No entered value was read.", "Serve the page and submit the form only over HTTPS.");
        if (element.hasPaymentFields && insecureContext) add(element, "form.payment-on-insecure-page", "Forms", "Critical", "Payment form is not fully encrypted", "Payment details could be exposed if this form is used.", "Payment-shaped control attributes were observed with HTTP page or action transport.", "Observed payment field structure and HTTP transport. No entered value was read.", "Move the complete payment flow to HTTPS and use a reviewed payment provider integration.");
        if (action?.protocol === "http:") add(element, "form.unencrypted-action", "Transport", "High", "Form submits without encryption", "This form sends information to an HTTP address.", "The effective form action resolves to an HTTP URL.", `Effective action origin: ${safeOrigin(action)}`,
          "Change the effective form action to HTTPS and verify redirects do not downgrade it.");
        if (action?.origin && pageOrigin && action.origin !== pageOrigin) add(element, "form.cross-origin-action", "Forms", "Info", "Form submits to another site", "This is context, not proof of danger: the form sends information to a different origin.", "The effective form action origin differs from the page origin. Legitimate hosted identity and payment flows commonly do this.", `Page origin and action origin differ; action origin: ${safeOrigin(action)}`, "Confirm the destination is the intended identity or payment provider and document the dependency.");
      }

      if (element.kind === "resource") {
        const resource = safeUrl(element.url, snapshot.pageUrl);
        if (pageProtocol === "https:" && resource?.protocol === "http:") add(element, "transport.mixed-content", "Transport", "High", "Insecure resource on an HTTPS page", "Part of this secure page is loaded without encryption.", "An HTTP subresource was observed on an HTTPS top-level page.", `${element.resourceType || "Resource"} origin: ${safeOrigin(resource)}`, "Load this resource over HTTPS or remove it.");
      }

      if (element.kind === "link") scanLink(element, snapshot, add);

      if (element.kind === "script" || element.kind === "frame") {
        const url = safeUrl(element.url, snapshot.pageUrl);
        if (url?.origin && pageOrigin && url.origin !== pageOrigin) {
          const noun = element.kind === "script" ? "script" : "frame";
          add(element, `third-party.${noun}`, "Third-party content", "Info", `Third-party ${noun}`, `This page relies on a ${noun} from another site. That is inventory context, not proof of danger.`, `The ${noun} origin differs from the top-level page origin.`, `${noun} origin: ${safeOrigin(url)}`, `Confirm this ${noun} is expected, maintained, and covered by an appropriate content security policy.`);
        }
        if (element.isNew) {
          const noun = element.kind === "script" ? "script" : "frame";
          add(element, `dynamic.${noun}-added`, "Dynamic content", "Medium", `New ${noun} added after X-ray started`, `The page added a ${noun} while X-ray was open.`, `A mutation introduced a new ${noun} element after the initial scan. This can be normal on interactive pages.`, `${noun} origin: ${safeOrigin(url)}`, `Confirm the dynamic ${noun} is expected and restrict allowed sources with a content security policy.`);
        }
        if (element.kind === "frame" && element.accessible === false && !snapshot.coverage?.inaccessibleFrameCount) inaccessibleFrameCount += 1;
      }

      if (element.kind === "visible-signal") {
        const signals = new Set(element.matchedSignals || []);
        if (signals.has("urgency") && signals.has("credential-request")) add(element, "content.urgent-credential-request", "Content signals", "High", "Urgent request for credentials", "This page combines urgency with a request to sign in or provide credentials.", "HIP content signal rules matched urgency and credential-request categories. The original page text was not retained.", "Matched rule categories: urgency, credential-request", "Pause and independently navigate to the organization's known website before entering credentials.", CONTENT_RULES_VERSION);
        if (signals.has("impersonation")) add(element, "content.impersonation-language", "Content signals", "Medium", "Possible authority impersonation language", "This page uses language associated with support, security, or official authority.", "HIP content signal rules matched the impersonation category. This is a caution signal, not an identity determination.", "Matched rule category: impersonation", "Verify the sender or organization through a separate trusted channel.", CONTENT_RULES_VERSION);
      }
    }

    findings.sort((left, right) => severityRank(right.severity) - severityRank(left.severity) || left.id.localeCompare(right.id));
    return {
      findings,
      coverage: { ...(snapshot.coverage || {}), inaccessibleFrameCount },
      backend: { available: false, message: "Full domain scan unavailable." },
      rulesetVersion: RULESET_VERSION
    };
  }

  function scanLink(element, snapshot, add) {
    const url = safeUrl(element.url, snapshot.pageUrl);
    if (!url) return;
    const visibleTarget = extractVisibleHostname(element.visibleText);
    if (visibleTarget && normalizeHost(visibleTarget) !== normalizeHost(url.hostname)) add(element, "link.misleading-text", "Links", "High", "Link text and destination differ", "This link appears to name one site but opens another.", "A hostname displayed in the link text differs from the resolved href hostname.", `Displayed host: ${visibleTarget}; destination host: ${url.hostname}`, "Update the visible destination or link target so they agree.");
    if (hasEncodedRedirect(url)) add(element, "link.encoded-redirect", "Links", "Medium", "Link contains a hidden redirect destination", "This link carries another web address inside a redirect parameter.", "A redirect-shaped query parameter contains an encoded HTTP or HTTPS URL.", `Redirect service origin: ${safeOrigin(url)}`, "Link directly to the intended destination or clearly disclose the redirect service.");
    if (isUnusualHostname(url.hostname)) add(element, "link.unusual-hostname", "Links", "Low", "Unusual destination hostname", "This destination uses a complex hostname that deserves a closer look.", "The hostname exceeds the versioned complexity thresholds for labels, length, or punctuation.", `Destination host: ${url.hostname}`, "Confirm the hostname character by character before continuing.");
    if (url.hostname.split(".").some(label => label.startsWith("xn--"))) add(element, "link.idn-hostname", "Links", "Medium", "Internationalized destination hostname", "This link uses an encoded internationalized hostname. It may be legitimate, but visual lookalikes are possible.", "At least one hostname label uses the IDNA punycode prefix.", `Destination host: ${url.hostname}`, "Display the Unicode and ASCII forms to users and verify the registered domain.");
    const lookalike = brandLookalike(url.hostname);
    if (lookalike) add(element, "link.brand-lookalike", "Links", "High", "Possible brand-lookalike hostname", `This destination resembles ${lookalike} but is not identified as its standard domain.`, "A versioned local normalization rule found a label that resembles a brand name. This is resemblance evidence, not an ownership or reputation claim.", `Destination host: ${url.hostname}; resembled name: ${lookalike}`, "Navigate to the brand using a saved bookmark or independently typed address.");
  }

  function addUrlElement(element, kind, attribute, newElement, pageUrl, page, newElements, add, extra = {}) {
    const url = safeUrl(element.getAttribute?.(attribute), pageUrl);
    if (!url || !isWebProtocol(url.protocol)) return;
    add(element, { kind, url: url.href, origin: url.origin, isNew: newElements.has(newElement), ...extra });
  }

  function hasEncodedRedirect(url) {
    for (const [key, candidate] of url.searchParams) {
      if (!REDIRECT_KEYS.has(key.toLowerCase())) continue;
      let decoded = candidate;
      try { decoded = decodeURIComponent(candidate); } catch { /* use parsed value */ }
      const nested = safeUrl(decoded);
      if (nested && isWebProtocol(nested.protocol) && nested.origin !== url.origin) return true;
    }
    return false;
  }

  function extractVisibleHostname(text) {
    const match = String(text || "").match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[\s/:]|$)/i);
    return match?.[1]?.toLowerCase() || "";
  }

  function isUnusualHostname(hostname) {
    const labels = normalizeHost(hostname).split(".");
    return labels.length > 5 || hostname.length > 55 || labels.some(label => (label.match(/-/g) || []).length >= 4 || /\d{6,}/.test(label));
  }

  function brandLookalike(hostname) {
    const host = normalizeHost(hostname);
    const labels = host.split(".").slice(0, -1);
    for (const label of labels) {
      const normalized = label.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s").replace(/7/g, "t").replace(/[^a-z]/g, "");
      for (const brand of BRAND_NAMES) {
        if (label !== brand && (normalized === brand || editDistance(normalized, brand) === 1)) return brand;
      }
    }
    return "";
  }

  function editDistance(left, right) {
    if (Math.abs(left.length - right.length) > 1) return 2;
    const row = Array.from({ length: right.length + 1 }, (_, index) => index);
    for (let i = 1; i <= left.length; i += 1) {
      let diagonal = row[0];
      row[0] = i;
      for (let j = 1; j <= right.length; j += 1) {
        const previous = row[j];
        row[j] = Math.min(row[j] + 1, row[j - 1] + 1, diagonal + (left[i - 1] === right[j - 1] ? 0 : 1));
        diagonal = previous;
      }
    }
    return row[right.length];
  }

  function validateFinding(finding) {
    const keys = ["id", "ruleId", "ruleVersion", "category", "severity", "title", "plainExplanation", "technicalExplanation", "evidence", "remediation", "source", "elementRefKey"];
    return Boolean(finding && Object.keys(finding).length === keys.length && keys.every(key => typeof finding[key] === "string" && finding[key].length > 0) && SEVERITIES.has(finding.severity) && ["Local", "HIP"].includes(finding.source));
  }

  function mergeHipFindings(localResult, hipFindings) {
    const remote = Array.isArray(hipFindings)
      ? hipFindings.slice(0, 100).filter(item => item?.source === "HIP" && validateFinding(item))
      : [];
    return {
      ...(localResult || {}),
      findings: [...(localResult?.findings || []), ...remote],
      backend: remote.length
        ? { available: true, message: "HIP domain evidence included." }
        : { available: false, message: "Full domain scan unavailable." }
    };
  }

  function isPrivateContent(element) {
    try { return Boolean(element.closest?.(PRIVATE_CONTENT_SELECTOR)); } catch { return true; }
  }
  function isHipOwned(element) { return element?.dataset?.hipXrayOwned === "true" || Boolean(element?.closest?.("[data-hip-xray-owned='true']")); }
  function safeQuery(root, selector) { try { return Array.from(root?.querySelectorAll?.(selector) || []); } catch { return []; } }
  function safeUrl(value, base) { try { const url = new URL(value, base); return url.username || url.password ? null : url; } catch { return null; } }
  function safeOrigin(url) { return url?.origin && url.origin !== "null" ? url.origin.slice(0, 300) : "Unavailable"; }
  function isWebProtocol(protocol) { return protocol === "http:" || protocol === "https:"; }
  function normalizeHost(hostname) { return String(hostname || "").toLowerCase().replace(/^www\./, ""); }
  function boundedText(text, maximum) { return typeof text === "string" ? text.replace(/\s+/g, " ").trim().slice(0, maximum) : ""; }
  function lower(value) { return typeof value === "string" ? value.toLowerCase() : ""; }
  function unique(values) { return [...new Set(values)]; }
  function severityRank(value) { return ({ Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 })[value] ?? 0; }

  global.HipXrayRules = Object.freeze({
    RULESET_VERSION,
    CONTENT_RULES_VERSION,
    MAX_SCANNED_ELEMENTS,
    MAX_TEXT_SIGNAL_ELEMENTS,
    collectAndScan,
    collectPageSnapshot,
    scanSnapshot,
    mergeHipFindings,
    validateFinding
  });
})(globalThis);
