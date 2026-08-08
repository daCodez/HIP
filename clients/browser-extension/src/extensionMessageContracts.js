const MAX_MESSAGE_BYTES = 64 * 1024;
const MAX_STRING_LENGTH = 4096;
const MAX_ARRAY_LENGTH = 200;
const MAX_DEPTH = 6;

const MESSAGE_KEYS = Object.freeze({
  HIP_GET_PLUGIN_VERSION: [],
  HIP_GET_SETTINGS: [],
  HIP_OPEN_SIDE_PANEL: ["findingId"],
  HIP_GET_BANNER_DISMISSED: ["domain", "pageKey"],
  HIP_SET_BANNER_DISMISSED: ["domain", "pageKey"],
  HIP_LOOKUP_DOMAIN: ["domain"],
  HIP_SCORE_SITE: ["request"],
  HIP_SCAN_LINKS: ["pageUrl", "links"],
  HIP_SCAN_SITE_SAFETY: ["request"],
  HIP_SAFETY_URL: ["originalUrl", "sourceDomain", "riskStatus"],
  HIP_REPORT_RISK_FINDING: ["report"],
  HIP_SUBMIT_SITE_FEEDBACK: ["feedback"],
  HIP_SAVE_SCAN_RESULT: ["result"],
  HIP_SCAN_SUMMARY: ["summary"],
  HIP_GET_SCAN_SUMMARY: ["tabId"],
  HIP_DEVICE_CAPABILITIES: [],
  HIP_DEVICE_PREPARE: [],
  HIP_DEVICE_STAGE: ["handle", "deviceId"],
  HIP_DEVICE_SIGN_CHALLENGE: ["deviceId", "signingInput"],
  HIP_DEVICE_ACTIVATE: ["deviceId"],
  HIP_DEVICE_REMOVE: ["deviceId"],
  HIP_DEVICE_RECONCILE: ["activeDeviceIds"]
});

const EXTENSION_PAGE_MESSAGES = new Set([
  "HIP_GET_PLUGIN_VERSION",
  "HIP_GET_SCAN_SUMMARY",
  "HIP_SUBMIT_SITE_FEEDBACK"
]);

const CONTENT_SCRIPT_MESSAGES = new Set([
  "HIP_GET_PLUGIN_VERSION",
  "HIP_GET_SETTINGS",
  "HIP_OPEN_SIDE_PANEL",
  "HIP_GET_BANNER_DISMISSED",
  "HIP_SET_BANNER_DISMISSED",
  "HIP_LOOKUP_DOMAIN",
  "HIP_SCORE_SITE",
  "HIP_SCAN_LINKS",
  "HIP_SCAN_SITE_SAFETY",
  "HIP_SAFETY_URL",
  "HIP_REPORT_RISK_FINDING",
  "HIP_SUBMIT_SITE_FEEDBACK",
  "HIP_SAVE_SCAN_RESULT",
  "HIP_SCAN_SUMMARY",
  "HIP_DEVICE_CAPABILITIES",
  "HIP_DEVICE_PREPARE",
  "HIP_DEVICE_STAGE",
  "HIP_DEVICE_SIGN_CHALLENGE",
  "HIP_DEVICE_ACTIVATE",
  "HIP_DEVICE_REMOVE",
  "HIP_DEVICE_RECONCILE"
]);

const REPORT_KEYS = new Set([
  "platform", "targetType", "domain", "urlHash", "originalUrl", "senderHash",
  "riskLevel", "reason", "detectedAtUtc", "reporterTrustLevel",
  "privacySafeEvidence", "hipSignature"
]);

const FEEDBACK_KEYS = new Set([
  "targetType", "targetId", "eventType", "severity", "reporterTrustLevel",
  "reason", "platform", "urlHash", "metadata"
]);

const SCAN_RESULT_KEYS = new Set([
  "domain", "pageUrl", "pageUrlHash", "pluginVersion", "score", "riskLevel",
  "status", "reasons", "linksScanned", "riskyLinksFound",
  "suspiciousLinksFound", "dangerousLinksFound", "recommendedAction",
  "privacySafeMetadata", "scannedAtUtc"
]);

const SUMMARY_KEYS = new Set([
  "apiStatus", "website", "linksScanned", "riskyLinks", "suspiciousLinks",
  "dangerousLinks", "unknownLinks", "downloadCandidates",
  "executableDownloadCandidates", "downloadLinks", "shortenedLinkCandidates",
  "obfuscatedLinkCandidates", "redirectCandidates", "redirectSignals",
  "formsDetected", "loginFormsDetected", "passwordFieldsDetected",
  "paymentFieldsDetected", "crossDomainLoginForms", "socialLinkCandidates",
  "webmailLinkCandidates", "clientChatLinkCandidates", "inlineScriptCount",
  "externalScriptUrls", "suspiciousScriptPatternCount", "siteSafetyStatus",
  "siteSafetyDataSource", "siteSafetyScannedAtUtc", "siteSafetyError",
  "domainTrustScore", "pageTrustScore", "contentRiskScore", "finalHipScore",
  "confidenceLevel", "hipScoringModelVersion", "hipPresentationStatus",
  "evidenceFreshness", "trustAssertionDisposition", "providerEvidenceCount",
  "siteSafety", "scanResultSubmission", "scanResultDataSource", "scanStage",
  "lastSubmittedUtc", "lastScanUtc", "updatedAt", "scanResultError",
  "pageUrlHash", "isHttps", "hipBadgeObserved", "hipBadgeDomainMatch", "pluginVersion"
]);

const SCAN_METADATA_KEYS = new Set([
  "scanMode", "apiStatus", "scanTimestampUtc", "isHttps", "hipBadgeObserved",
  "hipBadgeDomainMatch", "downloadCandidates",
  "executableDownloadCandidates", "formsDetected", "loginFormsDetected",
  "passwordFieldsDetected", "paymentFieldsDetected", "crossDomainLoginForms",
  "shortenedLinkCandidates", "obfuscatedLinkCandidates", "redirectCandidates",
  "socialLinkCandidates", "webmailLinkCandidates", "clientChatLinkCandidates",
  "siteSafetyDataSource", "siteSafetyStatus", "confidence",
  "hipScoringModelVersion", "hipPresentationStatus", "evidenceFreshness",
  "trustAssertionDisposition", "domainTrustScore", "pageTrustScore",
  "contentRiskScore", "finalHipScore", "providerEvidenceCount", "pluginVersion"
]);

const FEEDBACK_METADATA_KEYS = new Set([
  "source", "feedbackType", "domain", "displayedStatus", "displayedScore",
  "scanMode", "reportedAtUtc"
]);

/**
 * Validates and copies a message before the service worker uses it. The copy has
 * no attacker-controlled prototype, accessors, or keys outside the contract.
 */
export function validateBackgroundMessage(message, sender, runtimeId) {
  try {
    if (!isPlainObject(message) || typeof message.type !== "string") {
      throw new Error("Malformed extension message.");
    }

    const allowedKeys = MESSAGE_KEYS[message.type];
    if (!allowedKeys) {
      throw new Error("Unknown extension message type.");
    }

    const senderKind = validateSender(sender, runtimeId);
    const allowedForSender = senderKind === "content"
      ? CONTENT_SCRIPT_MESSAGES
      : EXTENSION_PAGE_MESSAGES;
    if (!allowedForSender.has(message.type)) {
      throw new Error("Message is not allowed from this extension context.");
    }

    assertAllowedKeys(message, new Set(["type", ...allowedKeys]));
    const clean = safeCopy(message);
    validateMessageFields(clean, sender);
    return { ok: true, message: clean, senderKind };
  } catch (error) {
    return { ok: false, error: error.message || "Extension message rejected." };
  }
}

/**
 * Produces a bounded, prototype-free response before API-derived data crosses
 * back into a content script or extension page.
 */
export function safeExtensionResult(value) {
  return safeCopy(value, 128 * 1024);
}

function validateSender(sender, runtimeId) {
  if (!runtimeId || sender?.id !== runtimeId) {
    throw new Error("Untrusted extension message sender.");
  }

  const expectedPrefix = `chrome-extension://${runtimeId}/`;
  if (typeof sender?.url === "string" && sender.url.startsWith(expectedPrefix)) {
    return "extension";
  }

  if (Number.isInteger(sender?.tab?.id) && sender.tab.id >= 0) {
    if (!isHttpUrl(senderPageUrl(sender))) {
      throw new Error("Content-script sender URL is invalid.");
    }

    return "content";
  }

  throw new Error("Unknown extension message context.");
}

function validateMessageFields(message, sender) {
  switch (message.type) {
    case "HIP_GET_PLUGIN_VERSION":
    case "HIP_GET_SETTINGS":
      return;
    case "HIP_OPEN_SIDE_PANEL":
      assertBoundedString(message.findingId, 240);
      return;
    case "HIP_GET_BANNER_DISMISSED":
    case "HIP_SET_BANNER_DISMISSED":
      assertDomain(message.domain);
      assertHash(message.pageKey);
      assertSenderDomain(message.domain, sender);
      return;
    case "HIP_LOOKUP_DOMAIN":
      assertDomain(message.domain);
      return;
    case "HIP_SCORE_SITE":
      assertExactKeys(message.request, new Set(["domain", "url"]));
      assertDomain(message.request.domain);
      assertHttpUrl(message.request.url);
      assertDomainMatchesUrl(message.request.domain, message.request.url);
      assertSenderOrigin(message.request.url, sender);
      return;
    case "HIP_SCAN_LINKS":
      assertHttpUrl(message.pageUrl);
      assertSenderOrigin(message.pageUrl, sender);
      assertUrlArray(message.links);
      return;
    case "HIP_SCAN_SITE_SAFETY":
      validateSiteSafetyRequest(message.request, sender);
      return;
    case "HIP_SAFETY_URL":
      assertHttpUrl(message.originalUrl);
      assertSenderOrigin(message.originalUrl, sender);
      assertOptionalDomain(message.sourceDomain);
      assertBoundedString(message.riskStatus, 64);
      return;
    case "HIP_REPORT_RISK_FINDING":
      assertExactKeys(message.report, REPORT_KEYS);
      assertDomain(message.report.domain);
      assertHash(message.report.urlHash);
      assertBoundedString(message.report.reason, 1024);
      if (message.report.originalUrl !== null || message.report.senderHash !== null) {
        throw new Error("Risk reports cannot include raw identifying values.");
      }
      validateRiskEvidence(message.report.privacySafeEvidence);
      return;
    case "HIP_SUBMIT_SITE_FEEDBACK":
      assertAllowedKeys(message.feedback, FEEDBACK_KEYS);
      assertDomain(message.feedback.targetId);
      assertHash(message.feedback.urlHash);
      assertBoundedString(message.feedback.reason, 512);
      assertIntegerInRange(message.feedback.targetType, 0, 20);
      assertIntegerInRange(message.feedback.eventType, 0, 20);
      assertIntegerInRange(message.feedback.severity, 0, 10);
      assertIntegerInRange(message.feedback.reporterTrustLevel, 0, 10);
      if (message.feedback.platform !== "Web") {
        throw new Error("Feedback platform is invalid.");
      }
      if (message.feedback.metadata !== undefined) {
        assertAllowedKeys(message.feedback.metadata, FEEDBACK_METADATA_KEYS);
      }
      return;
    case "HIP_SAVE_SCAN_RESULT":
      assertExactKeys(message.result, SCAN_RESULT_KEYS);
      assertDomain(message.result.domain);
      assertHash(message.result.pageUrlHash);
      if (message.result.pageUrl !== null) {
        assertHttpUrl(message.result.pageUrl);
        assertSenderOrigin(message.result.pageUrl, sender);
      }
      assertSenderDomain(message.result.domain, sender);
      if (message.result.scannedAtUtc !== null) {
        throw new Error("Browser submissions cannot assert a scan timestamp.");
      }
      assertIntegerInRange(message.result.score, 0, 100);
      for (const key of ["linksScanned", "riskyLinksFound", "suspiciousLinksFound", "dangerousLinksFound"]) {
        assertIntegerInRange(message.result[key], 0, 100000);
      }
      assertStringArray(message.result.reasons, 20, 512);
      assertAllowedKeys(message.result.privacySafeMetadata, SCAN_METADATA_KEYS);
      return;
    case "HIP_SCAN_SUMMARY":
      assertExactKeys(message.summary, SUMMARY_KEYS);
      return;
    case "HIP_GET_SCAN_SUMMARY":
      if (!Number.isInteger(message.tabId) || message.tabId < 0) {
        throw new Error("Tab identifier is invalid.");
      }
      return;
    case "HIP_DEVICE_CAPABILITIES":
    case "HIP_DEVICE_PREPARE":
      return;
    case "HIP_DEVICE_STAGE":
      assertOpaqueIdentifier(message.handle, "pending:");
      assertOpaqueIdentifier(message.deviceId, "dev_");
      return;
    case "HIP_DEVICE_SIGN_CHALLENGE":
      assertOpaqueIdentifier(message.deviceId, "dev_");
      assertBase64Url(message.signingInput, 4096);
      return;
    case "HIP_DEVICE_ACTIVATE":
    case "HIP_DEVICE_REMOVE":
      assertOpaqueIdentifier(message.deviceId, "dev_");
      return;
    case "HIP_DEVICE_RECONCILE":
      if (!Array.isArray(message.activeDeviceIds) || message.activeDeviceIds.length > 25) {
        throw new Error("Device reconciliation list is invalid.");
      }
      for (const deviceId of message.activeDeviceIds) assertOpaqueIdentifier(deviceId, "dev_");
      return;
    default:
      throw new Error("Unknown extension message type.");
  }
}

function validateRiskEvidence(evidence) {
  assertExactKeys(evidence, new Set(["evidenceType", "summary", "facts", "containsPrivateContent"]));
  assertBoundedString(evidence.evidenceType, 128);
  assertBoundedString(evidence.summary, 512);
  if (evidence.containsPrivateContent !== false) {
    throw new Error("Risk evidence must be privacy safe.");
  }
  assertExactKeys(evidence.facts, new Set(["sourceDomain", "targetDomain", "scanMode", "linkContext", "downloadCandidate"]));
  assertDomain(evidence.facts.sourceDomain);
  assertDomain(evidence.facts.targetDomain);
  for (const key of ["scanMode", "linkContext", "downloadCandidate"]) {
    assertBoundedString(evidence.facts[key], 128);
  }
}

function validateSiteSafetyRequest(request, sender) {
  assertExactKeys(request, new Set(["url", "pluginVersion", "observedSignals"]));
  assertHttpUrl(request.url);
  assertSenderOrigin(request.url, sender);
  if (request.pluginVersion !== null) {
    assertBoundedString(request.pluginVersion, 128);
  }

  const signals = request.observedSignals;
  const signalKeys = new Set([
    "downloadLinks", "hasLoginForm", "hasPasswordField", "hasPaymentField",
    "inlineScriptCount", "externalScriptUrls", "suspiciousScriptPatternCount",
    "trustDataAvailable", "shortenedLinkCount", "obfuscatedLinkCount",
    "clientChatLinkCount", "clientChatContextObserved", "redirectChain"
  ]);
  assertExactKeys(signals, signalKeys);
  assertUrlArray(signals.downloadLinks);
  assertUrlArray(signals.externalScriptUrls);
  assertUrlArray(signals.redirectChain);

  for (const key of ["hasLoginForm", "hasPasswordField", "hasPaymentField", "trustDataAvailable", "clientChatContextObserved"]) {
    if (typeof signals[key] !== "boolean") {
      throw new Error(`Site-safety signal ${key} must be boolean.`);
    }
  }

  for (const key of ["inlineScriptCount", "suspiciousScriptPatternCount", "shortenedLinkCount", "obfuscatedLinkCount", "clientChatLinkCount"]) {
    if (!Number.isInteger(signals[key]) || signals[key] < 0 || signals[key] > 100000) {
      throw new Error(`Site-safety signal ${key} is out of range.`);
    }
  }
}

function safeCopy(value, maximumBytes = MAX_MESSAGE_BYTES) {
  const state = { nodes: 0 };
  const clean = copyValue(value, 0, state);
  const serialized = JSON.stringify(clean);
  if (new TextEncoder().encode(serialized).byteLength > maximumBytes) {
    throw new Error("Extension message exceeds the size limit.");
  }
  return clean;
}

function copyValue(value, depth, state) {
  if (depth > MAX_DEPTH || ++state.nodes > 2000) {
    throw new Error("Extension message is too complex.");
  }

  if (value === null || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    assertBoundedString(value, MAX_STRING_LENGTH);
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Math.abs(value) > 1_000_000_000) {
      throw new Error("Extension message contains an invalid number.");
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY_LENGTH) {
      throw new Error("Extension message array exceeds the item limit.");
    }
    return value.map(item => copyValue(item, depth + 1, state));
  }
  if (!isPlainObject(value)) {
    throw new Error("Extension message contains an unsupported value.");
  }

  const clean = Object.create(null);
  for (const key of Object.keys(value)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") {
      throw new Error("Extension message contains a forbidden key.");
    }
    assertBoundedString(key, 128);
    clean[key] = copyValue(value[key], depth + 1, state);
  }
  return clean;
}

function assertExactKeys(value, allowed) {
  if (!isPlainObject(value)) {
    throw new Error("Extension message object is malformed.");
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new Error("Extension message contains an unexpected property.");
    }
  }
  for (const key of allowed) {
    if (!(key in value)) {
      throw new Error("Extension message is missing a required property.");
    }
  }
}

function assertAllowedKeys(value, allowed) {
  if (!isPlainObject(value)) {
    throw new Error("Extension message object is malformed.");
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new Error("Extension message contains an unexpected property.");
    }
  }
}

function assertUrlArray(value) {
  if (!Array.isArray(value)) {
    throw new Error("Extension message URL list is invalid.");
  }
  for (const item of value) {
    assertHttpUrl(item);
  }
}

function assertStringArray(value, maximumItems, maximumItemLength) {
  if (!Array.isArray(value) || value.length > maximumItems) {
    throw new Error("Extension message string list is invalid.");
  }
  for (const item of value) {
    assertBoundedString(item, maximumItemLength);
  }
}

function assertIntegerInRange(value, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error("Extension message number is out of range.");
  }
}

function assertHttpUrl(value) {
  if (!isHttpUrl(value)) {
    throw new Error("Extension message URL is invalid.");
  }
}

function isHttpUrl(value) {
  try {
    const url = new URL(value);
    return value.length <= 4096 && !url.username && !url.password && (url.protocol === "http:" || url.protocol === "https:");
  } catch {
    return false;
  }
}

function assertSenderOrigin(value, sender) {
  const pageUrl = senderPageUrl(sender);
  if (!pageUrl) {
    return;
  }
  if (new URL(value).origin !== new URL(pageUrl).origin) {
    throw new Error("Message URL does not match the sender tab.");
  }
}

function assertSenderDomain(domain, sender) {
  const pageUrl = senderPageUrl(sender);
  if (!pageUrl) {
    return;
  }
  const senderDomain = new URL(pageUrl).hostname.toLowerCase().replace(/^www\./, "");
  if (domain.toLowerCase().replace(/^www\./, "") !== senderDomain) {
    throw new Error("Message domain does not match the sender tab.");
  }
}

function assertDomainMatchesUrl(domain, url) {
  const urlDomain = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  if (domain.toLowerCase().replace(/^www\./, "") !== urlDomain) {
    throw new Error("Message domain does not match its URL.");
  }
}

function senderPageUrl(sender) {
  return typeof sender?.url === "string" && sender.url
    ? sender.url
    : sender?.tab?.url;
}

function assertDomain(value) {
  assertBoundedString(value, 253);
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(value)) {
    throw new Error("Extension message domain is invalid.");
  }
}

function assertOptionalDomain(value) {
  if (value !== null && value !== undefined && value !== "") {
    assertDomain(value);
  }
}

function assertHash(value) {
  assertBoundedString(value, 160);
  if (!/^(?:sha256:)?[a-f0-9]{64}$/i.test(value)) {
    throw new Error("Extension message hash is invalid.");
  }
}

function assertOpaqueIdentifier(value, prefix) {
  assertBoundedString(value, 160);
  if (!value.startsWith(prefix) || !/^[A-Za-z0-9:_-]+$/.test(value)) {
    throw new Error("Extension message identifier is invalid.");
  }
}

function assertBase64Url(value, maximumLength) {
  assertBoundedString(value, maximumLength);
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error("Extension message base64url value is invalid.");
  }
}

function assertBoundedString(value, maximumLength) {
  if (typeof value !== "string" || value.length > maximumLength) {
    throw new Error("Extension message string is invalid.");
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
