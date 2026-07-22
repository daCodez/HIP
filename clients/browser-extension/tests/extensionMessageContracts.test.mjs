import assert from "node:assert/strict";
import test from "node:test";

import {
  safeExtensionResult,
  validateBackgroundMessage
} from "../src/extensionMessageContracts.js";

const runtimeId = "hip-test-extension";
const contentSender = Object.freeze({
  id: runtimeId,
  url: "https://example.com/account?private=value",
  tab: Object.freeze({ id: 17 })
});
const popupSender = Object.freeze({
  id: runtimeId,
  url: `chrome-extension://${runtimeId}/src/popup.html`
});

const hash = `sha256:${"a".repeat(64)}`;

function emptySummary() {
  return {
    apiStatus: "Success", website: null, linksScanned: 0, riskyLinks: 0,
    suspiciousLinks: 0, dangerousLinks: 0, unknownLinks: 0, downloadCandidates: 0,
    executableDownloadCandidates: 0, downloadLinks: [], shortenedLinkCandidates: 0,
    obfuscatedLinkCandidates: 0, redirectCandidates: 0, redirectSignals: [],
    formsDetected: 0, loginFormsDetected: 0, passwordFieldsDetected: 0,
    paymentFieldsDetected: 0, crossDomainLoginForms: 0, socialLinkCandidates: 0,
    webmailLinkCandidates: 0, clientChatLinkCandidates: 0, inlineScriptCount: 0,
    externalScriptUrls: [], suspiciousScriptPatternCount: 0, siteSafetyStatus: "Safe",
    siteSafetyDataSource: "SiteSafetyScan", siteSafetyScannedAtUtc: null,
    siteSafetyError: null, domainTrustScore: 90, pageTrustScore: 90,
    contentRiskScore: 10, finalHipScore: 90, confidenceLevel: "High",
    hipScoringModelVersion: "hip-score-v1", hipPresentationStatus: "Safe",
    evidenceFreshness: "Fresh", trustAssertionDisposition: "Allowed",
    providerEvidenceCount: 0, siteSafety: null, scanResultSubmission: "Success",
    scanResultDataSource: "BrowserPluginScan", scanStage: "Complete",
    lastSubmittedUtc: null, lastScanUtc: null, updatedAt: null,
    scanResultError: null, pageUrlHash: hash, isHttps: true,
    pluginVersion: "HIP Plugin v0.1.14-dev"
  };
}

test("accepts the complete reviewed service-worker message inventory", () => {
  const contentMessages = [
    { type: "HIP_GET_PLUGIN_VERSION" },
    { type: "HIP_GET_SETTINGS" },
    { type: "HIP_GET_BANNER_DISMISSED", domain: "example.com", pageKey: hash },
    { type: "HIP_SET_BANNER_DISMISSED", domain: "example.com", pageKey: hash },
    { type: "HIP_LOOKUP_DOMAIN", domain: "target.example" },
    { type: "HIP_SCORE_SITE", request: { domain: "example.com", url: "https://example.com/account" } },
    { type: "HIP_SCAN_LINKS", pageUrl: "https://example.com/account", links: ["https://target.example/"] },
    {
      type: "HIP_SCAN_SITE_SAFETY",
      request: {
        url: "https://example.com/account",
        pluginVersion: "HIP Plugin v0.1.14-dev",
        observedSignals: {
          downloadLinks: [], hasLoginForm: false, hasPasswordField: false,
          hasPaymentField: false, inlineScriptCount: 0, externalScriptUrls: [],
          suspiciousScriptPatternCount: 0, trustDataAvailable: true,
          shortenedLinkCount: 0, obfuscatedLinkCount: 0, clientChatLinkCount: 0,
          clientChatContextObserved: false, redirectChain: []
        }
      }
    },
    { type: "HIP_SAFETY_URL", originalUrl: "https://example.com/account", sourceDomain: "example.com", riskStatus: "Safe" },
    {
      type: "HIP_REPORT_RISK_FINDING",
      report: {
        platform: "Web", targetType: "Url", domain: "target.example", urlHash: hash,
        originalUrl: null, senderHash: null, riskLevel: "Suspicious", reason: "Risk found.",
        detectedAtUtc: "2026-07-20T00:00:00Z", reporterTrustLevel: "Medium",
        privacySafeEvidence: {
          evidenceType: "browser-link-risk",
          summary: "Privacy-safe browser link evidence.",
          facts: {
            sourceDomain: "example.com", targetDomain: "target.example",
            scanMode: "Normal", linkContext: "page-link", downloadCandidate: "false"
          },
          containsPrivateContent: false
        },
        hipSignature: "development-placeholder"
      }
    },
    {
      type: "HIP_SUBMIT_SITE_FEEDBACK",
      feedback: {
        targetType: 5, targetId: "example.com", eventType: 0, severity: 0,
        reporterTrustLevel: 0, reason: "Looks safe.", platform: "Web", urlHash: hash
      }
    },
    {
      type: "HIP_SAVE_SCAN_RESULT",
      result: {
        domain: "example.com", pageUrl: null, pageUrlHash: hash,
        pluginVersion: "HIP Plugin v0.1.14-dev", scannedAtUtc: null, score: 90, riskLevel: "Safe",
        status: "Safe", reasons: ["No elevated risk."], linksScanned: 1,
        riskyLinksFound: 0, suspiciousLinksFound: 0, dangerousLinksFound: 0,
        recommendedAction: "Allow", privacySafeMetadata: { scanMode: "Normal" }
      }
    },
    { type: "HIP_SCAN_SUMMARY", summary: emptySummary() },
    { type: "HIP_DEVICE_PREPARE" },
    { type: "HIP_DEVICE_STAGE", handle: `pending:${"a".repeat(24)}`, deviceId: `dev_${"b".repeat(24)}` },
    { type: "HIP_DEVICE_SIGN_CHALLENGE", deviceId: `dev_${"b".repeat(24)}`, signingInput: "SGVsbG8" },
    { type: "HIP_DEVICE_ACTIVATE", deviceId: `dev_${"b".repeat(24)}` },
    { type: "HIP_DEVICE_REMOVE", deviceId: `dev_${"b".repeat(24)}` },
    { type: "HIP_DEVICE_RECONCILE", activeDeviceIds: [`dev_${"b".repeat(24)}`] }
  ];

  for (const message of contentMessages) {
    assert.equal(validateBackgroundMessage(message, contentSender, runtimeId).ok, true, message.type);
  }

  assert.equal(validateBackgroundMessage({ type: "HIP_GET_SCAN_SUMMARY", tabId: 17 }, popupSender, runtimeId).ok, true);
});

test("accepts and prototype-strips a valid tab-bound score request", () => {
  const validation = validateBackgroundMessage({
    type: "HIP_SCORE_SITE",
    request: { domain: "example.com", url: "https://example.com/account" }
  }, contentSender, runtimeId);

  assert.equal(validation.ok, true);
  assert.equal(Object.getPrototypeOf(validation.message), null);
  assert.equal(Object.getPrototypeOf(validation.message.request), null);
});

test("rejects unknown message types and extra root properties", () => {
  assert.equal(validateBackgroundMessage({ type: "HIP_DELETE_ALL" }, contentSender, runtimeId).ok, false);
  assert.equal(validateBackgroundMessage({
    type: "HIP_LOOKUP_DOMAIN",
    domain: "example.com",
    authorization: "attacker supplied"
  }, contentSender, runtimeId).ok, false);
});

test("rejects senders outside this extension and disallowed sender contexts", () => {
  assert.equal(validateBackgroundMessage(
    { type: "HIP_GET_SETTINGS" },
    { ...contentSender, id: "different-extension" },
    runtimeId
  ).ok, false);

  assert.equal(validateBackgroundMessage(
    { type: "HIP_GET_SETTINGS" },
    popupSender,
    runtimeId
  ).ok, false);

  assert.equal(validateBackgroundMessage(
    { type: "HIP_GET_SCAN_SUMMARY", tabId: 17 },
    popupSender,
    runtimeId
  ).ok, true);
});

test("binds page-specific URL and domain claims to the sender tab", () => {
  assert.match(validateBackgroundMessage({
    type: "HIP_SCORE_SITE",
    request: { domain: "attacker.example", url: "https://attacker.example/" }
  }, contentSender, runtimeId).error, /sender tab/);

  assert.match(validateBackgroundMessage({
    type: "HIP_SET_BANNER_DISMISSED",
    domain: "attacker.example",
    pageKey: `sha256:${"a".repeat(64)}`
  }, contentSender, runtimeId).error, /sender tab/);
});

test("rejects executable URLs, credentials, oversized arrays, and oversized strings", () => {
  assert.equal(validateBackgroundMessage({
    type: "HIP_SCAN_LINKS",
    pageUrl: "https://example.com/",
    links: ["javascript:alert(1)"]
  }, contentSender, runtimeId).ok, false);

  assert.equal(validateBackgroundMessage({
    type: "HIP_SCAN_LINKS",
    pageUrl: "https://user:secret@example.com/",
    links: []
  }, contentSender, runtimeId).ok, false);

  assert.equal(validateBackgroundMessage({
    type: "HIP_SCAN_LINKS",
    pageUrl: "https://example.com/",
    links: Array.from({ length: 201 }, (_, index) => `https://target${index}.example/`)
  }, contentSender, runtimeId).ok, false);

  assert.equal(validateBackgroundMessage({
    type: "HIP_LOOKUP_DOMAIN",
    domain: "a".repeat(5000)
  }, contentSender, runtimeId).ok, false);
});

test("rejects prototype-pollution keys at any depth", () => {
  const message = JSON.parse(`{
    "type":"HIP_SUBMIT_SITE_FEEDBACK",
    "feedback":{
      "targetType":5,
      "targetId":"example.com",
      "eventType":0,
      "severity":0,
      "reporterTrustLevel":0,
      "reason":"safe",
      "platform":"Web",
      "urlHash":"sha256:${"b".repeat(64)}",
      "metadata":{"__proto__":{"polluted":true}}
    }
  }`);

  assert.equal(validateBackgroundMessage(message, popupSender, runtimeId).ok, false);
  assert.equal({}.polluted, undefined);
});

test("rejects private risk-report fields and arbitrary API metadata", () => {
  const report = {
    platform: "Web", targetType: "Url", domain: "target.example", urlHash: hash,
    originalUrl: "https://target.example/private?token=secret", senderHash: null,
    riskLevel: "Suspicious", reason: "Risk found.", detectedAtUtc: "2026-07-20T00:00:00Z",
    reporterTrustLevel: "Medium",
    privacySafeEvidence: {
      evidenceType: "browser-link-risk", summary: "Safe summary.",
      facts: {
        sourceDomain: "example.com", targetDomain: "target.example",
        scanMode: "Normal", linkContext: "page-link", downloadCandidate: "false"
      },
      containsPrivateContent: false
    },
    hipSignature: "development-placeholder"
  };

  assert.equal(validateBackgroundMessage({ type: "HIP_REPORT_RISK_FINDING", report }, contentSender, runtimeId).ok, false);

  const result = {
    domain: "example.com", pageUrl: null, pageUrlHash: hash,
    pluginVersion: "HIP Plugin v0.1.14-dev", scannedAtUtc: null, score: 90, riskLevel: "Safe",
    status: "Safe", reasons: [], linksScanned: 0, riskyLinksFound: 0,
    suspiciousLinksFound: 0, dangerousLinksFound: 0, recommendedAction: "Allow",
    privacySafeMetadata: { pageText: "must not cross the boundary" }
  };
  assert.equal(validateBackgroundMessage({ type: "HIP_SAVE_SCAN_RESULT", result }, contentSender, runtimeId).ok, false);
});

test("bounds and prototype-strips API-derived response data", () => {
  const clean = safeExtensionResult({ status: "Safe", nested: { score: 90 } });
  assert.equal(Object.getPrototypeOf(clean), null);
  assert.equal(Object.getPrototypeOf(clean.nested), null);
  assert.throws(() => safeExtensionResult({ value: "x".repeat(5000) }), /string is invalid/);
});
