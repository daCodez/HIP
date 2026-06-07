import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  browserScanAssessment,
  buildBannerFeedbackReport,
  buildScanResultPayload,
  formatPluginVersion,
  hasRiskyLimitedTrustSignals,
  HipApiClient,
  isHipOwnedPageUrl,
  normalizeHipSettings,
  shouldShowTrustBanner,
  stripQueryAndFragment
} from "../src/hipApiClient.js";

test("plugin creates privacy-safe scan result payload", () => {
  const payload = buildScanResultPayload({
    domain: "example.com",
    pageUrl: "https://example.com/page",
    lookup: {
      finalHipScore: 84,
      status: "Trusted",
      reasons: ["No risky links found"]
    },
    summary: {
      linksScanned: 42,
      riskyLinks: 2,
      suspiciousLinks: 2,
      dangerousLinks: 0,
      apiStatus: "Available"
    },
    settings: {
      scanMode: "Normal"
    },
    pageUrlHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    pluginVersion: "HIP Plugin v0.1.0-dev",
    submittedAtUtc: "2026-06-01T00:00:00Z"
  });

  assert.equal(payload.domain, "example.com");
  assert.equal(payload.pageUrl, null);
  assert.equal(payload.pageUrlHash, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  assert.equal(payload.pluginVersion, "HIP Plugin v0.1.0-dev");
  assert.equal(payload.score, 84);
  assert.equal(payload.status, "Trusted");
  assert.deepEqual(payload.reasons, ["No risky links found"]);
  assert.equal(payload.linksScanned, 42);
  assert.equal(payload.riskyLinksFound, 2);
  assert.equal(payload.suspiciousLinksFound, 2);
  assert.equal(payload.dangerousLinksFound, 0);
  assert.equal(payload.privacySafeMetadata.scanTimestampUtc, "2026-06-01T00:00:00Z");
  assert.equal(payload.privacySafeMetadata.pluginVersion, "HIP Plugin v0.1.0-dev");
});

test("scan result payload sends stripped raw page URL only when explicitly enabled", () => {
  const payload = buildScanResultPayload({
    domain: "example.com",
    pageUrl: "https://example.com/private?token=secret#section",
    lookup: { status: "Trusted", score: 84 },
    summary: {},
    settings: {
      allowRawPageUrlSubmission: true
    }
  });

  assert.equal(payload.pageUrl, "https://example.com/private");
  assert.equal(JSON.stringify(payload).includes("token=secret"), false);
});

test("strip query helper rejects unsafe protocols", () => {
  assert.equal(stripQueryAndFragment("https://example.com/path?token=secret#fragment"), "https://example.com/path");
  assert.equal(stripQueryAndFragment("javascript:alert(1)"), null);
  assert.equal(stripQueryAndFragment("not a url"), null);
});

test("scan result payload includes privacy-safe observed page signals", () => {
  const payload = buildScanResultPayload({
    domain: "example.com",
    pageUrl: "https://example.com/login",
    pageUrlHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    pluginVersion: "HIP Plugin v0.1.0-dev",
    lookup: { status: "LimitedTrustData", score: 56 },
    summary: {
      isHttps: true,
      downloadCandidates: 3,
      executableDownloadCandidates: 1,
      formsDetected: 2,
      loginFormsDetected: 1,
      passwordFieldsDetected: 1,
      paymentFieldsDetected: 1,
      shortenedLinkCandidates: 2,
      obfuscatedLinkCandidates: 1,
      redirectCandidates: 2
    }
  });

  assert.equal(payload.privacySafeMetadata.isHttps, "true");
  assert.equal(payload.privacySafeMetadata.downloadCandidates, "3");
  assert.equal(payload.privacySafeMetadata.executableDownloadCandidates, "1");
  assert.equal(payload.privacySafeMetadata.formsDetected, "2");
  assert.equal(payload.privacySafeMetadata.loginFormsDetected, "1");
  assert.equal(payload.privacySafeMetadata.passwordFieldsDetected, "1");
  assert.equal(payload.privacySafeMetadata.paymentFieldsDetected, "1");
  assert.equal(payload.privacySafeMetadata.shortenedLinkCandidates, "2");
  assert.equal(payload.privacySafeMetadata.obfuscatedLinkCandidates, "1");
  assert.equal(payload.privacySafeMetadata.redirectCandidates, "2");
});

test("no-data lookup state persists actual browser scan result", () => {
  const payload = buildScanResultPayload({
    domain: "example.com",
    pageUrl: "https://example.com/page",
    lookup: {
      finalHipScore: 0,
      status: "Unknown",
      dataSource: "NoStoredData",
      explanations: ["HIP has not scanned this domain yet."]
    },
    summary: {
      linksScanned: 0,
      riskyLinks: 0,
      suspiciousLinks: 0,
      dangerousLinks: 0,
      unknownLinks: 0,
      downloadCandidates: 0,
      apiStatus: "Available"
    },
    settings: {
      scanMode: "Normal"
    },
    submittedAtUtc: "2026-06-01T00:00:00Z"
  });

  assert.equal(payload.score, 80);
  assert.equal(payload.status, "MostlyTrusted");
  assert.equal(payload.recommendedAction, "Allow");
  assert.equal(payload.reasons.some(reason => reason.includes("HIP has not scanned this domain yet")), false);
  assert.equal(payload.reasons.some(reason => reason.includes("No risky external links")), true);
});

test("browser scan assessment penalizes suspicious and dangerous scan counts", () => {
  const suspicious = browserScanAssessment({ dataSource: "NoStoredData" }, {
    linksScanned: 4,
    riskyLinks: 1,
    suspiciousLinks: 1,
    dangerousLinks: 0,
    unknownLinks: 0
  });
  const dangerous = browserScanAssessment({ dataSource: "NoStoredData" }, {
    linksScanned: 4,
    riskyLinks: 1,
    suspiciousLinks: 0,
    dangerousLinks: 1,
    unknownLinks: 0
  });

  assert.equal(suspicious.status, "Suspicious");
  assert.equal(dangerous.status, "Dangerous");
  assert.ok(dangerous.score < suspicious.score);
});

test("scan result payload excludes page text and form values", () => {
  const payload = buildScanResultPayload({
    domain: "example.com",
    pageUrl: "https://example.com/page",
    lookup: { status: "Caution", score: 52 },
    summary: {
      pageText: "private body text",
      formValues: "password=secret"
    }
  });

  assert.equal("pageText" in payload, false);
  assert.equal("formValues" in payload, false);
  assert.equal("password" in payload.privacySafeMetadata, false);
  assert.equal(JSON.stringify(payload).includes("private body text"), false);
  assert.equal(JSON.stringify(payload).includes("password=secret"), false);
});

test("plugin calls scan-results endpoint", async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return {
      ok: true,
      json: async () => ({ saved: true })
    };
  };

  try {
    const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5260" });
    await client.saveScanResult(buildScanResultPayload({
      domain: "example.com",
      pageUrl: "https://example.com/page",
      lookup: { status: "Trusted", score: 84 },
      summary: {}
    }));
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://localhost:5099/api/v1/browser/scan-results");
  assert.equal(calls[0].options.method, "POST");
});

test("plugin scan result request sends URL hash and plugin version to API", async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return {
      ok: true,
      json: async () => ({ saved: true })
    };
  };

  try {
    const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5260" });
    await client.saveScanResult(buildScanResultPayload({
      domain: "example.com",
      pageUrl: "https://example.com/page?token=secret",
      pageUrlHash: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      pluginVersion: "HIP Plugin v0.1.0-dev",
      lookup: { status: "Trusted", score: 84 },
      summary: {}
    }));
  } finally {
    globalThis.fetch = originalFetch;
  }

  const body = JSON.parse(calls[0].options.body);
  assert.equal(body.pageUrl, null);
  assert.equal(body.pageUrlHash, "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
  assert.equal(body.pluginVersion, "HIP Plugin v0.1.0-dev");
  assert.equal(JSON.stringify(body).includes("token=secret"), false);
});

test("submission failure rejects without requiring popup failure", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: false,
    status: 500,
    json: async () => ({})
  });

  try {
    const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5260" });
    await assert.rejects(
      () => client.saveScanResult(buildScanResultPayload({
        domain: "example.com",
        pageUrl: "https://example.com/page",
        lookup: { status: "Trusted", score: 84 },
        summary: {}
      })),
      /scan result persistence failed/
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("submitScanResults false is preserved in settings", () => {
  const settings = normalizeHipSettings({
    apiBaseUrl: "http://localhost:5099",
    submitScanResults: false
  });

  assert.equal(settings.submitScanResults, false);
});

test("invalid API base URL is handled safely", async () => {
  const client = new HipApiClient({ apiBaseUrl: "not a url", webBaseUrl: "http://localhost:5260" });

  await assert.rejects(
    () => client.saveScanResult(buildScanResultPayload({
      domain: "example.com",
      pageUrl: "https://example.com/page",
      lookup: { status: "Trusted", score: 84 },
      summary: {}
    })),
    /Invalid HIP API base URL/
  );
});

test("site safety request includes structural observations", () => {
  const client = new HipApiClient({ apiBaseUrl: "http://localhost:5099", webBaseUrl: "http://localhost:5260" });
  const request = client.buildSiteSafetyRequest("https://example.com/login", {
    pluginVersion: "HIP Plugin v0.1.0-dev",
    downloadLinks: ["https://example.com/setup.exe"],
    loginFormsDetected: 1,
    passwordFieldsDetected: 1,
    paymentFieldsDetected: 1,
    shortenedLinkCandidates: 2,
    obfuscatedLinkCandidates: 1,
    redirectSignals: ["https://example.com/out?url=https%3A%2F%2Ftarget.example"],
    inlineScriptCount: 3,
    externalScriptUrls: ["https://cdn.example.com/app.js"]
  });

  assert.equal(request.pluginVersion, "HIP Plugin v0.1.0-dev");
  assert.equal(request.observedSignals.hasLoginForm, true);
  assert.equal(request.observedSignals.hasPasswordField, true);
  assert.equal(request.observedSignals.hasPaymentField, true);
  assert.equal(request.observedSignals.shortenedLinkCount, 2);
  assert.equal(request.observedSignals.obfuscatedLinkCount, 1);
  assert.deepEqual(request.observedSignals.redirectChain, ["https://example.com/out?url=https%3A%2F%2Ftarget.example"]);
});

test("content script contains duplicate scan submission guards", async () => {
  const contentScript = await readFile(new URL("../src/content.js", import.meta.url), "utf8");
  const backgroundScript = await readFile(new URL("../src/background.js", import.meta.url), "utf8");

  assert.match(contentScript, /pendingScanSubmissions/);
  assert.match(contentScript, /pageUrlHash/);
  assert.match(backgroundScript, /pendingScanResultSaves/);
  assert.match(backgroundScript, /duplicateSuppressed/);
});

test("plugin version is formatted from manifest version", () => {
  assert.equal(formatPluginVersion("0.1.0"), "HIP Plugin v0.1.0-dev");
});

test("hip owned web pages are skipped by content scanning guard", () => {
  const settings = {
    apiBaseUrl: "http://localhost:5099",
    webBaseUrl: "http://localhost:5260"
  };

  assert.equal(isHipOwnedPageUrl("http://localhost:5260/lookup/example.com", settings), true);
  assert.equal(isHipOwnedPageUrl("http://localhost:5099/swagger", settings), true);
  assert.equal(isHipOwnedPageUrl("https://example.com", settings), false);
});

test("hip owned page guard tolerates invalid settings safely", () => {
  assert.equal(isHipOwnedPageUrl("https://example.com", { apiBaseUrl: "not a url" }), false);
});

test("banner display defaults to warnings only", () => {
  assert.equal(shouldShowTrustBanner({ status: "Trusted" }, {}, {}), false);
  assert.equal(shouldShowTrustBanner({ status: "MostlyTrusted" }, {}, {}), false);
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, {}, {}), false);
  assert.equal(shouldShowTrustBanner({ status: "Unknown" }, {}, {}), false);
  assert.equal(shouldShowTrustBanner({ status: "Suspicious" }, {}, {}), true);
  assert.equal(shouldShowTrustBanner({ status: "HighRisk" }, {}, {}), true);
  assert.equal(shouldShowTrustBanner({ status: "Dangerous" }, {}, {}), true);
});

test("unknown without risky signals does not show banner", () => {
  assert.equal(shouldShowTrustBanner({ status: "Unknown" }, {
    loginFormsDetected: 0,
    passwordFieldsDetected: 0,
    paymentFieldsDetected: 0,
    executableDownloadCandidates: 0,
    dangerousLinks: 0
  }, { bannerDisplayMode: "WarningsOnly" }), false);
});

test("banner display handles limited trust special cases", () => {
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, { loginFormsDetected: 1 }, {}), true);
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, { passwordFieldsDetected: 1 }, {}), true);
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, { paymentFieldsDetected: 1 }, {}), true);
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, { executableDownloadCandidates: 1 }, {}), true);
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, { suspiciousRedirects: 1 }, {}), true);
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, { containsPhishingWording: true }, {}), true);
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, { containsScamWording: true }, {}), true);
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, { containsImpersonationWording: true }, {}), true);
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, { knownRiskyProviderEvidence: true }, {}), true);
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, { trustedDomainRiskMismatch: true }, {}), true);
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, { riskyUserGeneratedContent: true }, {}), true);
});

test("limited trust risky signal helper ignores private content fields", () => {
  assert.equal(hasRiskyLimitedTrustSignals({
    pageText: "private message text",
    formValues: "password=secret"
  }), false);
  assert.equal(hasRiskyLimitedTrustSignals({ passwordFieldsDetected: 1 }), true);
});

test("trusted and mostly trusted pages do not show warning banners", () => {
  assert.equal(shouldShowTrustBanner({ status: "Trusted" }, { suspiciousLinks: 1 }, {}), false);
  assert.equal(shouldShowTrustBanner({ status: "MostlyTrusted" }, { executableDownloadCandidates: 1 }, {}), false);
  assert.equal(shouldShowTrustBanner({ status: "ProbablySafe" }, { paymentFieldsDetected: 1 }, {}), false);
});

test("banner display does not interrupt for mostly trusted pages with broad attention counts only", () => {
  assert.equal(shouldShowTrustBanner({ status: "MostlyTrusted" }, { riskyLinks: 4, unknownLinks: 4 }, {}), false);
});

test("banner display modes are respected", () => {
  assert.equal(shouldShowTrustBanner({ status: "Dangerous" }, {}, { bannerDisplayMode: "NeverShow" }), false);
  assert.equal(shouldShowTrustBanner({ status: "Trusted" }, {}, { bannerDisplayMode: "AlwaysShow" }), true);
  assert.equal(shouldShowTrustBanner({ status: "Suspicious" }, {}, { bannerDisplayMode: "DangerousOnly" }), false);
  assert.equal(shouldShowTrustBanner({ status: "HighRisk" }, {}, { bannerDisplayMode: "DangerousOnly" }), false);
  assert.equal(shouldShowTrustBanner({ status: "Critical" }, {}, { bannerDisplayMode: "DangerousOnly" }), false);
  assert.equal(shouldShowTrustBanner({ status: "Dangerous" }, {}, { bannerDisplayMode: "DangerousOnly" }), true);
  assert.equal(shouldShowTrustBanner({ status: "Trusted" }, { dangerousLinks: 1 }, { bannerDisplayMode: "DangerousOnly" }), false);
  assert.equal(shouldShowTrustBanner({ status: "Dangerous" }, {}, { bannerDisplayMode: "WarningsOnly", enableWarningBanner: false }), false);
});

test("warnings only mode shows warning statuses and risky limited trust only", () => {
  const settings = { bannerDisplayMode: "WarningsOnly" };

  assert.equal(shouldShowTrustBanner({ status: "Suspicious" }, {}, settings), true);
  assert.equal(shouldShowTrustBanner({ status: "HighRisk" }, {}, settings), true);
  assert.equal(shouldShowTrustBanner({ status: "Dangerous" }, {}, settings), true);
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, {}, settings), false);
  assert.equal(shouldShowTrustBanner({ status: "LimitedTrustData" }, { paymentFieldsDetected: 1 }, settings), true);
});

test("banner feedback creates privacy-safe suspicious evidence", async () => {
  const payload = await buildBannerFeedbackReport({
    feedbackType: "LooksSuspicious",
    domain: "example.com",
    pageUrl: "https://example.com/private?token=secret",
    lookup: { status: "LimitedTrustData", finalHipScore: 56 },
    settings: { scanMode: "Normal" },
    reportedAtUtc: "2026-06-01T00:00:00Z",
    hashUrl: async () => "sha256:test-hash"
  });

  assert.equal(payload.sourceClient, "BrowserPlugin");
  assert.equal(payload.riskLevel, "Suspicious");
  assert.equal(payload.urlHash, "sha256:test-hash");
  assert.equal(payload.originalUrl, null);
  assert.equal(payload.privacySafeEvidence.evidenceType, "browser-banner-feedback");
  assert.equal(payload.privacySafeEvidence.containsPrivateContent, false);
  assert.equal(payload.privacySafeEvidence.facts.source, "BrowserPluginBanner");
  assert.equal(JSON.stringify(payload).includes("token=secret"), false);
});

test("banner looks safe feedback is evidence not raw voting", async () => {
  const payload = await buildBannerFeedbackReport({
    feedbackType: "LooksSafe",
    domain: "example.com",
    pageUrl: "https://example.com/",
    lookup: { status: "MostlyTrusted", finalHipScore: 72 },
    hashUrl: async () => "sha256:test-hash"
  });

  assert.equal(payload.riskLevel, "ProbablySafe");
  assert.equal(payload.reporterTrustLevel, "Medium");
  assert.equal(payload.reason.includes("looks safe"), true);
  assert.equal("vote" in payload.privacySafeEvidence.facts, false);
});

test("banner feedback excludes page text and form values", async () => {
  const payload = await buildBannerFeedbackReport({
    feedbackType: "LooksSuspicious",
    domain: "example.com",
    pageUrl: "https://example.com/",
    lookup: { pageText: "private page body", formValues: "password=secret" },
    hashUrl: async () => "sha256:test-hash"
  });

  assert.equal("pageText" in payload, false);
  assert.equal("formValues" in payload, false);
  assert.equal(JSON.stringify(payload).includes("password=secret"), false);
});
