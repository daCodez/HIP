import assert from "node:assert/strict";
import test from "node:test";
import {
  browserScanAssessment,
  buildBannerFeedbackReport,
  buildScanResultPayload,
  formatPluginVersion,
  HipApiClient,
  normalizeHipSettings
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
    submittedAtUtc: "2026-06-01T00:00:00Z"
  });

  assert.equal(payload.domain, "example.com");
  assert.equal(payload.score, 84);
  assert.equal(payload.status, "Trusted");
  assert.deepEqual(payload.reasons, ["No risky links found"]);
  assert.equal(payload.linksScanned, 42);
  assert.equal(payload.riskyLinksFound, 2);
  assert.equal(payload.suspiciousLinksFound, 2);
  assert.equal(payload.dangerousLinksFound, 0);
  assert.equal(payload.privacySafeMetadata.scanTimestampUtc, "2026-06-01T00:00:00Z");
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

test("plugin version is formatted from manifest version", () => {
  assert.equal(formatPluginVersion("0.1.0"), "HIP Plugin v0.1.0-dev");
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
