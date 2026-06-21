import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const extensionRoot = fileURLToPath(new URL("../", import.meta.url));

test("browser scan assessment helper is loaded before content script", () => {
  const manifest = JSON.parse(read("manifest.json"));
  const scripts = manifest.content_scripts[0].js;

  assert.ok(scripts.indexOf("src/browserScanAssessment.js") > -1);
  assert.ok(scripts.indexOf("src/browserScanAssessment.js") < scripts.indexOf("src/content.js"));
});

test("browser scan assessment keeps no-data scans privacy safe", () => {
  const helper = loadHelper();
  const result = helper.browserScanAssessment(
    {
      dataSource: "NoStoredData",
      reasons: ["HIP has not scanned this domain yet."]
    },
    {
      linksScanned: 3,
      riskyLinks: 0,
      suspiciousLinks: 0,
      dangerousLinks: 0,
      unknownLinks: 0,
      clientChatLinkCandidates: 1
    }
  );

  assert.equal(result.status, "MostlyTrusted");
  assert.equal(result.reasons.some(reason => reason.includes("message text")), true);
  assert.equal(JSON.stringify(result).includes("HIP has not scanned this domain yet"), false);
});

test("browser scan assessment maps Site Safety scans into stored scan summaries", () => {
  const helper = loadHelper();
  const result = helper.browserScanAssessment(
    { dataSource: "NoStoredData" },
    {
      siteSafetyDataSource: "SiteSafetyScan",
      siteSafetyStatus: "Clean",
      finalHipScore: 77,
      confidenceLevel: "Medium",
      providerEvidenceCount: 1
    }
  );

  assert.equal(result.score, 77);
  assert.equal(result.status, "MostlyTrusted");
  assert.equal(result.reasons.includes("Site Safety confidence: Medium."), true);
});

test("browser scan assessment recommends safety routing for risky statuses", () => {
  const helper = loadHelper();

  assert.equal(helper.recommendedSiteAction("Dangerous"), "RouteToSafetyPage");
  assert.equal(helper.recommendedSiteAction("LimitedTrustData"), "ShowLabel");
  assert.equal(helper.recommendedSiteAction("MostlyTrusted"), "Allow");
});

function loadHelper() {
  const sandbox = { globalThis: {} };
  vm.runInNewContext(read("src/browserScanAssessment.js"), sandbox);
  return sandbox.globalThis.HipBrowserScanAssessment;
}

function read(relativePath) {
  return readFileSync(join(extensionRoot, relativePath), "utf8");
}
