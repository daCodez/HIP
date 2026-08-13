import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, expect, test } from "@playwright/test";

const extensionPath = fileURLToPath(new URL("../", import.meta.url));
const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));
const expectedPluginVersion = `HIP Plugin v${manifest.version}-dev`;

/** Returns an explicitly configured Chromium build; otherwise Playwright uses its tested build. */
function chromiumExecutablePath() {
  return process.env.HIP_CHROMIUM_PATH || undefined;
}

/** Launches HIP in a clean profile and returns its extension identifier. */
async function launchHipExtension({ useLocalServices = false } = {}) {
  const profilePath = await mkdtemp(path.join(tmpdir(), "hip-extension-e2e-"));
  const context = await chromium.launchPersistentContext(profilePath, {
    headless: false,
    executablePath: chromiumExecutablePath(),
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
      "--no-first-run",
      "--disable-default-apps"
    ]
  });
  const serviceWorker = context.serviceWorkers()[0]
    ?? await context.waitForEvent("serviceworker", { timeout: 15_000 });
  if (useLocalServices) {
    await serviceWorker.evaluate(() => chrome.storage.sync.set({
      hipApiBaseUrl: "http://localhost:5099",
      apiBaseUrl: "http://localhost:5099",
      webBaseUrl: "http://localhost:5123",
      serviceDefaultsVersion: 1
    }));
  }
  return {
    context,
    extensionId: new URL(serviceWorker.url()).host,
    profilePath
  };
}

test("loads the unpacked MV3 extension and renders the real popup", async () => {
  const runtime = await launchHipExtension();
  const page = await runtime.context.newPage();
  const consoleProblems = [];
  const pageErrors = [];
  page.on("console", message => {
    if (["error", "warning"].includes(message.type())) {
      consoleProblems.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on("pageerror", error => pageErrors.push(error.message));

  try {
    await page.goto(`chrome-extension://${runtime.extensionId}/src/popup.html`);
    const versionResponse = await page.evaluate(() =>
      chrome.runtime.sendMessage({ type: "HIP_GET_PLUGIN_VERSION" }));

    await expect(page).toHaveTitle("HIP");
    await expect(page.getByRole("heading", { name: "Website Trust" })).toBeVisible();
    await expect(page.getByText("HIP checks identity, safety, and trust evidence for this site.")).toBeVisible();
    expect(versionResponse).toEqual({ ok: true, result: expectedPluginVersion });
    await expect(page.locator("#pluginVersion")).toContainText(expectedPluginVersion);
    expect(pageErrors).toEqual([]);
    expect(consoleProblems).toEqual([]);
  } finally {
    await runtime.context.close();
    await rm(runtime.profilePath, { recursive: true, force: true });
  }
});

test("prepares a non-exportable installation key through the consumer-page bridge", async () => {
  const runtime = await launchHipExtension({ useLocalServices: true });
  const page = await runtime.context.newPage();

  try {
    await runtime.context.route("http://localhost:5123/**", route => route.fulfill({
      status: 200,
      contentType: "text/html",
      body: "<!doctype html><title>HIP Device Test</title><main>Consumer device registration</main>"
    }));
    await page.goto("http://localhost:5123/devices");

    const response = await page.evaluate(() => new Promise((resolve, reject) => {
      const requestId = `e2e-${crypto.randomUUID()}`;
      const timeout = setTimeout(() => reject(new Error("HIP device bridge timed out.")), 15_000);
      window.addEventListener("message", function onMessage(event) {
        if (event.source !== window ||
            event.data?.source !== "hip-extension-device-registration" ||
            event.data?.requestId !== requestId) {
          return;
        }

        clearTimeout(timeout);
        window.removeEventListener("message", onMessage);
        resolve(event.data);
      });
      window.postMessage({
        source: "hip-web-device-registration",
        type: "request",
        requestId,
        operation: "prepare",
        payload: {}
      }, window.location.origin);
    }));

    expect(response.ok).toBe(true);
    expect(response.result.handle).toMatch(/^pending:[A-Za-z0-9_-]{24,}$/);
    expect(response.result.publicKey).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(response.result.algorithm).toBe("ECDSA-P256-SHA256");
    expect(JSON.stringify(response)).not.toContain("privateKey");
  } finally {
    await runtime.context.close();
    await rm(runtime.profilePath, { recursive: true, force: true });
  }
});

test("renders a meaningful-risk banner and submits privacy-safe feedback", async () => {
  const runtime = await launchHipExtension({ useLocalServices: true });
  const page = await runtime.context.newPage();
  const feedbackRequests = [];

  try {
    await runtime.context.route("https://score-sync.test/**", route => route.fulfill({
      status: 200,
      contentType: "text/html",
      body: `<!doctype html>
        <title>Untrusted test page</title>
        <div id="hip-trust-banner">HIP Trust Score: 56/100 HIP Plugin v0.1.34-dev</div>
        <main>private-page-marker-must-not-leave</main>
        <form><input type="password" value="private-password-marker"></form>`
    }));
    await runtime.context.route("http://localhost:5099/**", async route => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      const corsHeaders = {
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "content-type,x-hip-instance-id,x-hip-device-id,x-hip-device-timestamp,x-hip-device-nonce,x-hip-device-body-sha256,x-hip-device-signature",
        "access-control-allow-methods": "GET,POST,OPTIONS"
      };
      if (request.method() === "OPTIONS") {
        await route.fulfill({ status: 204, headers: corsHeaders });
        return;
      }

      if (pathname === "/api/v1/browser/score-site") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          headers: corsHeaders,
          body: JSON.stringify({
            domain: "score-sync.test",
            finalHipScore: 56,
            status: "Suspicious",
            verificationStatus: "Unverified",
            identityVerificationStatus: "NoSignedIdentityFound",
            knownRisks: ["Suspicious redirect evidence."],
            explanations: ["Suspicious redirect evidence."],
            publicLookupUrl: "http://localhost:5123/lookup/domain/score-sync.test"
          })
        });
        return;
      }

      if (pathname === "/api/v1/site-safety/scan") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          headers: corsHeaders,
          body: JSON.stringify({
            status: "Suspicious",
            summary: "HIP found suspicious structural signals.",
            confidenceLevel: "High",
            domainTrustScore: 45,
            pageTrustScore: 30,
            contentRiskScore: 70,
            finalHipScore: 69,
            warnings: ["Suspicious redirect evidence."],
            providerEvidence: [],
            scannedAtUtc: "2026-07-21T12:00:00Z"
          })
        });
        return;
      }

      if (pathname === "/api/v1/public/feedback") {
        feedbackRequests.push(JSON.parse(request.postData() || "{}"));
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          headers: corsHeaders,
          body: JSON.stringify({ accepted: true })
        });
        return;
      }

      if (pathname === "/api/v1/browser/scan-results") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          headers: corsHeaders,
          body: JSON.stringify({ saved: true, domain: "localhost", lastCheckedUtc: "2026-07-21T12:00:00Z" })
        });
        return;
      }

      await route.fulfill({ status: 404, contentType: "application/json", headers: corsHeaders, body: "{}" });
    });

    await page.goto("https://score-sync.test/account?token=private-url-marker");
    const banner = page.locator("#hip-trust-banner");
    await expect(banner).toBeVisible({ timeout: 20_000 });
    await expect(banner).toHaveCount(1);
    await expect(banner).toContainText("Suspicious");
    await expect(banner).toContainText("69/100");
    await expect(banner).toContainText(expectedPluginVersion);
    await expect(banner).not.toContainText("56/100");
    await expect(banner).not.toContainText("v0.1.34-dev");
    await banner.getByRole("button", { name: "Looks Suspicious" }).click();
    await expect.poll(() => feedbackRequests.length).toBe(1);

    const serializedFeedback = JSON.stringify(feedbackRequests[0]);
    expect(serializedFeedback).not.toContain("private-page-marker-must-not-leave");
    expect(serializedFeedback).not.toContain("private-password-marker");
    expect(serializedFeedback).not.toContain("private-url-marker");
    expect(feedbackRequests[0].platform).toBe("Web");
    expect(feedbackRequests[0].targetId).toBe("score-sync.test");
    expect(feedbackRequests[0].eventType).toBe(2);
  } finally {
    await runtime.context.close();
    await rm(runtime.profilePath, { recursive: true, force: true });
  }
});

test("shows a critical interstitial and preserves the host page after explicit continuation", async () => {
  const runtime = await launchHipExtension({ useLocalServices: true });
  const page = await runtime.context.newPage();

  try {
    await runtime.context.route("https://critical-warning.test/**", route => route.fulfill({
      status: 200,
      contentType: "text/html",
      body: `<!doctype html><title>Critical warning fixture</title>
        <main>Host page remains intact</main>
        <form><label>Private field <input id="private-field" value="preserve-me"></label></form>`
    }));
    await runtime.context.route("http://localhost:5099/**", async route => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      const headers = {
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "content-type,x-hip-instance-id,x-hip-device-id,x-hip-device-timestamp,x-hip-device-nonce,x-hip-device-body-sha256,x-hip-device-signature",
        "access-control-allow-methods": "GET,POST,OPTIONS"
      };
      if (request.method() === "OPTIONS") {
        await route.fulfill({ status: 204, headers });
        return;
      }

      let body = {};
      if (pathname === "/api/v1/browser/score-site") {
        body = {
          domain: "critical-warning.test",
          finalHipScore: 14,
          status: "Dangerous",
          verificationStatus: "Unverified",
          identityVerificationStatus: "NoSignedIdentityFound",
          knownRisks: ["Critical phishing evidence."],
          publicLookupUrl: "http://localhost:5123/lookup/domain/critical-warning.test"
        };
      } else if (pathname === "/api/v1/site-safety/scan") {
        body = {
          status: "Critical",
          summary: "HIP found critical phishing evidence.",
          confidenceLevel: "High",
          finalHipScore: 4,
          domainTrustScore: 10,
          pageTrustScore: 2,
          contentRiskScore: 98,
          blockingDisposition: "Block",
          warnings: ["Critical phishing evidence."],
          providerEvidence: [],
          scannedAtUtc: "2026-08-13T12:00:00Z"
        };
      } else if (pathname === "/api/v1/browser/scan-links") {
        body = { results: [] };
      } else if (pathname === "/api/v1/browser/scan-results") {
        body = { saved: true };
      }

      await route.fulfill({ status: 200, contentType: "application/json", headers, body: JSON.stringify(body) });
    });

    await page.goto("https://critical-warning.test/account");
    const interstitial = page.locator("#hip-current-page-interstitial");
    await expect(interstitial).toBeVisible({ timeout: 20_000 });
    await expect(interstitial.getByRole("heading", { name: "HIP recommends leaving this page" })).toBeVisible();
    await expect(interstitial.getByRole("button", { name: "Leave this page" })).toBeFocused();

    await interstitial.getByRole("button", { name: "Continue anyway" }).click();
    await expect(interstitial).toHaveCount(0);
    await expect(page.locator("#private-field")).toHaveValue("preserve-me");
    await expect(page.locator("main")).toContainText("Host page remains intact");
  } finally {
    await runtime.context.close();
    await rm(runtime.profilePath, { recursive: true, force: true });
  }
});

test("keeps routine trust in the popup and shows a safe API-failure state", async () => {
  const runtime = await launchHipExtension({ useLocalServices: true });
  const targetPage = await runtime.context.newPage();
  let apiAvailable = true;
  let savedScanCount = 0;

  try {
    await runtime.context.route("http://localhost:4174/**", route => route.fulfill({
      status: 200,
      contentType: "text/html",
      body: "<!doctype html><title>Routine trust page</title><main>Public test page</main>"
    }));
    await runtime.context.route("http://localhost:5099/**", async route => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      const headers = {
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "content-type,x-hip-instance-id,x-hip-device-id,x-hip-device-timestamp,x-hip-device-nonce,x-hip-device-body-sha256,x-hip-device-signature",
        "access-control-allow-methods": "GET,POST,OPTIONS"
      };
      if (request.method() === "OPTIONS") {
        await route.fulfill({ status: 204, headers });
        return;
      }
      if (!apiAvailable) {
        await route.fulfill({ status: 503, contentType: "application/json", headers, body: "{}" });
        return;
      }

      if (pathname === "/api/v1/browser/score-site") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          headers,
          body: JSON.stringify({
            domain: "localhost",
            finalHipScore: 88,
            status: "Trusted",
            verificationStatus: "Verified",
            identityVerificationStatus: "DomainVerified",
            knownRisks: [],
            explanations: ["HIP found strong trust signals."],
            publicLookupUrl: "http://localhost:5123/lookup/domain/localhost"
          })
        });
        return;
      }
      if (pathname === "/api/v1/site-safety/scan") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          headers,
          body: JSON.stringify({
            status: "Clean",
            summary: "No elevated structural risks found.",
            confidenceLevel: "High",
            domainTrustScore: 90,
            pageTrustScore: 88,
            contentRiskScore: 10,
            finalHipScore: 88,
            warnings: [],
            providerEvidence: [],
            scannedAtUtc: "2026-07-21T12:00:00Z"
          })
        });
        return;
      }
      if (pathname === "/api/v1/browser/scan-results") {
        savedScanCount += 1;
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          headers,
          body: JSON.stringify({ saved: true, domain: "localhost", lastCheckedUtc: "2026-07-21T12:00:00Z" })
        });
        return;
      }
      await route.fulfill({ status: 404, contentType: "application/json", headers, body: "{}" });
    });

    await targetPage.goto("http://localhost:4174/routine");
    await expect.poll(() => savedScanCount, { timeout: 20_000 }).toBeGreaterThan(0);
    await expect(targetPage.locator("#hip-trust-banner")).toHaveCount(0);

    const popup = await runtime.context.newPage();
    await targetPage.bringToFront();
    await popup.goto(`chrome-extension://${runtime.extensionId}/src/popup.html`);
    await expect(popup.locator("#scorePanel")).toBeVisible({ timeout: 20_000 });
    await expect(popup.locator("#status")).toHaveText("Trusted");
    await expect(popup.locator("#score")).toHaveText("88/100");

    apiAvailable = false;
    await targetPage.goto("http://localhost:4174/api-failure");
    await targetPage.bringToFront();
    await popup.reload();
    await expect(popup.locator("#state")).toHaveText(
      "HIP API unavailable. Unable to score this site right now.",
      { timeout: 20_000 });
  } finally {
    await runtime.context.close();
    await rm(runtime.profilePath, { recursive: true, force: true });
  }
});

test("embedded Site view replaces every loading placeholder with terminal Zero to Hero results", async () => {
  const runtime = await launchHipExtension({ useLocalServices: true });
  const targetPage = await runtime.context.newPage();

  try {
    await runtime.context.route("http://localhost:4176/**", route => route.fulfill({
      status: 200,
      contentType: "text/html",
      body: "<!doctype html><title>Zero to Hero fixture</title><main><a href='/about'>About</a></main>"
    }));
    await runtime.context.route("http://localhost:5099/**", async route => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      const headers = {
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "content-type,x-hip-instance-id,x-hip-device-id,x-hip-device-timestamp,x-hip-device-nonce,x-hip-device-body-sha256,x-hip-device-signature",
        "access-control-allow-methods": "GET,POST,OPTIONS"
      };
      if (request.method() === "OPTIONS") {
        await route.fulfill({ status: 204, headers });
        return;
      }

      if (pathname === "/api/v1/browser/score-site") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          headers,
          body: JSON.stringify({
            domain: "score-sync.test",
            score: 89,
            finalHipScore: 89,
            domainTrustScore: 85,
            pageTrustScore: 82,
            contentRiskScore: 100,
            status: "Trusted",
            verificationStatus: "Verified",
            identityStatus: "Verified",
            identityVerificationStatus: "DomainVerified",
            scorePresentation: "Available",
            evidenceCoverage: "Sufficient",
            evidenceConfidence: "Medium",
            certificateApplicationStatus: "Approved",
            certificateProgressStatus: "Certificate active",
            monitoringStatus: "Retry scheduled",
            knownRisks: [],
            explanations: ["HIP found strong trust signals."],
            publicLookupUrl: "http://localhost:5123/lookup/domain/score-sync.test"
          })
        });
        return;
      }
      if (pathname === "/api/v1/site-safety/scan") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          headers,
          body: JSON.stringify({
            status: "Trusted",
            summary: "No elevated structural risks found.",
            confidenceLevel: "High",
            domainTrustScore: 85,
            pageTrustScore: 82,
            contentRiskScore: 100,
            finalHipScore: 88,
            malwareRiskScore: 0,
            phishingRiskScore: 0,
            redirectRiskScore: 0,
            downloadRiskScore: 0,
            scriptRiskScore: 0,
            warnings: [],
            providerEvidence: [],
            scannedAtUtc: "2026-08-13T04:29:00Z"
          })
        });
        return;
      }
      if (pathname === "/api/v1/browser/scan-results") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          headers,
          body: JSON.stringify({ saved: true, domain: "localhost", lastCheckedUtc: "2026-08-13T04:29:00Z" })
        });
        return;
      }

      await route.fulfill({ status: 404, contentType: "application/json", headers, body: "{}" });
    });

    const serviceWorker = runtime.context.serviceWorkers()[0];
    await targetPage.goto("http://localhost:4176/");
    const targetTab = await serviceWorker.evaluate(async () => {
      const tabs = await chrome.tabs.query({});
      return tabs.find(tab => tab.url?.startsWith("http://localhost:4176/"));
    });
    expect(targetTab?.id).toBeTruthy();

    const siteView = await runtime.context.newPage();
    await siteView.goto(
      `chrome-extension://${runtime.extensionId}/src/popup.html?embedded=1&tab=${targetTab.id}&page=${encodeURIComponent(targetTab.url)}`);

    await expect(siteView.locator("#score")).toHaveText("89/100", { timeout: 20_000 });
    await expect(siteView.locator("#status")).toHaveText("Trusted");
    await expect(siteView.locator("#evidenceCoverage")).toHaveText("Sufficient");
    await expect(siteView.locator("#evidenceConfidence")).toHaveText("Medium");
    await expect(siteView.locator("#certificateApplication")).toHaveText("Certificate active");
    await expect(siteView.locator("#monitoringStatus")).toHaveText("Retry scheduled");
    await expect(siteView.locator("#siteSafetyStatus")).toHaveText("Not run");
    await expect(siteView.locator("#siteSafetyConfidence")).toHaveText("Not applicable");
    await expect(siteView.locator("#malwareRisk")).not.toHaveText("Checking...");
    await expect(siteView.locator("#phishingRisk")).not.toHaveText("Checking...");
    await expect(siteView.locator("#redirectRisk")).not.toHaveText("Checking...");
    await expect(siteView.locator("#downloadRisk")).not.toHaveText("Checking...");
    await expect(siteView.locator("#scriptRisk")).not.toHaveText("Checking...");
    await expect(siteView.locator("body")).not.toContainText("Checking...");
  } finally {
    await runtime.context.close();
    await rm(runtime.profilePath, { recursive: true, force: true });
  }
});

test("routes a dangerous link through the HIP safety page", async () => {
  const runtime = await launchHipExtension({ useLocalServices: true });
  const page = await runtime.context.newPage();
  const dangerousUrl = "http://127.0.0.1:4175/dangerous-download";
  const safetyUrl = "http://localhost:5123/safety?source=e2e&risk=Dangerous";

  try {
    await runtime.context.route("http://localhost:4175/**", route => route.fulfill({
      status: 200,
      contentType: "text/html",
      body: `<!doctype html><title>Link routing test</title>
        <main><a id="dangerous-link" href="${dangerousUrl}">Download candidate</a></main>`
    }));
    await runtime.context.route("http://localhost:5123/**", route => route.fulfill({
      status: 200,
      contentType: "text/html",
      body: "<!doctype html><title>HIP Safety</title><main>HIP safety interstitial</main>"
    }));
    await runtime.context.route("http://localhost:5099/**", async route => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      const headers = {
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "content-type,x-hip-instance-id,x-hip-device-id,x-hip-device-timestamp,x-hip-device-nonce,x-hip-device-body-sha256,x-hip-device-signature",
        "access-control-allow-methods": "GET,POST,OPTIONS"
      };
      if (request.method() === "OPTIONS") {
        await route.fulfill({ status: 204, headers });
        return;
      }

      let body = {};
      if (pathname === "/api/v1/browser/score-site") {
        body = {
          domain: "localhost",
          finalHipScore: 88,
          status: "Trusted",
          verificationStatus: "Verified",
          identityVerificationStatus: "DomainVerified",
          knownRisks: [],
          explanations: ["HIP found strong trust signals."]
        };
      } else if (pathname === "/api/v1/browser/scan-links") {
        body = {
          results: [{
            url: dangerousUrl,
            score: 4,
            riskLevel: "Dangerous",
            reasons: ["Executable download risk."],
            requiresIcon: true,
            label: "Dangerous",
            safetyPageUrl: safetyUrl
          }]
        };
      } else if (pathname === "/api/v1/site-safety/scan") {
        body = {
          status: "Clean",
          summary: "No elevated structural risks found.",
          confidenceLevel: "High",
          domainTrustScore: 90,
          pageTrustScore: 88,
          contentRiskScore: 10,
          finalHipScore: 88,
          warnings: [],
          providerEvidence: [],
          scannedAtUtc: "2026-07-21T12:00:00Z"
        };
      } else if (pathname === "/api/v1/browser/scan-results") {
        body = { saved: true, domain: "localhost", lastCheckedUtc: "2026-07-21T12:00:00Z" };
      } else if (pathname === "/api/v1/reports/risk-finding") {
        body = { accepted: true };
      }

      await route.fulfill({ status: 200, contentType: "application/json", headers, body: JSON.stringify(body) });
    });

    await page.goto("http://localhost:4175/routing");
    const link = page.locator("#dangerous-link");
    await expect(link).toHaveAttribute("data-hip-safety-bound", "true", { timeout: 20_000 });
    await link.click();
    await expect(page).toHaveURL(safetyUrl, { timeout: 20_000 });
    await expect(page.getByText("HIP safety interstitial")).toBeVisible();
  } finally {
    await runtime.context.close();
    await rm(runtime.profilePath, { recursive: true, force: true });
  }
});
