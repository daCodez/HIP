import { expect, test, chromium } from "@playwright/test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const extensionPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));

async function launchExtension() {
  const profilePath = await mkdtemp(path.join(tmpdir(), "hip-side-panel-e2e-"));
  const context = await chromium.launchPersistentContext(profilePath, {
    headless: false,
    executablePath: process.env.HIP_CHROMIUM_PATH || undefined,
    args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`, "--no-first-run", "--disable-default-apps"]
  });
  let worker = context.serviceWorkers()[0];
  if (!worker) worker = await context.waitForEvent("serviceworker");
  return { context, worker, extensionId: new URL(worker.url()).host, profilePath };
}

async function openPanelDocument(runtime) {
  const panel = await runtime.context.newPage();
  await panel.goto(`chrome-extension://${runtime.extensionId}/src/sidepanel.html`);
  return panel;
}

/**
 * Bounds extension messaging so a lost MV3 response fails at the responsible
 * phase instead of consuming the complete Playwright test timeout.
 */
async function sendTabMessage(panel, tabId, message, phase) {
  return await Promise.race([
    panel.evaluate(({ id, payload }) => chrome.tabs.sendMessage(id, payload), { id: tabId, payload: message }),
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${phase} did not receive an extension response within 10 seconds.`)), 10_000))
  ]);
}

/** Closes an isolated extension profile without allowing Chromium cleanup to hide the tested result. */
async function closeRuntime(runtime) {
  await Promise.race([
    runtime.context.close(),
    new Promise(resolve => setTimeout(resolve, 10_000))
  ]);
  await rm(runtime.profilePath, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}

const fixture = `<!doctype html><html><body style="min-height:2200px">
  <button id="host-button" type="button">Host action</button><output id="host-output">0</output>
  <div style="height:1100px"></div>
  <form id="login" action="http://unsafe.example/login"><label>Password<input id="password" type="password" value="sentinel-secret" autocomplete="current-password"></label></form>
  <a id="external" href="https://different.example">https://safe.example</a>
  <div id="editor" contenteditable="true">editable-sentinel</div>
  <script>document.querySelector('#host-button').onclick=()=>document.querySelector('#host-output').value='1';</script>
</body></html>`;

test("persistent Page panel links findings to pointer-transparent page markers", async ({}, testInfo) => {
  const runtime = await launchExtension();
  try {
    const target = await runtime.context.newPage();
    await target.route("https://fixture.example/**", route => route.fulfill({ contentType: "text/html", body: fixture }));
    await target.goto("https://fixture.example/start");
    await target.bringToFront();
    const tabId = await runtime.worker.evaluate(async () => (await chrome.tabs.query({ active: true }))[0]?.id ?? null);
    expect(tabId).not.toBeNull();
    const panel = await openPanelDocument(runtime);
    const consoleErrors = [];
    panel.on("pageerror", error => consoleErrors.push(error.message));
    await target.locator("#password").fill("do-not-read-this");

    await expect(panel.locator("#activeDomain")).toHaveText("Unsupported browser page");
    await expect(panel.locator(".panel-header h1")).toHaveText("Website Trust");
    await expect(panel.locator("#pluginVersion")).toContainText(`v${manifest.version}`);
    const headerBox = await panel.locator(".panel-header").boundingBox();
    const tabsBox = await panel.locator(".tabs").boundingBox();
    expect(headerBox.y).toBeLessThan(tabsBox.y);
    await expect(panel.getByRole("tab", { name: "Page" })).toHaveAttribute("aria-selected", "true");
    await expect(panel.getByRole("button", { name: "X-ray this page" })).toBeVisible();
    const started = await sendTabMessage(panel, tabId, { type: "HIP_XRAY_START" }, "Starting Page X-ray");
    expect(started.ok).toBe(true);
    expect(started.result.findingCount).toBeGreaterThan(0);
    await expect.poll(() => target.evaluate(() => document.querySelectorAll("[data-hip-xray-owned='true']").length)).toBe(1);
    const overlay = target.locator("[data-hip-xray-owned='true']:not(.theatre)");
    await expect(overlay.locator(".marker").first()).toBeAttached();

    const coexistence = await target.evaluate(() => {
      const root = document.querySelector("[data-hip-xray-owned='true']").shadowRoot;
      return {
        password: document.querySelector("#password").value,
        editable: document.querySelector("#editor").textContent,
        layerPointer: getComputedStyle(root.querySelector(".marker-layer")).pointerEvents,
        framePointer: getComputedStyle(root.querySelector(".marker-frame")).pointerEvents,
        markerPointer: getComputedStyle(root.querySelector(".marker")).pointerEvents,
        hudCount: root.querySelectorAll(".hud,.launcher,.results-pill").length
      };
    });
    expect(coexistence).toEqual({ password: "do-not-read-this", editable: "editable-sentinel", layerPointer: "none", framePointer: "none", markerPointer: "auto", hudCount: 0 });
    await target.locator("#host-button").click();
    await expect(target.locator("#host-output")).toHaveText("1");

    const state = await sendTabMessage(panel, tabId, { type: "HIP_XRAY_GET_STATE", findingOffset: 0, findingLimit: 50 }, "Reading Page X-ray state");
    const findingId = state.result.findings[0].findingId;
    const selection = await sendTabMessage(panel, tabId, { type: "HIP_XRAY_SELECT_FINDING", findingId }, "Selecting a Page X-ray finding");
    expect(selection.result.status).toBe("selected");
    await expect.poll(() => target.evaluate(() => window.scrollY)).toBeGreaterThan(0);
    await expect(overlay.locator(".marker[data-selected='true']").first()).toBeVisible();

    await sendTabMessage(panel, tabId, { type: "HIP_XRAY_SET_MARKERS", visible: false }, "Hiding Page X-ray markers");
    await expect(overlay.locator(".marker-layer")).toBeHidden();
    await sendTabMessage(panel, tabId, { type: "HIP_XRAY_SET_MARKERS", visible: true }, "Showing Page X-ray markers");

    await panel.screenshot({ path: testInfo.outputPath("side-panel-shell.png"), fullPage: true });
    await target.screenshot({ path: testInfo.outputPath("selected-page-marker.png"), fullPage: false });
    await panel.setViewportSize({ width: 320, height: 700 });
    await panel.screenshot({ path: testInfo.outputPath("narrow-page-panel.png"), fullPage: true });
    expect(consoleErrors).toEqual([]);
  } finally {
    await closeRuntime(runtime);
  }
});

test("side-panel tabs are keyboard accessible in a narrow reduced-motion view", async ({}, testInfo) => {
  const runtime = await launchExtension();
  try {
    const first = await runtime.context.newPage();
    await first.route("https://first.example/**", route => route.fulfill({ contentType: "text/html", body: fixture }));
    await first.goto("https://first.example/one");
    const panel = await openPanelDocument(runtime);
    await expect(panel.locator("#activeDomain")).toHaveText("Unsupported browser page");

    await panel.getByRole("tab", { name: "Page" }).focus();
    await panel.keyboard.press("ArrowRight");
    await expect(panel.getByRole("tab", { name: "Site" })).toHaveAttribute("aria-selected", "true");
    await expect(panel.frameLocator("#siteFrame").locator("body")).toBeVisible();
    await expect(panel.frameLocator("#siteFrame").locator("#domain")).not.toBeEmpty();
    await expect(panel.frameLocator("#siteFrame").locator(".popup-header")).toBeHidden();
    await expect(panel.locator(".panel-header")).toBeVisible();
    await panel.screenshot({ path: testInfo.outputPath("site-tab.png"), fullPage: false });
    await panel.keyboard.press("ArrowRight");
    await expect(panel.getByRole("tab", { name: "Settings" })).toHaveAttribute("aria-selected", "true");
    await expect(panel.locator("#settingsFrame")).toBeVisible();
    await expect(panel.frameLocator("#settingsFrame").locator("#settingsForm")).toBeVisible();
    await expect(panel.locator(".panel-header")).toBeVisible();
    await expect.poll(async () => (await panel.locator(".panel-header").boundingBox())?.y ?? 999).toBeLessThan(80);
    await panel.screenshot({ path: testInfo.outputPath("settings-tab.png"), fullPage: false });
    await panel.keyboard.press("Home");
    await expect(panel.getByRole("tab", { name: "Page" })).toHaveAttribute("aria-selected", "true");

    await panel.emulateMedia({ reducedMotion: "reduce" });
    await panel.setViewportSize({ width: 320, height: 700 });
    await panel.screenshot({ path: testInfo.outputPath("reduced-motion-empty-state.png"), fullPage: true });
  } finally {
    await runtime.context.close();
    await rm(runtime.profilePath, { recursive: true, force: true });
  }
});

test("side panel follows the exact selected tab across different host permissions", async () => {
  const runtime = await launchExtension();
  try {
    const guardPage = await runtime.context.newPage();
    await guardPage.route("https://guardwithhip.com/**", route => route.fulfill({ contentType: "text/html", body: fixture }));
    await guardPage.goto("https://guardwithhip.com/hip-tab-sync-test");

    const zeroPage = await runtime.context.newPage();
    await zeroPage.route("https://zerotoherobudgeting.com/**", route => route.fulfill({ contentType: "text/html", body: fixture }));
    await zeroPage.goto("https://zerotoherobudgeting.com/hip-tab-sync-test");

    const panel = await openPanelDocument(runtime);
    await guardPage.bringToFront();
    const guardTabId = await runtime.worker.evaluate(async () => (await chrome.tabs.query({ active: true }))[0]?.id ?? null);
    const guardState = await panel.evaluate(id => chrome.tabs.sendMessage(id, { type: "HIP_XRAY_GET_STATE", inventoryOffset: 0, inventoryLimit: 1, findingOffset: 0, findingLimit: 1 }), guardTabId);
    expect(guardState.ok).toBe(true);
    expect(guardState.result.pageHost).toBe("guardwithhip.com");
    await expect(panel.locator("#activeDomain")).toHaveText("guardwithhip.com");

    await zeroPage.bringToFront();
    await expect(panel.locator("#activeDomain")).toHaveText("zerotoherobudgeting.com");
    await expect(panel.getByRole("button", { name: "X-ray this page" })).toBeEnabled();

    await guardPage.bringToFront();
    await expect(panel.locator("#activeDomain")).toHaveText("guardwithhip.com");
  } finally {
    await runtime.context.close();
    await rm(runtime.profilePath, { recursive: true, force: true });
  }
});
