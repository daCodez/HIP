import { expect, test, chromium } from "@playwright/test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const extensionPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

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
    await expect(panel.locator("#pluginVersion")).toContainText("v0.1.31");
    await expect(panel.getByRole("tab", { name: "Page" })).toHaveAttribute("aria-selected", "true");
    await expect(panel.getByRole("button", { name: "X-ray this page" })).toBeVisible();
    const started = await panel.evaluate(id => chrome.tabs.sendMessage(id, { type: "HIP_XRAY_START" }), tabId);
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

    const state = await panel.evaluate(id => chrome.tabs.sendMessage(id, { type: "HIP_XRAY_GET_STATE", findingOffset: 0, findingLimit: 50 }), tabId);
    const findingId = state.result.findings[0].findingId;
    const selection = await panel.evaluate(({ id, findingId: selected }) => chrome.tabs.sendMessage(id, { type: "HIP_XRAY_SELECT_FINDING", findingId: selected }), { id: tabId, findingId });
    expect(selection.result.status).toBe("selected");
    await expect.poll(() => target.evaluate(() => window.scrollY)).toBeGreaterThan(0);
    await expect(overlay.locator(".marker[data-selected='true']").first()).toBeVisible();

    await panel.evaluate(id => chrome.tabs.sendMessage(id, { type: "HIP_XRAY_SET_MARKERS", visible: false }), tabId);
    await expect(overlay.locator(".marker-layer")).toBeHidden();
    await panel.evaluate(id => chrome.tabs.sendMessage(id, { type: "HIP_XRAY_SET_MARKERS", visible: true }), tabId);

    await panel.screenshot({ path: testInfo.outputPath("side-panel-shell.png"), fullPage: true });
    await target.screenshot({ path: testInfo.outputPath("selected-page-marker.png"), fullPage: false });
    await panel.setViewportSize({ width: 320, height: 700 });
    await panel.screenshot({ path: testInfo.outputPath("narrow-page-panel.png"), fullPage: true });
    expect(consoleErrors).toEqual([]);
  } finally {
    await runtime.context.close();
    await rm(runtime.profilePath, { recursive: true, force: true });
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
