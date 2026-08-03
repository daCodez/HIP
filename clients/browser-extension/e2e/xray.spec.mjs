import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, expect, test } from "@playwright/test";

const extensionPath = fileURLToPath(new URL("../", import.meta.url));
const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));

async function launchExtension() {
  const profilePath = await mkdtemp(path.join(tmpdir(), "hip-xray-e2e-"));
  const context = await chromium.launchPersistentContext(profilePath, {
    headless: false,
    executablePath: process.env.HIP_CHROMIUM_PATH || undefined,
    args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`, "--no-first-run", "--disable-default-apps"]
  });
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker", { timeout: 15_000 });
  return { context, extensionId: new URL(worker.url()).host, profilePath };
}

/** Reopens the navigator when collision handling collapsed it to reveal a target. */
async function ensureResultsOpen(page) {
  const pill = page.getByRole("button", { name: /Open Page X-ray results/ });
  if (await pill.isVisible().catch(() => false)) await pill.click();
}

test("X-ray is explicit, interactive, privacy-safe, and fully removable", async () => {
  const runtime = await launchExtension();
  const page = await runtime.context.newPage();
  const privateValue = "private-autofill-sentinel";

  try {
    await runtime.context.route("http://localhost:4180/**", route => route.fulfill({
      status: 200,
      contentType: route.request().url().endsWith(".js") ? "application/javascript" : "text/html",
      headers: { "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'none'; frame-src 'none'" },
      body: route.request().url().endsWith(".js") ? "globalThis.lateScriptLoaded = true; document.querySelector('#host-button')?.addEventListener('click', () => document.querySelector('#host-output').textContent = '1');" : `<!doctype html>
        <title>X-ray test</title>
        <main>
          <h1>Account check</h1>
          <div aria-hidden="true">${"<br>".repeat(100)}</div>
          <form id="login" action="http://accounts.example/session" autocomplete="on">
            <label>Password <input id="password" name="password" type="password" value="${privateValue}" autocomplete="current-password"></label>
          </form>
          <div id="editor" contenteditable="true">editable-sentinel</div>
          <button id="host-button" type="button">Continue</button><output id="host-output">0</output>
          <a id="misleading" href="https://destination.example/">https://accounts.example/sign-in</a>
          <script src="/fixture.js"></script>
        </main>`
    }));
    await runtime.context.route("http://localhost:5099/**", route => route.fulfill({ status: 503, contentType: "application/json", body: "{}" }));
    await page.goto("http://localhost:4180/account");
    await expect(page.getByRole("button", { name: "X-ray this page" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Page X-ray results" })).toHaveCount(0);
    await page.locator("#password").focus();
    const before = await page.evaluate(() => ({
      form: document.querySelector("#login").getAttributeNames().map(name => [name, document.querySelector("#login").getAttribute(name)]),
      input: document.querySelector("#password").getAttributeNames().map(name => [name, document.querySelector("#password").getAttribute(name)]),
      activeId: document.activeElement?.id,
      selectionStart: document.querySelector("#password").selectionStart,
      selectionEnd: document.querySelector("#password").selectionEnd
    }));

    const worker = runtime.context.serviceWorkers()[0];
    const tabId = await worker.evaluate(async targetUrl => (await chrome.tabs.query({ url: targetUrl }))[0].id, page.url());
    const popup = await runtime.context.newPage();
    await popup.goto(`chrome-extension://${runtime.extensionId}/src/popup.html`);
    const response = await popup.evaluate(id => chrome.tabs.sendMessage(id, { type: "HIP_XRAY_START" }), tabId);
    expect(response.ok).toBe(true);
    await expect(page.locator("[data-hip-xray-owned='true']")).toHaveCount(1);
    await expect(page.getByRole("heading", { name: "Page X-ray results" })).toBeVisible();
    await expect(page.getByText("Reading page structure", { exact: true })).toBeVisible();
    await expect(page.getByText("Applying local HIP rules", { exact: true })).toBeVisible();
    await expect(page.getByText("HIP · PAGE X-RAY RESULTS", { exact: true })).toBeVisible({ timeout: 5_000 });
    await expect(page.locator("[data-hip-xray-owned='true']").locator(".result-score")).toBeVisible();
    await expect(page.locator("[data-hip-xray-owned='true']").locator(".result-progress-fill")).toBeVisible();
    await expect(page.getByText("Every score comes with its reasons. Nothing is hidden.", { exact: true })).toBeVisible();
    await expect(page.getByText("Full domain scan unavailable.", { exact: false })).toBeVisible();
    await expect(page.getByRole("button", { name: /Locate finding .*Password form is not fully encrypted/ })).toBeVisible();
    expect(await page.locator("form [data-hip-xray-owned='true']").count()).toBe(0);

    const afterOpen = await page.evaluate(() => ({
      form: document.querySelector("#login").getAttributeNames().map(name => [name, document.querySelector("#login").getAttribute(name)]),
      input: document.querySelector("#password").getAttributeNames().map(name => [name, document.querySelector("#password").getAttribute(name)]),
      activeId: document.activeElement?.id,
      selectionStart: document.querySelector("#password").selectionStart,
      selectionEnd: document.querySelector("#password").selectionEnd,
      privateValue: document.querySelector("#password").value,
      markerPointerEvents: getComputedStyle(document.querySelector("[data-hip-xray-owned='true']").shadowRoot.querySelector(".marker-layer")).pointerEvents
    }));
    expect(afterOpen).toEqual({ ...before, privateValue, markerPointerEvents: "none" });
    await page.locator("#host-button").click();
    await expect(page.locator("#host-output")).toHaveText("1");
    await expect(page.locator("#editor")).toHaveText("editable-sentinel");

    const linkage = await page.evaluate(() => {
      const root = document.querySelector("[data-hip-xray-owned='true']").shadowRoot;
      const rows = [...root.querySelectorAll(".finding-row[data-finding-id]")].map(item => item.dataset.findingId);
      const markers = [...root.querySelectorAll(".marker[data-finding-id]")].map(item => item.dataset.findingId);
      return {
        linked: rows.every(id => markers.includes(id)),
        markerCount: markers.length,
        markerLayerPointer: getComputedStyle(root.querySelector(".marker-layer")).pointerEvents,
        markerFramePointer: getComputedStyle(root.querySelector(".marker-frame")).pointerEvents,
        markerPointer: getComputedStyle(root.querySelector(".marker")).pointerEvents,
        launcherLeft: getComputedStyle(root.querySelector(".launcher")).left,
        launcherRight: getComputedStyle(root.querySelector(".launcher")).right
      };
    });
    expect(linkage.linked).toBe(true);
    expect(linkage.markerCount).toBeGreaterThan(0);
    expect(linkage).toMatchObject({ markerLayerPointer: "none", markerFramePointer: "none", markerPointer: "auto", launcherLeft: "24px", launcherRight: "auto" });

    await page.getByRole("button", { name: "Collapse Page X-ray results" }).click();
    await expect(page.getByRole("button", { name: /Open Page X-ray results/ })).toBeVisible();
    await page.getByRole("button", { name: /Open finding/ }).first().click();
    await expect(page.getByRole("heading", { name: "Page X-ray results" })).toBeVisible();
    await expect(page.locator("[data-hip-xray-owned='true']").locator(".finding-item[data-selected='true'] .finding-details")).toBeVisible();

    await page.getByRole("button", { name: "Show technical explanations" }).click();
    await expect(page.getByText("The page or the form's effective submission action uses HTTP", { exact: false })).toBeVisible();
    await page.getByRole("button", { name: /Locate finding .*Password form is not fully encrypted/ }).click();
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
    await expect(page.locator("[data-hip-xray-owned='true']").locator(".highlight")).toBeVisible();
    await page.evaluate(() => window.dispatchEvent(new Event("scroll")));
    await expect(page.locator("[data-hip-xray-owned='true']").locator(".highlight")).toBeVisible();

    await page.evaluate(() => {
      const original = document.querySelector("#login");
      original.replaceWith(original.cloneNode(true));
    });
    await page.waitForTimeout(700);
    await ensureResultsOpen(page);
    await page.getByRole("button", { name: /Locate finding .*Password form is not fully encrypted/ }).click();
    await ensureResultsOpen(page);
    await expect(page.locator("[data-hip-xray-owned='true'] .finding-item[data-selected='true'] .target-state")).toHaveText("Linked page element available");

    await page.evaluate(() => {
      const target = document.querySelector("#misleading");
      globalThis.savedXrayTarget = target.cloneNode(true);
      globalThis.savedXrayParent = target.parentElement;
      target.remove();
    });
    await page.waitForTimeout(700);
    await ensureResultsOpen(page);
    await page.getByRole("button", { name: /Locate finding .*Link text and destination differ/ }).click();
    await ensureResultsOpen(page);
    await expect(page.locator("[data-hip-xray-owned='true'] .finding-item[data-selected='true'] .target-state")).toHaveText("Element no longer available");
    await page.evaluate(() => globalThis.savedXrayParent.append(globalThis.savedXrayTarget));
    await page.waitForTimeout(700);
    await page.getByRole("button", { name: /Locate finding .*Link text and destination differ/ }).click();
    await ensureResultsOpen(page);
    await expect(page.locator("[data-hip-xray-owned='true'] .finding-item[data-selected='true'] .target-state")).toHaveText("Linked page element available");

    const markerCountBeforeRescan = await page.locator("[data-hip-xray-owned='true']").locator(".marker").count();
    await ensureResultsOpen(page);
    await page.getByRole("button", { name: "Rescan the current page" }).click();
    await expect(page.locator("[data-hip-xray-owned='true'] .finding-count")).toContainText(/finding/);
    await expect(page.getByText("HIP · PAGE X-RAY RESULTS", { exact: true })).toBeVisible({ timeout: 5_000 });
    expect(await page.locator("[data-hip-xray-owned='true']").locator(".marker").count()).toBe(markerCountBeforeRescan);

    await page.evaluate(() => {
      const script = document.createElement("script");
      script.src = "/late.js";
      document.head.append(script);
    });
    await expect(page.getByText("New script added after X-ray started", { exact: false })).toBeVisible({ timeout: 5_000 });
    await page.getByRole("button", { name: "Hide numbered page markers" }).click();
    await expect(page.locator("[data-hip-xray-owned='true']").locator(".marker:visible")).toHaveCount(0);
    await page.getByRole("button", { name: "Show numbered page markers" }).click();
    await expect(page.locator("[data-hip-xray-owned='true']").locator(".marker:visible").first()).toBeVisible();

    await page.evaluate(() => history.pushState({}, "", "/spa-route"));
    await expect(page.getByRole("button", { name: "X-ray this page" })).toBeVisible({ timeout: 2_000 });
    await expect(page.locator("[data-hip-xray-owned='true']").locator(".marker")).toHaveCount(0);
    await page.getByRole("button", { name: "X-ray this page" }).click();
    await expect(page.getByText("HIP · PAGE X-RAY RESULTS", { exact: true })).toBeVisible({ timeout: 5_000 });
    await page.getByRole("button", { name: "Exit X-ray" }).click();
    await expect(page.getByRole("button", { name: "X-ray this page" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Page X-ray results" })).toHaveCount(0);
    expect(await page.locator("#password").inputValue()).toBe(privateValue);
  } finally {
    await runtime.context.close();
    await rm(runtime.profilePath, { recursive: true, force: true });
  }
});
