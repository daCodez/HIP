import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const manifest = JSON.parse(await readFile(new URL("manifest.json", root), "utf8"));
const background = await readFile(new URL("src/background.js", root), "utf8");
const html = await readFile(new URL("src/sidepanel.html", root), "utf8");
const popupHtml = await readFile(new URL("src/popup.html", root), "utf8");
const sidePanelScript = await readFile(new URL("src/sidepanel.js", root), "utf8");

test("manifest opens the persistent side panel from the toolbar", () => {
  assert.equal(manifest.version, "0.1.30");
  assert.ok(manifest.permissions.includes("sidePanel"));
  assert.equal(manifest.side_panel.default_path, "src/sidepanel.html");
  assert.equal("default_popup" in manifest.action, false);
  assert.match(background, /setPanelBehavior\(\{\s*openPanelOnActionClick:\s*true\s*\}\)/);
  assert.match(manifest.content_security_policy.extension_pages, /frame-ancestors 'self'/);
});

test("side panel provides accessible Page, Site, and Settings tabs", () => {
  assert.match(html, /role="tablist"/);
  for (const name of ["Page", "Site", "Settings"]) {
    assert.match(html, new RegExp(`role="tab"[^>]*>${name}<`));
  }
  assert.match(html, /role="tabpanel"/);
  assert.match(html, /<img[^>]+class="brand-shield"[^>]+src="\.\.\/assets\/hip-logo\.png"/);
  assert.match(html, /<button id="startXray"[^>]*>X-ray this page<\/button>/);
  assert.doesNotMatch(html, /class="brand-mark"[^>]*>\s*HIP\s*</);
  assert.doesNotMatch(sidePanelScript, /siteFrame\.src\s*=\s*["']about:blank["']/);
  assert.doesNotMatch(sidePanelScript, /page\.start\.hidden\s*=\s*!supported/);
  assert.match(popupHtml, /<img[^>]+class="brand-shield"[^>]+src="\.\.\/assets\/hip-logo\.png"/);
});
