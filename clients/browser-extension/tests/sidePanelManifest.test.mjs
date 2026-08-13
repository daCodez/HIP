import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const manifest = JSON.parse(await readFile(new URL("manifest.json", root), "utf8"));
const background = await readFile(new URL("src/background.js", root), "utf8");
const html = await readFile(new URL("src/sidepanel.html", root), "utf8");
const popupHtml = await readFile(new URL("src/popup.html", root), "utf8");
const popupCss = await readFile(new URL("src/popup.css", root), "utf8");
const siteCss = await readFile(new URL("src/sidepanel-site.css", root), "utf8");
const shellCss = await readFile(new URL("src/sidepanel-shell.css", root), "utf8").catch(() => "");
const sidePanelScript = await readFile(new URL("src/sidepanel.js", root), "utf8");
const contentScript = await readFile(new URL("src/content.js", root), "utf8");

test("manifest opens the persistent side panel from the toolbar", () => {
  assert.equal(manifest.version, "0.1.43");
  assert.ok(manifest.permissions.includes("sidePanel"));
  assert.equal(manifest.side_panel.default_path, "src/sidepanel.html");
  assert.equal("default_popup" in manifest.action, false);
  assert.ok(manifest.host_permissions.includes("https://*/*"));
  assert.equal(manifest.optional_host_permissions?.includes("https://*/*") ?? false, false);
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
  assert.ok(html.indexOf('class="panel-header"') < html.indexOf('class="tabs"'));
  assert.match(html, /<h1>Website Trust<\/h1>/);
  assert.match(html, /id="pluginVersion"/);
  assert.match(html, /href="sidepanel-shell\.css"/);
  assert.match(shellCss, /\.panel-header\s*\{[^}]*position:\s*sticky[^}]*top:\s*0/s);
  assert.match(shellCss, /\.tabs\s*\{[^}]*top:\s*97px/s);
  assert.match(sidePanelScript, /className\s*=\s*"finding-dot"/);
  assert.match(sidePanelScript, /className\s*=\s*"score-impact"/);
  assert.match(sidePanelScript, /onActivated\.addListener\(\(\{\s*tabId\s*\}\)\s*=>\s*refreshActiveTab\(tabId\)\)/);
  assert.match(sidePanelScript, /chrome\.tabs\.query\(\{\s*active:\s*true,\s*currentWindow:\s*true\s*\}\)/);
  assert.match(sidePanelScript, /changeInfo\.status\s*===\s*"complete"/);
  assert.match(sidePanelScript, /chrome\.scripting\.executeScript/);
  assert.match(sidePanelScript, /"src\/content\.js"/);
  assert.match(sidePanelScript, /await injectContentScanner\(tabId\)/);
  assert.match(contentScript, /__hipContentScriptLoaded\s*===\s*contentScriptVersion/);
  assert.match(sidePanelScript, /chrome\.runtime\.getManifest\(\)\.version/);
  assert.match(sidePanelScript, /syncSiteFrame\(tab, forceSiteRefresh\)/);
  assert.ok(sidePanelScript.indexOf("syncSiteFrame(tab, forceSiteRefresh)") < sidePanelScript.indexOf("await coordinator.activate(tab || {})"));
  assert.match(sidePanelScript, /&v=\$\{version\}/);
  assert.match(html, /<button id="startXray"[^>]*>X-ray this page<\/button>/);
  assert.doesNotMatch(html, /class="brand-mark"[^>]*>\s*HIP\s*</);
  assert.doesNotMatch(sidePanelScript, /siteFrame\.src\s*=\s*["']about:blank["']/);
  assert.doesNotMatch(sidePanelScript, /page\.start\.hidden\s*=\s*!supported/);
  assert.match(popupHtml, /<img[^>]+class="brand-shield"[^>]+src="\.\.\/assets\/hip-logo\.png"/);
  assert.match(popupCss, /body\.embedded\s+\.popup-header\s*\{[^}]*display:\s*none/);
  assert.match(popupHtml, /href="sidepanel-site\.css"/);
  assert.match(siteCss, /body\.embedded \.score-panel,[\s\S]*border-radius:\s*14px/);
  assert.match(siteCss, /body\.embedded\s+\.reasons-panel li::before/);
  assert.match(siteCss, /body\.embedded\s+\.button-row button/);
});
