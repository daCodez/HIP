import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  DEFAULT_HIP_SETTINGS,
  HIP_CONFIG,
  migrateLegacyLocalDefaults,
  normalizeBadgePosition,
  normalizeHipSettings
} from "../src/hipApiClient.js";

const [optionsHtml, optionsScript, rendererSource] = await Promise.all([
  readFile(new URL("../src/options.html", import.meta.url), "utf8"),
  readFile(new URL("../src/options.js", import.meta.url), "utf8"),
  readFile(new URL("../src/xrayRenderer.js", import.meta.url), "utf8")
]);

test("new installs use the production HIP services", () => {
  assert.equal(HIP_CONFIG.apiBaseUrl, "https://api.guardwithhip.com");
  assert.equal(HIP_CONFIG.webBaseUrl, "https://guardwithhip.com");
  assert.equal(DEFAULT_HIP_SETTINGS.apiBaseUrl, HIP_CONFIG.apiBaseUrl);
  assert.equal(DEFAULT_HIP_SETTINGS.webBaseUrl, HIP_CONFIG.webBaseUrl);
});

test("the exact legacy localhost defaults migrate without replacing custom development URLs", () => {
  const migrated = migrateLegacyLocalDefaults({
    hipApiBaseUrl: "http://localhost:5099",
    apiBaseUrl: "http://localhost:5099",
    webBaseUrl: "http://localhost:5123"
  });
  assert.equal(migrated.apiBaseUrl, HIP_CONFIG.apiBaseUrl);
  assert.equal(migrated.webBaseUrl, HIP_CONFIG.webBaseUrl);

  const custom = migrateLegacyLocalDefaults({
    apiBaseUrl: "http://localhost:6001",
    webBaseUrl: "http://localhost:6002"
  });
  assert.equal(custom.apiBaseUrl, "http://localhost:6001");
  assert.equal(custom.webBaseUrl, "http://localhost:6002");
});

test("badge placement is normalized and exposed in the options page", () => {
  for (const position of ["bottom-left", "bottom-right", "top-left", "top-right"]) {
    assert.equal(normalizeBadgePosition(position), position);
    assert.match(optionsHtml, new RegExp(`value="${position}"`));
    assert.match(rendererSource, new RegExp(`launcher\\[data-position="${position}"\\]`));
  }
  assert.equal(normalizeBadgePosition("center"), "bottom-left");
  assert.equal(normalizeHipSettings({ badgePosition: "top-right" }).badgePosition, "top-right");
  assert.match(optionsScript, /badgePosition/);
});
