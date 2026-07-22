import { defineConfig } from "@playwright/test";

/**
 * Keeps Manifest V3 browser checks serial and preserves diagnostics only when a
 * test fails. Each test owns its isolated Chromium profile.
 */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 10_000 },
  reporter: "line",
  use: {
    screenshot: "only-on-failure",
    trace: "retain-on-failure"
  }
});
