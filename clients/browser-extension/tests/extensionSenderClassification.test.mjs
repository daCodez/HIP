import assert from "node:assert/strict";
import test from "node:test";

import { validateBackgroundMessage } from "../src/extensionMessageContracts.js";

test("classifies an extension page opened in a tab as an extension sender", () => {
  const runtimeId = "abcdefghijklmnopabcdefghijklmnop";
  const sender = {
    id: runtimeId,
    url: `chrome-extension://${runtimeId}/src/popup.html`,
    tab: {
      id: 17,
      url: `chrome-extension://${runtimeId}/src/popup.html`
    }
  };

  const version = validateBackgroundMessage({ type: "HIP_GET_PLUGIN_VERSION" }, sender, runtimeId);
  const contentOnly = validateBackgroundMessage({ type: "HIP_GET_SETTINGS" }, sender, runtimeId);

  assert.equal(version.ok, true);
  assert.equal(version.senderKind, "extension");
  assert.equal(contentOnly.ok, false);
});
