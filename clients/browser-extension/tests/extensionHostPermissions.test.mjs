import assert from "node:assert/strict";
import test from "node:test";

import {
  ensureHipHostPermissions,
  hipHostPermissionPattern
} from "../src/extensionHostPermissions.js";

test("builds an exact HTTPS host permission without retaining paths or ports", () => {
  assert.equal(
    hipHostPermissionPattern("https://hip.example:8443/api/v1?token=private"),
    "https://hip.example/*"
  );
});

test("allows HTTP only for loopback development services", () => {
  assert.equal(hipHostPermissionPattern("http://localhost:5099"), "http://localhost/*");
  assert.equal(hipHostPermissionPattern("http://127.0.0.1:5123"), "http://127.0.0.1/*");
  assert.throws(
    () => hipHostPermissionPattern("http://192.168.1.20:5099"),
    /must use HTTPS/
  );
});

test("rejects invalid schemes and embedded credentials", () => {
  assert.throws(() => hipHostPermissionPattern("javascript:alert(1)"), /must use HTTPS/);
  assert.throws(
    () => hipHostPermissionPattern("https://user:secret@hip.example"),
    /cannot contain credentials/
  );
});

test("requests only the unique configured HIP origins", async () => {
  const calls = [];
  const permissionsApi = {
    async contains(request) {
      calls.push(["contains", request]);
      return false;
    },
    async request(request) {
      calls.push(["request", request]);
      return true;
    }
  };

  const granted = await ensureHipHostPermissions([
    "https://hip.example:8443/api",
    "https://hip.example/ui"
  ], permissionsApi);

  assert.equal(granted, true);
  assert.deepEqual(calls, [
    ["contains", { origins: ["https://hip.example/*"] }],
    ["request", { origins: ["https://hip.example/*"] }]
  ]);
});

test("does not prompt again when the selected hosts are already granted", async () => {
  let requestCalled = false;
  const permissionsApi = {
    async contains() {
      return true;
    },
    async request() {
      requestCalled = true;
      return false;
    }
  };

  assert.equal(await ensureHipHostPermissions(["https://hip.example"], permissionsApi), true);
  assert.equal(requestCalled, false);
});
