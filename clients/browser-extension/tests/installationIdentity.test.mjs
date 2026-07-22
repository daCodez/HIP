import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { webcrypto } from "node:crypto";

import {
  generateInstallationKeyMaterial,
  createInstallationRequestProofForIdentity,
  signInstallationBytes
} from "../src/installationIdentity.js";

test("generates a non-exportable P-256 private key and canonical public SPKI", async () => {
  const generated = await generateInstallationKeyMaterial(webcrypto);
  assert.equal(generated.algorithm, "ECDSA-P256-SHA256");
  assert.equal(generated.keyPair.privateKey.extractable, false);
  assert.equal(generated.keyPair.privateKey.algorithm.namedCurve, "P-256");
  assert.match(generated.publicKey, /^[A-Za-z0-9_-]+$/);
  await assert.rejects(
    webcrypto.subtle.exportKey("pkcs8", generated.keyPair.privateKey),
    /not extractable/i
  );
});

test("creates the 64-byte WebCrypto proof format accepted by HIP", async () => {
  const generated = await generateInstallationKeyMaterial(webcrypto);
  const payload = new TextEncoder().encode("HIP device-registration challenge bytes");
  const signingInput = Buffer.from(payload).toString("base64url");
  const signature = await signInstallationBytes(generated.keyPair.privateKey, signingInput, webcrypto);
  const publicKey = await webcrypto.subtle.importKey(
    "spki",
    Buffer.from(generated.publicKey, "base64url"),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );

  assert.equal(Buffer.from(signature, "base64url").length, 64);
  assert.equal(await webcrypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    Buffer.from(signature, "base64url"),
    payload
  ), true);
});

test("creates deterministic canonical request fields with fresh nonce proof", async () => {
  const generated = await generateInstallationKeyMaterial(webcrypto);
  const proof = await createInstallationRequestProofForIdentity(
    { deviceId: "dev_browser_test", privateKey: generated.keyPair.privateKey },
    "post",
    "/api/v1/browser/scan-results",
    { status: "Safe", nested: { score: 90, active: true } },
    {
      cryptoApi: webcrypto,
      now: () => 1_752_969_600_000,
      nonceBytes: new Uint8Array(18).fill(7)
    }
  );

  assert.deepEqual({ ...proof, signature: undefined }, {
    deviceId: "dev_browser_test",
    timestamp: "1752969600",
    nonce: "BwcHBwcHBwcHBwcHBwcHBwcH",
    bodyDigest: "sha256:4f3909aad65b83ebe6ad7379d41e0eabec2b8c508fa6172c2465c9196c1216aa",
    signature: undefined
  });
  assert.equal(Buffer.from(proof.signature, "base64url").length, 64);
});

test("keeps extension private keys out of sync/local storage and messages", async () => {
  const source = await readFile(new URL("../src/installationIdentity.js", import.meta.url), "utf8");
  const background = await readFile(new URL("../src/background.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /chrome\.storage/);
  assert.match(source, /privateKey: keyPair\.privateKey/);
  assert.doesNotMatch(background, /privateKey/);
  assert.doesNotMatch(background, /exportKey\(["']pkcs8/);
});

test("consumer portal bridge falls back to its existing local key flow", async () => {
  const portalModule = await readFile(new URL("../../../src/HIP.Web/wwwroot/js/hip-device-registration.js", import.meta.url), "utf8");
  assert.match(portalModule, /requestExtension\("prepare"/);
  assert.match(portalModule, /generateKey/);
  assert.match(portalModule, /extensionHandlePrefix/);
});
