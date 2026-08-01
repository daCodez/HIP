import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

import { BoundedLruStore, FastScanCache, privacySafeScanCacheKey, RecentSubmissionDeduper } from "../src/fastScanCache.js";

test("returns explicit network, fresh-cache, and stale-while-revalidate metadata", async () => {
  let now = 0;
  let loads = 0;
  const cache = new FastScanCache({ now: () => now, freshTtlMs: 100, staleTtlMs: 300 });

  const first = await cache.getOrCreate("key", async () => ++loads);
  assert.deepEqual(first, { value: 1, source: "network", freshness: "fresh", ageMs: 0 });

  now = 50;
  const fresh = await cache.getOrCreate("key", async () => ++loads);
  assert.deepEqual(fresh, { value: 1, source: "cache", freshness: "fresh", ageMs: 50 });

  now = 150;
  const stale = await cache.getOrCreate("key", async () => ++loads);
  assert.deepEqual(stale, { value: 1, source: "cache", freshness: "stale-while-revalidate", ageMs: 150 });
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(loads, 2);
});

test("coalesces identical misses onto one loader", async () => {
  let resolveLoad;
  let loads = 0;
  const cache = new FastScanCache();
  const loader = () => {
    loads += 1;
    return new Promise(resolve => { resolveLoad = resolve; });
  };

  const first = cache.getOrCreate("same", loader);
  const second = cache.getOrCreate("same", loader);
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(loads, 1);
  resolveLoad({ status: "Safe" });

  const [firstResult, secondResult] = await Promise.all([first, second]);
  assert.equal(firstResult.source, "network");
  assert.equal(secondResult.source, "coalesced");
  assert.deepEqual(secondResult.value, { status: "Safe" });
});

test("expired entries reload and failures do not poison later requests", async () => {
  let now = 0;
  let loads = 0;
  const cache = new FastScanCache({ now: () => now, freshTtlMs: 10, staleTtlMs: 20 });
  await cache.getOrCreate("key", async () => ++loads);
  now = 25;

  await assert.rejects(() => cache.getOrCreate("key", async () => {
    loads += 1;
    throw new Error("temporary failure");
  }), /temporary failure/);

  const recovered = await cache.getOrCreate("key", async () => ++loads);
  assert.equal(recovered.value, 3);
  assert.equal(recovered.source, "network");
});

test("evicts least-recently-used entries deterministically", async () => {
  const cache = new FastScanCache({ maxEntries: 2 });
  await cache.getOrCreate("a", async () => "a1");
  await cache.getOrCreate("b", async () => "b1");
  await cache.getOrCreate("a", async () => "a2");
  await cache.getOrCreate("c", async () => "c1");

  const reloaded = await cache.getOrCreate("b", async () => "b2");
  assert.equal(reloaded.value, "b2");
  assert.equal(reloaded.source, "network");
});

test("hashes canonical inputs so raw URLs never become cache keys", async () => {
  const first = await privacySafeScanCacheKey("site-safety", {
    url: "https://example.com/private?token=secret",
    signals: { count: 1, safe: true }
  }, webcrypto.subtle);
  const reordered = await privacySafeScanCacheKey("site-safety", {
    signals: { safe: true, count: 1 },
    url: "https://example.com/private?token=secret"
  }, webcrypto.subtle);

  assert.equal(first, reordered);
  assert.match(first, /^site-safety:sha256:[a-f0-9]{64}$/);
  assert.equal(first.includes("example.com"), false);
  assert.equal(first.includes("secret"), false);
});

test("different observations and service settings remain isolated", async () => {
  const base = { apiBaseUrl: "https://hip.example", request: { url: "https://target.example", count: 1 } };
  const observationChanged = { apiBaseUrl: "https://hip.example", request: { url: "https://target.example", count: 2 } };
  const serviceChanged = { apiBaseUrl: "https://other-hip.example", request: { url: "https://target.example", count: 1 } };

  assert.notEqual(
    await privacySafeScanCacheKey("score", base, webcrypto.subtle),
    await privacySafeScanCacheKey("score", observationChanged, webcrypto.subtle));
  assert.notEqual(
    await privacySafeScanCacheKey("score", base, webcrypto.subtle),
    await privacySafeScanCacheKey("score", serviceChanged, webcrypto.subtle));
});

test("coalesces writes and suppresses recent successful duplicates", async () => {
  let now = 0;
  let resolveWrite;
  let writes = 0;
  const deduper = new RecentSubmissionDeduper({ now: () => now, ttlMs: 100 });
  const action = () => {
    writes += 1;
    return new Promise(resolve => { resolveWrite = resolve; });
  };

  const first = deduper.run("submission", action);
  const simultaneous = deduper.run("submission", action);
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(writes, 1);
  resolveWrite({ saved: true });

  assert.deepEqual(await first, { executed: true, duplicateSuppressed: false, value: { saved: true } });
  assert.deepEqual(await simultaneous, { executed: false, duplicateSuppressed: true, value: null });
  assert.equal((await deduper.run("submission", action)).duplicateSuppressed, true);
  assert.equal(writes, 1);
});

test("allows retry after expiry and immediately after failed writes", async () => {
  let now = 0;
  let attempts = 0;
  const deduper = new RecentSubmissionDeduper({ now: () => now, ttlMs: 10 });

  await assert.rejects(() => deduper.run("failed", async () => {
    attempts += 1;
    throw new Error("write failed");
  }), /write failed/);
  const retry = await deduper.run("failed", async () => ++attempts);
  assert.equal(retry.executed, true);

  await deduper.run("expiring", async () => ++attempts);
  now = 11;
  const expired = await deduper.run("expiring", async () => ++attempts);
  assert.equal(expired.executed, true);
});

test("bounds remembered submission history", async () => {
  const deduper = new RecentSubmissionDeduper({ maxEntries: 2 });
  await deduper.run("a", async () => "a");
  await deduper.run("b", async () => "b");
  await deduper.run("c", async () => "c");

  const oldest = await deduper.run("a", async () => "a-new");
  assert.equal(oldest.executed, true);
});

test("bounds and deterministically evicts per-tab scan summaries", () => {
  const store = new BoundedLruStore(2);
  store.set(1, "first");
  store.set(2, "second");
  assert.equal(store.get(1), "first");
  store.set(3, "third");

  assert.equal(store.get(2), undefined);
  assert.equal(store.get(1), "first");
  assert.equal(store.get(3), "third");
});
