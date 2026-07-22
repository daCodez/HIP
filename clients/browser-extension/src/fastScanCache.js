const DEFAULT_FRESH_TTL_MS = 5 * 60 * 1000;
const DEFAULT_STALE_TTL_MS = 15 * 60 * 1000;
const DEFAULT_MAX_ENTRIES = 256;

/**
 * Bounded in-memory cache for privacy-safe browser scan keys. Fresh values are
 * returned directly, stale values are returned while one refresh runs, and
 * expired/absent requests are coalesced onto one loader promise.
 */
export class FastScanCache {
  constructor({
    now = () => Date.now(),
    freshTtlMs = DEFAULT_FRESH_TTL_MS,
    staleTtlMs = DEFAULT_STALE_TTL_MS,
    maxEntries = DEFAULT_MAX_ENTRIES
  } = {}) {
    if (freshTtlMs < 0 || staleTtlMs < freshTtlMs || !Number.isInteger(maxEntries) || maxEntries < 1) {
      throw new Error("Fast scan cache configuration is invalid.");
    }
    this.now = now;
    this.freshTtlMs = freshTtlMs;
    this.staleTtlMs = staleTtlMs;
    this.maxEntries = maxEntries;
    this.entries = new Map();
    this.inFlight = new Map();
  }

  async getOrCreate(key, loader) {
    const currentTime = this.now();
    const cached = this.entries.get(key);
    if (cached) {
      const ageMs = Math.max(0, currentTime - cached.createdAt);
      this.touch(key, cached);
      if (ageMs <= this.freshTtlMs) {
        return result(cached.value, "cache", "fresh", ageMs);
      }
      if (ageMs <= this.staleTtlMs) {
        this.refresh(key, loader).catch(() => {});
        return result(cached.value, "cache", "stale-while-revalidate", ageMs);
      }
      this.entries.delete(key);
    }

    const loaded = await this.refresh(key, loader);
    return result(loaded.value, loaded.coalesced ? "coalesced" : "network", "fresh", 0);
  }

  async refresh(key, loader) {
    const pending = this.inFlight.get(key);
    if (pending) {
      return { value: await pending, coalesced: true };
    }

    const promise = Promise.resolve().then(loader);
    this.inFlight.set(key, promise);
    try {
      const value = await promise;
      this.entries.set(key, { value, createdAt: this.now() });
      this.evictOverflow();
      return { value, coalesced: false };
    } finally {
      if (this.inFlight.get(key) === promise) {
        this.inFlight.delete(key);
      }
    }
  }

  touch(key, entry) {
    this.entries.delete(key);
    this.entries.set(key, entry);
  }

  evictOverflow() {
    while (this.entries.size > this.maxEntries) {
      const oldestKey = this.entries.keys().next().value;
      this.entries.delete(oldestKey);
    }
  }
}

/**
 * Coalesces identical writes and remembers successful submissions briefly.
 * Failures are never remembered, so a later user action can retry normally.
 */
export class RecentSubmissionDeduper {
  constructor({ now = () => Date.now(), ttlMs = 30 * 1000, maxEntries = 512 } = {}) {
    if (ttlMs < 0 || !Number.isInteger(maxEntries) || maxEntries < 1) {
      throw new Error("Submission dedupe configuration is invalid.");
    }
    this.now = now;
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.completed = new Map();
    this.inFlight = new Map();
  }

  async run(key, action) {
    this.prune();
    if (this.completed.has(key)) {
      return Object.freeze({ executed: false, duplicateSuppressed: true, value: null });
    }

    const pending = this.inFlight.get(key);
    if (pending) {
      await pending;
      return Object.freeze({ executed: false, duplicateSuppressed: true, value: null });
    }

    const promise = Promise.resolve().then(action);
    this.inFlight.set(key, promise);
    try {
      const value = await promise;
      this.completed.set(key, this.now());
      this.evictOverflow();
      return Object.freeze({ executed: true, duplicateSuppressed: false, value });
    } finally {
      if (this.inFlight.get(key) === promise) {
        this.inFlight.delete(key);
      }
    }
  }

  prune() {
    const cutoff = this.now() - this.ttlMs;
    for (const [key, completedAt] of this.completed) {
      if (completedAt < cutoff) {
        this.completed.delete(key);
      }
    }
  }

  evictOverflow() {
    while (this.completed.size > this.maxEntries) {
      this.completed.delete(this.completed.keys().next().value);
    }
  }
}

/** Bounded LRU storage for the latest per-tab popup projection. */
export class BoundedLruStore {
  constructor(maxEntries = 128) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) {
      throw new Error("Bounded store configuration is invalid.");
    }
    this.maxEntries = maxEntries;
    this.entries = new Map();
  }

  set(key, value) {
    this.entries.delete(key);
    this.entries.set(key, value);
    while (this.entries.size > this.maxEntries) {
      this.entries.delete(this.entries.keys().next().value);
    }
  }

  get(key) {
    const value = this.entries.get(key);
    if (value !== undefined) {
      this.entries.delete(key);
      this.entries.set(key, value);
    }
    return value;
  }
}

/**
 * Creates a non-reversible key from normalized structured inputs. Raw URLs and
 * browsing observations never become Map keys or diagnostic metadata.
 */
export async function privacySafeScanCacheKey(kind, input, subtle = globalThis.crypto?.subtle) {
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(kind) || !subtle) {
    throw new Error("Fast scan cache key configuration is invalid.");
  }
  const canonical = canonicalJson(input);
  const digest = await subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  const hash = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
  return `${kind}:sha256:${hash}`;
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new Error("Fast scan cache key input is invalid.");
}

function result(value, source, freshness, ageMs) {
  return Object.freeze({ value, source, freshness, ageMs });
}
