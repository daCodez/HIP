const databaseName = "hip-extension-installation-v1";
const storeName = "installation-keys";
const algorithm = "ECDSA-P256-SHA256";

/** Generates a non-exportable private key and durably stages it before returning. */
export async function prepareInstallationKey() {
  const generated = await generateInstallationKeyMaterial();
  const keyPair = generated.keyPair;
  const publicKey = generated.publicKey;
  const handle = `pending:${globalThis.crypto.randomUUID()}`;
  await putRecord({
    keyId: handle,
    deviceId: null,
    algorithm,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    state: "prepared",
    createdAtUtc: new Date().toISOString()
  });
  return { handle, publicKey, algorithm };
}

export async function generateInstallationKeyMaterial(cryptoApi = globalThis.crypto) {
  const keyPair = await cryptoApi.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"]);
  const publicKey = await cryptoApi.subtle.exportKey("spki", keyPair.publicKey);
  return { keyPair, publicKey: base64UrlEncode(new Uint8Array(publicKey)), algorithm };
}

/** Atomically moves a prepared key onto the opaque device identifier issued by HIP. */
export async function stageInstallationKey(handle, deviceId) {
  assertOpaqueId(handle, "pending:");
  assertOpaqueId(deviceId, "dev_");
  const database = await openDatabase();
  try {
    const transaction = database.transaction(storeName, "readwrite");
    const store = transaction.objectStore(storeName);
    const prepared = await requestPromise(store.get(handle));
    if (!prepared || prepared.state !== "prepared" || !prepared.privateKey) {
      throw new Error("The prepared HIP extension key is unavailable.");
    }
    store.put({ ...prepared, keyId: deviceId, deviceId, state: "pending" });
    store.delete(handle);
    await transactionPromise(transaction);
  } finally {
    database.close();
  }
}

export async function signInstallationChallenge(deviceId, signingInput) {
  const stored = await getRecord(deviceId);
  if (!stored || stored.state !== "pending" || !stored.privateKey) {
    throw new Error("The staged HIP extension key is unavailable.");
  }
  return signInstallationBytes(stored.privateKey, signingInput);
}

export async function signInstallationBytes(privateKey, signingInput, cryptoApi = globalThis.crypto) {
  const payload = base64UrlDecode(signingInput, 2048);
  const signature = await cryptoApi.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    payload);
  return base64UrlEncode(new Uint8Array(signature));
}

export async function activateInstallationKey(deviceId) {
  const stored = await getRecord(deviceId);
  if (!stored || stored.state !== "pending") {
    throw new Error("The staged HIP extension key is unavailable.");
  }
  await putRecord({ ...stored, state: "active", activatedAtUtc: new Date().toISOString() });
}

export async function removeInstallationKey(deviceId) {
  const existing = await getRecord(deviceId);
  if (!existing) return false;
  const database = await openDatabase();
  try {
    await executeTransaction(database, "readwrite", store => store.delete(deviceId));
  } finally {
    database.close();
  }
  return true;
}

export async function reconcileInstallationKeys(activeDeviceIds) {
  const activeIds = new Set(Array.isArray(activeDeviceIds) ? activeDeviceIds : []);
  const records = await getAllRecords();
  let activated = 0;
  let removed = 0;
  const staleCutoff = Date.now() - 10 * 60 * 1000;
  for (const record of records) {
    if (!record || typeof record.keyId !== "string") continue;
    if (record.state === "pending" && activeIds.has(record.deviceId)) {
      await putRecord({ ...record, state: "active", activatedAtUtc: new Date().toISOString() });
      activated += 1;
    } else if ((record.state === "prepared" || record.state === "pending") && Date.parse(record.createdAtUtc) <= staleCutoff) {
      await removeInstallationKey(record.keyId);
      removed += 1;
    } else if (record.state === "active" && !activeIds.has(record.deviceId)) {
      await removeInstallationKey(record.keyId);
      removed += 1;
    }
  }
  return { activated, removed };
}

/** Creates a replay-resistant proof for a scoped HIP API request, or null when unregistered. */
export async function createInstallationRequestProof(method, path, body) {
  if (!globalThis.indexedDB) return null;
  const records = (await getAllRecords())
    .filter(record => record?.state === "active" && record.privateKey && record.deviceId)
    .sort((left, right) => String(right.activatedAtUtc).localeCompare(String(left.activatedAtUtc)));
  if (records.length === 0) return null;

  return createInstallationRequestProofForIdentity(records[0], method, path, body);
}

export async function createInstallationRequestProofForIdentity(
  identity,
  method,
  path,
  body,
  { cryptoApi = globalThis.crypto, now = () => Date.now(), nonceBytes = null } = {}) {
  const bodyDigest = `sha256:${await sha256Hex(canonicalJson(body), cryptoApi)}`;
  const timestamp = String(Math.floor(now() / 1000));
  const resolvedNonceBytes = nonceBytes || new Uint8Array(18);
  if (!nonceBytes) cryptoApi.getRandomValues(resolvedNonceBytes);
  if (!(resolvedNonceBytes instanceof Uint8Array) || resolvedNonceBytes.length !== 18) {
    throw new Error("The HIP request nonce is invalid.");
  }
  const nonce = base64UrlEncode(resolvedNonceBytes);
  const signingInput = [
    "HIP-DEVICE-REQUEST-V1",
    identity.deviceId,
    String(method).toUpperCase(),
    path,
    bodyDigest,
    timestamp,
    nonce
  ].join("\n");
  const signatureBytes = await cryptoApi.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    identity.privateKey,
    new TextEncoder().encode(signingInput));
  return {
    deviceId: identity.deviceId,
    timestamp,
    nonce,
    bodyDigest,
    signature: base64UrlEncode(new Uint8Array(signatureBytes))
  };
}

async function getRecord(keyId) {
  const database = await openDatabase();
  try {
    return await executeTransaction(database, "readonly", store => store.get(keyId));
  } finally {
    database.close();
  }
}

async function getAllRecords() {
  const database = await openDatabase();
  try {
    return await executeTransaction(database, "readonly", store => store.getAll());
  } finally {
    database.close();
  }
}

async function putRecord(record) {
  const database = await openDatabase();
  try {
    await executeTransaction(database, "readwrite", store => store.put(record));
  } finally {
    database.close();
  }
}

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = globalThis.indexedDB.open(databaseName, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(storeName)) {
        request.result.createObjectStore(storeName, { keyPath: "keyId" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("HIP extension key storage is unavailable."));
  });
}

async function executeTransaction(database, mode, createRequest) {
  const transaction = database.transaction(storeName, mode);
  const request = createRequest(transaction.objectStore(storeName));
  const [value] = await Promise.all([requestPromise(request), transactionPromise(transaction)]);
  return value;
}

function requestPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("HIP extension key storage failed."));
  });
}

function transactionPromise(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error ?? new Error("HIP extension key transaction was aborted."));
    transaction.onerror = () => reject(transaction.error ?? new Error("HIP extension key transaction failed."));
  });
}

function assertOpaqueId(value, prefix) {
  if (typeof value !== "string" || !value.startsWith(prefix) || value.length > 160 || !/^[A-Za-z0-9:_-]+$/.test(value)) {
    throw new Error("The HIP extension key identifier is invalid.");
  }
}

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return globalThis.btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlDecode(value, maximumBytes) {
  if (typeof value !== "string" || value.length > maximumBytes * 2 || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error("The HIP signing input is invalid.");
  }
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(value.length + ((4 - value.length % 4) % 4), "=");
  const bytes = Uint8Array.from(globalThis.atob(base64), character => character.charCodeAt(0));
  if (bytes.length === 0 || bytes.length > maximumBytes || base64UrlEncode(bytes) !== value) {
    throw new Error("The HIP signing input is invalid.");
  }
  return bytes;
}

async function sha256Hex(value, cryptoApi = globalThis.crypto) {
  const digest = await cryptoApi.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new Error("The HIP request body is not canonicalizable.");
}
