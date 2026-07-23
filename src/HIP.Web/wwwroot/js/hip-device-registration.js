const databaseName = "hip-device-identity-v1";
const storeName = "device-keys";
const pendingKeys = new Map();
const extensionHandlePrefix = "extension:";
const extensionManagedDeviceIds = new Set();

export async function inspectDeviceRegistrationSupport() {
    const extension = await requestExtension("capabilities", {}, 500);
    const extensionAvailable = extension?.supported === true;
    const secureContext = globalThis.isSecureContext === true;
    const webCryptoAvailable = typeof globalThis.crypto?.randomUUID === "function" &&
        typeof globalThis.crypto?.subtle?.generateKey === "function";
    const indexedDbAvailable = typeof globalThis.indexedDB?.open === "function";
    let keyStorageAvailable = false;

    if (indexedDbAvailable) {
        try {
            const database = await openDatabase();
            database.close();
            keyStorageAvailable = true;
        }
        catch {
            keyStorageAvailable = false;
        }
    }

    return {
        supported: secureContext && (extensionAvailable || (webCryptoAvailable && keyStorageAvailable)),
        secureContext,
        webCryptoAvailable,
        keyStorageAvailable,
        extensionAvailable
    };
}

export async function prepareDeviceKey() {
    const extension = await requestExtension("prepare", {}, 750);
    if (extension?.handle && extension?.publicKey && extension?.algorithm === "ECDSA-P256-SHA256") {
        return { handle: `${extensionHandlePrefix}${extension.handle}`, publicKey: extension.publicKey };
    }

    const support = await inspectDeviceRegistrationSupport();
    if (!support.secureContext) {
        throw new Error("HIP_DEVICE_INSECURE_CONTEXT");
    }
    if (!support.webCryptoAvailable && !support.extensionAvailable) {
        throw new Error("HIP_DEVICE_WEBCRYPTO_UNAVAILABLE");
    }
    if (!support.keyStorageAvailable && !support.extensionAvailable) {
        throw new Error("HIP_DEVICE_KEY_STORAGE_UNAVAILABLE");
    }

    const keyPair = await globalThis.crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign", "verify"]);
    const publicKey = await globalThis.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const handle = globalThis.crypto.randomUUID();
    pendingKeys.set(handle, keyPair);
    return { handle, publicKey: base64UrlEncode(new Uint8Array(publicKey)) };
}

export async function stageDeviceKey(handle, deviceId) {
    if (handle?.startsWith(extensionHandlePrefix)) {
        await requireExtension("stage", { handle: handle.slice(extensionHandlePrefix.length), deviceId });
        extensionManagedDeviceIds.add(deviceId);
        return;
    }

    const keyPair = pendingKeys.get(handle);
    if (!keyPair || !deviceId) {
        throw new Error("The pending HIP device key is unavailable.");
    }

    await putDeviceKey({
        deviceId,
        algorithm: "ECDSA-P256-SHA256",
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        state: "pending",
        createdAtUtc: new Date().toISOString()
    });
    pendingKeys.delete(handle);
}

export async function signDeviceChallenge(deviceId, signingInput) {
    if (extensionManagedDeviceIds.has(deviceId)) {
        const result = await requireExtension("sign", { deviceId, signingInput });
        return result.signature;
    }

    const stored = await getDeviceKey(deviceId);
    if (!stored || stored.state !== "pending" || !stored.privateKey) {
        throw new Error("The staged HIP device key is unavailable.");
    }

    const signature = await globalThis.crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        stored.privateKey,
        base64UrlDecode(signingInput));
    return base64UrlEncode(new Uint8Array(signature));
}

export async function activateDeviceKey(deviceId) {
    if (extensionManagedDeviceIds.has(deviceId)) {
        await requireExtension("activate", { deviceId });
        return;
    }

    const stored = await getDeviceKey(deviceId);
    if (!stored) {
        throw new Error("The staged HIP device key is unavailable.");
    }

    await putDeviceKey({ ...stored, state: "active", activatedAtUtc: new Date().toISOString() });
}

export async function removeDeviceKey(deviceId) {
    const extension = await requestExtension("remove", { deviceId }, 1000);
    if (extension?.removed) {
        extensionManagedDeviceIds.delete(deviceId);
        return;
    }

    const database = await openDatabase();
    try {
        await executeTransaction(
            database,
            "readwrite",
            store => store.delete(deviceId));
    }
    finally {
        database.close();
    }
}

export async function reconcileDeviceKeys(activeDeviceIds) {
    const activeIds = new Set(
        Array.isArray(activeDeviceIds)
            ? activeDeviceIds.filter(value => typeof value === "string" && value.length > 0)
            : []);
    const extension = await requestExtension("reconcile", { activeDeviceIds: [...activeIds] }, 1000);
    const database = await openDatabase();
    let storedKeys;
    try {
        storedKeys = await executeTransaction(
            database,
            "readonly",
            store => store.getAll());
    }
    finally {
        database.close();
    }

    let activated = 0;
    let removed = 0;
    const stalePendingCutoff = Date.now() - 10 * 60 * 1000;
    for (const stored of storedKeys) {
        if (!stored || stored.state !== "pending" || typeof stored.deviceId !== "string") {
            continue;
        }

        if (activeIds.has(stored.deviceId)) {
            await putDeviceKey({ ...stored, state: "active", activatedAtUtc: new Date().toISOString() });
            activated += 1;
            continue;
        }

        const createdAt = Date.parse(stored.createdAtUtc);
        if (Number.isFinite(createdAt) && createdAt <= stalePendingCutoff) {
            await removeDeviceKey(stored.deviceId);
            removed += 1;
        }
    }

    return {
        activated: activated + (extension?.activated ?? 0),
        removed: removed + (extension?.removed ?? 0)
    };
}

export function discardPendingDeviceKey(handle) {
    pendingKeys.delete(handle);
}

async function getDeviceKey(deviceId) {
    const database = await openDatabase();
    try {
        return await executeTransaction(
            database,
            "readonly",
            store => store.get(deviceId));
    }
    finally {
        database.close();
    }
}

async function putDeviceKey(value) {
    const database = await openDatabase();
    try {
        await executeTransaction(
            database,
            "readwrite",
            store => store.put(value));
    }
    finally {
        database.close();
    }
}

/**
 * Executes one device-key request and resolves only after its transaction commits.
 *
 * @param {IDBDatabase} database Device-key database.
 * @param {IDBTransactionMode} mode IndexedDB transaction mode.
 * @param {(store: IDBObjectStore) => IDBRequest} createRequest Request factory.
 * @returns {Promise<unknown>} The request result after transaction completion.
 */
async function executeTransaction(database, mode, createRequest) {
    const transaction = database.transaction(storeName, mode);
    const request = createRequest(transaction.objectStore(storeName));
    const [result] = await Promise.all([
        requestPromise(request),
        transactionPromise(transaction)
    ]);
    return result;
}

function openDatabase() {
    return new Promise((resolve, reject) => {
        const request = globalThis.indexedDB.open(databaseName, 1);
        request.onupgradeneeded = () => {
            const database = request.result;
            if (!database.objectStoreNames.contains(storeName)) {
                database.createObjectStore(storeName, { keyPath: "deviceId" });
            }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new Error("HIP device-key storage is unavailable."));
    });
}

function requestPromise(request) {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new Error("HIP device-key storage failed."));
    });
}

/**
 * Reports the durable outcome of an IndexedDB transaction.
 *
 * @param {IDBTransaction} transaction Transaction to observe.
 * @returns {Promise<void>} Completion when committed, or rejection when aborted or failed.
 */
function transactionPromise(transaction) {
    return new Promise((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onabort = () => reject(
            transaction.error ?? new Error("HIP device-key storage transaction was aborted."));
        transaction.onerror = () => reject(
            transaction.error ?? new Error("HIP device-key storage transaction failed."));
    });
}

function base64UrlEncode(bytes) {
    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return globalThis.btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function base64UrlDecode(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value) || value.length % 4 === 1) {
        throw new Error("The HIP signing input is not canonical base64url.");
    }

    const base64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(value.length + ((4 - value.length % 4) % 4), "=");
    const binary = globalThis.atob(base64);
    return Uint8Array.from(binary, character => character.charCodeAt(0));
}

async function requireExtension(operation, payload) {
    const result = await requestExtension(operation, payload, 3000);
    if (!result) {
        throw new Error("The HIP browser extension registration bridge is unavailable.");
    }
    return result;
}

function requestExtension(operation, payload, timeoutMs) {
    if (typeof globalThis.window?.postMessage !== "function") {
        return Promise.resolve(null);
    }

    const requestId = `hip-device-${globalThis.crypto.randomUUID()}`;
    return new Promise(resolve => {
        let settled = false;
        const finish = value => {
            if (settled) return;
            settled = true;
            globalThis.window.removeEventListener("message", onMessage);
            clearTimeout(timeoutId);
            resolve(value);
        };
        const onMessage = event => {
            const response = event?.data;
            if (event.source !== globalThis.window ||
                event.origin !== globalThis.window.location.origin ||
                response?.source !== "hip-extension-device-registration" ||
                response?.type !== "response" ||
                response?.requestId !== requestId) {
                return;
            }
            finish(response.ok === true ? response.result : null);
        };
        const timeoutId = setTimeout(() => finish(null), timeoutMs);
        globalThis.window.addEventListener("message", onMessage);
        globalThis.window.postMessage({
            source: "hip-web-device-registration",
            type: "request",
            requestId,
            operation,
            payload
        }, globalThis.window.location.origin);
    });
}
