import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const modulePath = new URL(
    "../../../src/HIP.Web/wwwroot/js/hip-device-registration.js",
    import.meta.url);

test("staging waits for transaction commit and retains the pending key after an abort", async () => {
    const originalIndexedDb = globalThis.indexedDB;
    const originalSecureContext = globalThis.isSecureContext;
    globalThis.indexedDB = createIndexedDb(["abort", "complete"]);
    globalThis.isSecureContext = true;

    try {
        const source = await readFile(modulePath, "utf8");
        const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
        const registration = await import(moduleUrl);
        const prepared = await registration.prepareDeviceKey();

        await assert.rejects(
            registration.stageDeviceKey(prepared.handle, "device-1"),
            /simulated transaction abort/u);

        await assert.doesNotReject(
            registration.stageDeviceKey(prepared.handle, "device-1"));
    }
    finally {
        globalThis.indexedDB = originalIndexedDb;
        globalThis.isSecureContext = originalSecureContext;
    }
});

test("reports browser key capabilities before registration", async () => {
    const originalIndexedDb = globalThis.indexedDB;
    const originalSecureContext = globalThis.isSecureContext;
    globalThis.indexedDB = createIndexedDb(["complete"]);
    globalThis.isSecureContext = true;

    try {
        const source = await readFile(modulePath, "utf8");
        const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}#capabilities`;
        const registration = await import(moduleUrl);

        const support = await registration.inspectDeviceRegistrationSupport();

        assert.deepEqual(support, {
            supported: true,
            secureContext: true,
            webCryptoAvailable: true,
            keyStorageAvailable: true,
            extensionAvailable: false,
            suggestedDeviceName: "This device"
        });
    }
    finally {
        globalThis.indexedDB = originalIndexedDb;
        globalThis.isSecureContext = originalSecureContext;
    }
});

test("suggests broad physical device names without producing unique identifiers", async () => {
    const source = await readFile(modulePath, "utf8");
    const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}#device-names`;
    const registration = await import(moduleUrl);

    assert.equal(registration.suggestDeviceName("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), "My Windows PC");
    assert.equal(registration.suggestDeviceName("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"), "My iPhone");
    assert.equal(registration.suggestDeviceName("Mozilla/5.0 (Linux; Android 15; Pixel) Mobile"), "My Android phone");
    assert.equal(registration.suggestDeviceName("Mozilla/5.0 (Linux; Android 15; Tablet)"), "My Android tablet");
});

test("removes active local credentials that the server no longer recognizes", async () => {
    const originalIndexedDb = globalThis.indexedDB;
    const store = createReconciliationIndexedDb([
        { deviceId: "active-device", state: "active", createdAtUtc: "2026-07-26T12:00:00.000Z" },
        { deviceId: "removed-device", state: "active", createdAtUtc: "2026-07-26T12:00:00.000Z" }
    ]);
    globalThis.indexedDB = store.indexedDb;

    try {
        const source = await readFile(modulePath, "utf8");
        const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}#reconcile`;
        const registration = await import(moduleUrl);

        const result = await registration.reconcileDeviceKeys(["active-device"]);

        assert.deepEqual(result, { activated: 0, removed: 1 });
        assert.deepEqual(store.deviceIds(), ["active-device"]);
    }
    finally {
        globalThis.indexedDB = originalIndexedDb;
    }
});

function createReconciliationIndexedDb(records) {
    const values = new Map(records.map(record => [record.deviceId, record]));
    const database = {
        objectStoreNames: { contains: () => true },
        close() {
        },
        transaction() {
            const transaction = {
                error: null,
                objectStore() {
                    return {
                        getAll: () => completeRequest(transaction, [...values.values()]),
                        put(value) {
                            values.set(value.deviceId, value);
                            return completeRequest(transaction, value);
                        },
                        delete(deviceId) {
                            values.delete(deviceId);
                            return completeRequest(transaction, undefined);
                        }
                    };
                }
            };
            return transaction;
        }
    };

    return {
        indexedDb: {
            open() {
                const request = { error: null, result: database };
                queueMicrotask(() => request.onsuccess?.());
                return request;
            }
        },
        deviceIds: () => [...values.keys()].sort()
    };
}

function completeRequest(transaction, result) {
    const request = { error: null, result: undefined };
    queueMicrotask(() => {
        request.result = result;
        request.onsuccess?.();
        setTimeout(() => transaction.oncomplete?.(), 0);
    });
    return request;
}
function createIndexedDb(transactionOutcomes) {
    const database = {
        objectStoreNames: { contains: () => true },
        close() {
        },
        transaction() {
            const outcome = transactionOutcomes.shift() ?? "complete";
            const transaction = {
                error: null,
                objectStore() {
                    return {
                        put(value) {
                            const request = { error: null, result: undefined };
                            queueMicrotask(() => {
                                request.result = value;
                                request.onsuccess?.();
                                setTimeout(() => {
                                    if (outcome === "abort") {
                                        transaction.error = new Error("simulated transaction abort");
                                        transaction.onabort?.();
                                        return;
                                    }

                                    transaction.oncomplete?.();
                                }, 0);
                            });
                            return request;
                        }
                    };
                }
            };

            return transaction;
        }
    };

    return {
        open() {
            const request = { error: null, result: database };
            queueMicrotask(() => request.onsuccess?.());
            return request;
        }
    };
}
