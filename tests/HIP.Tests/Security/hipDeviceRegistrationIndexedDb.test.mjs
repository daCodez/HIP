import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const modulePath = new URL(
    "../../../src/HIP.Web/wwwroot/js/hip-device-registration.js",
    import.meta.url);

test("staging waits for transaction commit and retains the pending key after an abort", async () => {
    const originalIndexedDb = globalThis.indexedDB;
    globalThis.indexedDB = createIndexedDb(["abort", "complete"]);

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
    }
});

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
