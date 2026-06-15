/**
 * Root-level Manifest V3 service worker wrapper.
 *
 * Chrome reports vague "Service worker registration failed. Status code: 3" errors when the worker entrypoint
 * or one of its imports cannot be fetched during unpacked-extension reloads. Keeping the manifest entrypoint at
 * the extension root gives Chrome a simple, stable worker script while preserving the implementation in src.
 */
import "./src/background.js";
